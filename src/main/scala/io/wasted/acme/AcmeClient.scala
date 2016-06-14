package io.wasted.acme

import java.io.{ ByteArrayInputStream, ByteArrayOutputStream, InputStreamReader, OutputStreamWriter }
import java.math.BigInteger
import java.net.URI
import java.security._
import java.security.cert.X509Certificate
import java.security.interfaces.{ RSAPrivateKey, RSAPublicKey }

import com.twitter.concurrent.Broker
import com.twitter.util._
import io.netty.buffer.{ ByteBuf, ByteBufInputStream }
import io.netty.handler.codec.http._
import io.netty.util.CharsetUtil
import io.wasted.util.http._
import io.wasted.util.{ Logger, Schedule, WheelTimer }
import net.liftweb.json.{ DefaultFormats, FieldSerializer, JsonParser, Serialization }
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.jce.provider.{ BouncyCastleProvider, X509CertParser }
import org.bouncycastle.openssl.jcajce.{ JcaPEMKeyConverter, JcePEMDecryptorProviderBuilder }
import org.bouncycastle.openssl.{ PEMEncryptedKeyPair, PEMKeyPair, PEMParser }
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.{ PKCS10CertificationRequest, PKCS10CertificationRequestBuilder }
import org.bouncycastle.util.io.pem.{ PemObject, PemWriter }
import org.joda.time.DateTime

import scala.collection.JavaConverters._
import scala.concurrent.duration._

final case class AcmeClient(keyPair: KeyPair, endpoint: String,
                            newAuthz: URI, newCert: URI, newReg: URI, revokeCert: URI, terms: URI,
                            contacts: List[String]) {
  private[acme] val nonce = new Broker[String]

  def registration(): Future[Unit] = {
    AcmeClient.registration(this)
  }

  def authorize(domain: String): Future[AcmeAuthorization] = {
    AcmeClient.authorize(this, domain)
  }

  def challenge(challenge: AcmeChallenge, tls: Boolean = false): Future[AcmeAuthorizationState.Value] = {
    AcmeClient.challenge(this, challenge, tls)
  }

  def issue(csr: PKCS10CertificationRequest, notBefore: DateTime = DateTime.now(), notAfter: DateTime = DateTime.now().plusDays(90)): Future[X509Certificate] = {
    AcmeClient.issue(this, csr, notBefore, notAfter)
  }

  def revoke(certificate: X509Certificate): Future[Unit] = {
    AcmeClient.revoke(this, certificate)
  }
}

final case class AcmeChallenge(`type`: String, status: String, uri: String, token: String, thumbprint: String) {
  def getHTTP01ChallengeContent: String = token + "." + thumbprint
}
final case class AcmeAuthChallenge(`type`: String, status: String, validated: DateTime, token: String, keyAuthorization: String)
final case class AcmeAuthorization(status: AcmeAuthorizationState.Value, expires: DateTime, domain: String, challenges: List[AcmeChallenge])

object AcmeAuthorizationState extends Enumeration {
  val Unknown = Value("unknown")
  val Pending = Value("pending")
  val Processing = Value("processing")
  val Valid = Value("valid")
  val Invalid = Value("invalid")
  val Revoked = Value("revoked")
}

object AcmeClient extends Logger {
  private val provider = new BouncyCastleProvider()
  Security.addProvider(provider)

  implicit val wheelTimer = WheelTimer
  implicit val formats = DefaultFormats +
    new FieldSerializer[AcmeAuthChallenge] +
    new EnumerationSerializer(AcmeAuthorizationState :: Nil) +
    new DateTimeSerializer

  private val signatureAlgo = "RS256"
  private val mime = "application/x-www-form-urlencoded"
  private val httpCodec = NettyHttpCodec[HttpRequest, FullHttpResponse]()
    .withDecompression(true)
    .withKeepAlive(false)
    .withInsecureTls()

  private val httpClient = HttpClient()
    .withSpecifics(httpCodec)
    .withTcpNoDelay(true)
    .withTcpKeepAlive(false)

  private def toIntegerBytes(bigInt: BigInteger): Array[Byte] = {
    var bitlen = bigInt.bitLength()
    bitlen = ((bitlen + 7) >> 3) << 3
    val bigBytes = bigInt.toByteArray
    if (((bigInt.bitLength() % 8) != 0) && (((bigInt.bitLength() / 8) + 1) == (bitlen / 8))) {
      return bigBytes
    }
    var startSrc = 0
    var len = bigBytes.length
    if ((bigInt.bitLength() % 8) == 0) {
      startSrc = 1
      len -= 1
    }
    val startDst = bitlen / 8 - len
    val resizedBytes = Array.ofDim[Byte](bitlen / 8)
    System.arraycopy(bigBytes, startSrc, resizedBytes, startDst, len)
    resizedBytes
  }

  private def getWebKey(publicKey: PublicKey): Map[String, Object] = publicKey match {
    case rsapubkey: RSAPublicKey =>
      val e = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(toIntegerBytes(rsapubkey.getPublicExponent))
      val n = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(toIntegerBytes(rsapubkey.getModulus))
      Map("e" -> e, "kty" -> "RSA", "n" -> n)
    case _ => throw new IllegalArgumentException("Only RSA Public Keys are supported")
  }

  private def getWebKeyThumbprintSHA256(publicKey: PublicKey): String = {
    val webkey = getWebKey(publicKey)
    val json = Serialization.write(webkey)
    val md = MessageDigest.getInstance("SHA-256")
    md.update(json.getBytes(CharsetUtil.UTF_8), 0, json.length)
    val thumbprint = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(md.digest())
    thumbprint
  }

  private def keyPairGenerator = {
    val kpg = KeyPairGenerator.getInstance("RSA")
    kpg.initialize(4096)
    kpg
  }

  private def generateSignedJWS(keyPair: KeyPair, nonce: String, claims: Map[String, Object]): String = {
    val body = Serialization.write(claims)
    val bytes = Serialization.write(Map("nonce" -> nonce)).getBytes(CharsetUtil.UTF_8)
    val protectionHeader = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
    val protectionBody = java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(body.getBytes(CharsetUtil.UTF_8))
    val signature = Signature.getInstance("SHA256withRSA")
    signature.initSign(keyPair.getPrivate)
    signature.update((protectionHeader + "." + protectionBody).getBytes(CharsetUtil.UTF_8))
    Serialization.writePretty(Map(
      "header" -> Map("alg" -> signatureAlgo, "jwk" -> getWebKey(keyPair.getPublic)),
      "protected" -> protectionHeader,
      "payload" -> protectionBody,
      "signature" -> java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(signature.sign())))
  }

  def generateKeyPair(): KeyPair = keyPairGenerator.generateKeyPair

  def generateCertificationRequest(keyPair: KeyPair, hostnames: List[String]): PKCS10CertificationRequest = {
    val sans = hostnames.tail.map(new GeneralName(GeneralName.dNSName, _))
    val pubKeyEncoded = SubjectPublicKeyInfo.getInstance(keyPair.getPublic.getEncoded)
    val builder = new PKCS10CertificationRequestBuilder(new X500Name("CN=" + hostnames.head), pubKeyEncoded)
    if (sans.nonEmpty) {
      val values = new java.util.Vector[Extension]()
      val subjectAltName = new GeneralNames(sans.toArray)
      values.add(new Extension(Extension.subjectAlternativeName, true, new DEROctetString(subjectAltName)))
      builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new Extensions(values.asScala.toArray))
    }
    builder.build(new JcaContentSignerBuilder("SHA512withRSA").build(keyPair.getPrivate))
  }

  def keyPairToPem(keyPair: KeyPair): (String, String) = (keyPair.getPrivate, keyPair.getPublic) match {
    case (rsaPriv: RSAPrivateKey, rsaPub: RSAPublicKey) =>
      val privKey = {
        val baos = new ByteArrayOutputStream()
        val os = new OutputStreamWriter(baos)
        val writer = new PemWriter(os)
        writer.writeObject(new PemObject("RSA PRIVATE KEY", rsaPriv.getEncoded))
        writer.close()
        os.close()
        baos.close()
        baos.toString("UTF-8")
      }
      val pubKey = {
        val baos = new ByteArrayOutputStream()
        val os = new OutputStreamWriter(baos)
        val writer = new PemWriter(os)
        writer.writeObject(new PemObject("PUBLIC KEY", rsaPub.getEncoded))
        writer.close()
        os.close()
        baos.close()
        baos.toString("UTF-8")
      }
      privKey -> pubKey
    case _ =>
      throw new IllegalArgumentException("We currently only deal with RSA Keys")
  }

  def pemToKeyPair(pem: String, password: Option[String] = None): KeyPair = {
    val bais = new ByteArrayInputStream(pem.getBytes(CharsetUtil.UTF_8))
    val is = new InputStreamReader(bais)
    val reader = new PEMParser(is)
    val pemo = reader.readObject()
    reader.close()
    is.close()
    bais.close()
    val converter = new JcaPEMKeyConverter().setProvider("BC")
    pemo match {
      case encryptedKeyPair: PEMEncryptedKeyPair =>
        val decProv = new JcePEMDecryptorProviderBuilder().build(password.getOrElse("").toCharArray)
        converter.getKeyPair(encryptedKeyPair.decryptKeyPair(decProv))
      case keyPair: PEMKeyPair =>
        converter.getKeyPair(keyPair)
      case t =>
        throw new IllegalArgumentException("Unable to read KeyPair from given String")
    }
  }

  private final case class AcmePaths(`new-authz`: String, `new-cert`: String, `new-reg`: String, `revoke-cert`: String)
  private final case class AcmeChallengePlain(`type`: String, status: String, uri: String, token: String) {
    def toChallenge(keyPair: KeyPair): AcmeChallenge = {
      AcmeChallenge(`type`, status, uri, token, getWebKeyThumbprintSHA256(keyPair.getPublic))
    }
  }

  private def httpGETbinary(uri: URI, headers: Map[String, String] = Map.empty, client: Option[AcmeClient] = None): Future[(Int, ByteBuf, HttpHeaders, Option[String])] = {
    httpClient.get(uri, headers).map { resp =>
      val nonce = Option(resp.headers().get("Replay-Nonce"))
      for {
        cl <- client
        n <- nonce
      } cl.nonce ! n
      (resp.getStatus().code, resp.content(), resp.headers(), nonce)
    }
  }

  private def httpGET(uri: URI, headers: Map[String, String] = Map.empty, client: Option[AcmeClient] = None): Future[(Int, String, HttpHeaders, Option[String])] = {
    httpClient.get(uri, headers).map { resp =>
      val nonce = Option(resp.headers().get("Replay-Nonce"))
      val r = (resp.getStatus().code, resp.content().toString(CharsetUtil.UTF_8), resp.headers(), nonce)
      for {
        cl <- client
        n <- nonce
      } cl.nonce ! n
      resp.release()
      r
    }
  }

  private def httpPOST(uri: URI, mime: String, bytes: String, client: AcmeClient): Future[(Int, String, HttpHeaders, Option[String])] = {
    httpClient.post(uri, mime, bytes.getBytes(CharsetUtil.UTF_8).toSeq, Map.empty, HttpMethod.POST).map { resp =>
      val nonce = Option(resp.headers().get("Replay-Nonce"))
      nonce.map(client.nonce ! _)
      val r = (resp.getStatus().code, resp.content().toString(CharsetUtil.UTF_8), resp.headers(), nonce)
      resp.release()
      r
    }
  }

  def apply(endpoint: String, keyPair: KeyPair, contacts: List[String]): Future[AcmeClient] = {
    httpGET(new URI(endpoint + "/directory")).map {
      case (200, body, headers, nonce) =>
        val j = JsonParser.parseOpt(body).flatMap(_.extractOpt[AcmePaths])
        j.map { paths =>
          val newAuth = new URI(paths.`new-authz`)
          val newCert = new URI(paths.`new-cert`)
          val newReg = new URI(paths.`new-reg`)
          val revokeCert = new URI(paths.`revoke-cert`)
          val terms = new URI(endpoint + "/terms")
          val acme = AcmeClient(keyPair, endpoint, newAuth, newCert, newReg, revokeCert, terms, contacts)
          nonce.map(acme.nonce ! _)
          acme
        }.getOrElse(throw new IllegalArgumentException("Directory index did not contain expected listing"))
      case (status, body, headers, nonce) =>
        error("[%s] Unable to get directory index", endpoint)
        throw new IllegalStateException("Unable to get directory index: " + status + ": " + body)
    }
  }

  private def findTerms(headers: HttpHeaders): Option[String] = {
    headers.getAll("Link").asScala.find(_.endsWith(";rel=\"terms-of-service\""))
      .flatMap(_.split(">").headOption.map(_.replaceAll("^<", "")))
  }

  private def getTerms(client: AcmeClient, headers: HttpHeaders): Future[String] = findTerms(headers).map(Future.value).getOrElse {
    httpGET(client.terms).map(_._3).map(hdrs => Option(hdrs.get(HttpHeaders.Names.LOCATION)).getOrElse {
      throw new IllegalArgumentException("No terms could be found for signing")
    })
  }

  private def getNonce(client: AcmeClient): Future[Unit] = httpGET(new URI(client.endpoint + "/directory"), client = Some(client)).map {
    case (200, body, headers, nonce) =>
      Future.Done
    case (status, body, headers, nonce) =>
      error("[%s] No nonce was returned", client.endpoint)
      throw new IllegalStateException("No Nonce was returned: " + status + ": " + body)
  }

  private[acme] def registration(client: AcmeClient, numTry: Int = 0): Future[Unit] = {
    info("[%s] Checking registration", client.endpoint)
    client.nonce.recvAndSync().flatMap { nextNonce =>
      val claims = Map[String, Object](
        "resource" -> "new-reg",
        "contact" -> client.contacts)
      val bytes = generateSignedJWS(client.keyPair, nextNonce, claims)
      httpPOST(client.newReg, mime, bytes, client).flatMap {
        case (201, body, headers, nonce) =>
          info("[%s] Successfully registered account", client.endpoint)
          val regURL = new URI(headers.get(HttpHeaders.Names.LOCATION))
          getTerms(client, headers).map { terms =>
            info("[%s] Agreement needs signing", client.endpoint, numTry)
            agreement(client, regURL, terms)
          }

        case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          debug("[%s] Expired nonce used, getting new one", client.endpoint)
          getNonce(client).flatMap { gotNonce =>
            registration(client, numTry) // we don't count this as an error
          }

        case (409, body, headers, nonce) if numTry < 3 =>
          info("[%s] We already have an account", client.endpoint)
          val termsAndServices = for {
            regURL <- Option(headers.get(HttpHeaders.Names.LOCATION)).map(new URI(_))
            terms <- findTerms(headers)
          } yield {
            info("[%s] Agreement needs signing", client.endpoint, numTry)
            agreement(client, regURL, terms)
          }
          termsAndServices.getOrElse(Future.Done)

        case (status, body, headers, nonce) =>
          error("[%s] Unable to register account after %s tries", client.endpoint, numTry)
          throw new IllegalStateException("Unable to register: " + status + ": " + body)
      }
    }
  }

  private[acme] def agreement(client: AcmeClient, regURL: URI, terms: String, numTry: Int = 0): Future[Unit] = {
    info("[%s] Handling agreement", client.endpoint)
    client.nonce.recvAndSync().map { nextNonce =>
      val claims = Map[String, Object](
        "resource" -> "reg",
        "agreement" -> terms)
      val bytes = generateSignedJWS(client.keyPair, nextNonce, claims)
      httpPOST(regURL, mime, bytes, client).flatMap {
        case (code, body, headers, nonce) if code < 250 =>
          info("[%s] Successfully signed Terms of Service", client.endpoint)
          Future.Done

        case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          debug("[%s] Expired nonce used, getting new one", client.endpoint)
          getNonce(client).flatMap { gotNonce =>
            agreement(client, regURL, terms, numTry) // we don't count this as an error
          }

        case (status, body, headers, nonce) if numTry < 3 =>
          error("[%s] Unable to sign Terms of Service, retrying (try #%s)", client.endpoint, numTry)
          agreement(client, regURL, terms, numTry + 1)

        case (status, body, headers, nonce) =>
          error("[%s] Unable to sign Terms of Service after %s tries", client.endpoint, numTry)
          throw new IllegalStateException("Unable to sign agreement: " + status + ": " + body)
      }
    }
  }

  private[acme] def authorize(client: AcmeClient, domain: String, numTry: Int = 0): Future[AcmeAuthorization] = {
    debug("[%s] Creating authorization for %s", client.endpoint, domain)
    client.nonce.recvAndSync().flatMap { nextNonce =>
      val claims = Map[String, Object](
        "resource" -> "new-authz",
        "identifier" -> Map(
          "type" -> "dns",
          "value" -> domain))
      val bytes = generateSignedJWS(client.keyPair, nextNonce, claims)
      httpPOST(client.newAuthz, mime, bytes, client).flatMap {
        case (201, body, headers, nonce) =>
          val json = JsonParser.parse(body)
          val challenges = {
            (json \ "challenges").extract[List[AcmeChallengePlain]].map(_.toChallenge(client.keyPair))
          }
          val authInfo = for {
            expires <- (json \ "expires").extractOpt[DateTime]
            domain <- (json \ "identifier" \ "value").extractOpt[String]
            status = (json \ "status").extractOpt[AcmeAuthorizationState.Value].getOrElse(AcmeAuthorizationState.Pending)
          } yield Future.value(AcmeAuthorization(status, expires, domain, challenges))
          authInfo getOrElse {
            error("[%s] No http-01 challenges given", client.endpoint)
            throw new IllegalStateException("No http-01 challenges given")
          }

        case (429, body, headers, nonce) =>
          throw new IllegalStateException("Unable to start challenge: " + body)

        case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          debug("[%s] Expired nonce used, getting new one", client.endpoint)
          getNonce(client).flatMap { gotNonce =>
            authorize(client, domain, numTry) // we don't count this as an error
          }

        case (status, body, headers, nonce) if numTry < 3 =>
          error("[%s] Unable to authorize, retrying (try #%s)", client.endpoint, numTry)
          val p = Promise[AcmeAuthorization]()
          Schedule.once(() => authorize(client, domain, numTry + 1).onSuccess(p.setValue).onFailure(p.setException), 10.seconds)
          p

        case (status, body, headers, nonce) =>
          error("[%s] Unable to authorize after %s tries", client.endpoint, numTry)
          throw new IllegalStateException("Unable to authorize " + domain + ": " + status + ": " + body)
      }
    }
  }

  private def checkAuthorization(client: AcmeClient, challenge: AcmeChallenge, authURL: URI, numTry: Int = 0): Future[AcmeAuthorizationState.Value] = {
    httpGET(authURL).flatMap {
      case (status, body, headers, nonce) if status < 250 && numTry < 3 =>
        val json = body
        JsonParser.parseOpt(json).flatMap { json =>
          (json \ "status").extractOpt[AcmeAuthorizationState.Value].map {
            case AcmeAuthorizationState.Valid =>
              info("[%s] Authorization for %s succeeded", client.endpoint, challenge.token)
              Future.value(AcmeAuthorizationState.Valid)
            case AcmeAuthorizationState.Pending =>
              info("[%s] Authorization for %s pending at try %s", client.endpoint, challenge.token, numTry)
              val p = Promise[AcmeAuthorizationState.Value]()
              Schedule.once(() => checkAuthorization(client, challenge, authURL, numTry + 1).onSuccess(p.setValue).onFailure(p.setException), 10.seconds)
              p

            case auth =>
              info("[%s] Authorization for %s state: %s", client.endpoint, challenge.token, auth)
              val p = Promise[AcmeAuthorizationState.Value]()
              Schedule.once(() => checkAuthorization(client, challenge, authURL, numTry + 1).onSuccess(p.setValue).onFailure(p.setException), 10.seconds)
              p
          }
        }.getOrElse {
          error("[%s] Unable to get challenge response status", client.endpoint)
          throw new IllegalStateException("Unable to get challenge response status: " + status + ": " + body)
        }

      case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
        debug("[%s] Expired nonce used, getting new one", client.endpoint)
        getNonce(client).flatMap { gotNonce =>
          checkAuthorization(client, challenge, authURL, numTry) // we don't count this as an error
        }

      case (status, body, headers, nonce) =>
        error("[%s] Unable to get complete challenge after %s tries", client.endpoint, numTry)
        throw new IllegalStateException("Unable to complete challenge after " + numTry + " tries: " + status + ": " + body)
    }
  }

  private[acme] def challenge(client: AcmeClient, challenge: AcmeChallenge, tls: Boolean = false, numTry: Int = 0): Future[AcmeAuthorizationState.Value] = {
    debug("[%s] Solving challenge %s", client.endpoint, challenge.token)
    client.nonce.recvAndSync().flatMap { nextNonce =>
      val claims = Map[String, Object](
        "resource" -> "challenge",
        "type" -> challenge.`type`,
        "keyAuthorization" -> challenge.getHTTP01ChallengeContent)
      val bytes = generateSignedJWS(client.keyPair, nextNonce, claims)
      httpPOST(new URI(challenge.uri), mime, bytes, client).flatMap {
        case (status, body, headers, nonce) if status < 250 =>
          val authURL = new URI(headers.get(HttpHeaders.Names.LOCATION))
          val json = body
          JsonParser.parseOpt(json).flatMap { json =>
            (json \ "status").extractOpt[AcmeAuthorizationState.Value].map {
              case AcmeAuthorizationState.Valid =>
                info("[%s] Authorization for %s succeeded", client.endpoint, challenge.token)
                Future.value(AcmeAuthorizationState.Valid)

              case AcmeAuthorizationState.Pending =>
                info("[%s] Authorization for %s pending at try %s", client.endpoint, challenge.token, numTry)
                val p = Promise[AcmeAuthorizationState.Value]()
                Schedule.once(() => checkAuthorization(client, challenge, authURL).onSuccess(p.setValue).onFailure(p.setException), 10.seconds)
                p

              case auth =>
                info("[%s] Authorization for %s state: %s", client.endpoint, challenge.token, auth)
                Future.value(auth)
            }
          }.getOrElse {
            error("[%s] Unable to get challenge response status", client.endpoint)
            throw new IllegalStateException("Unable to get challenge response status: " + status + ": " + body)
          }

        case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          debug("[%s] Expired nonce used, getting new one", client.endpoint)
          getNonce(client).flatMap { gotNonce =>
            this.challenge(client, challenge, tls, numTry) // we don't count this as an error
          }

        case (status, body, headers, nonce) if numTry < 3 =>
          error("[%s] Unable to get challenge response, retrying (try #%s)", client.endpoint, numTry)
          val p = Promise[AcmeAuthorizationState.Value]()
          Schedule.once(() => this.challenge(client, challenge, tls, numTry + 1).onSuccess(p.setValue).onFailure(p.setException), 10.seconds)
          p

        case (status, body, headers, nonce) =>
          error("[%s] Unable to get challenge response after %s tries", client.endpoint, numTry)
          throw new IllegalStateException("Unable to complete challenge: " + status + ": " + body)
      }
    }
  }

  private[acme] def issue(client: AcmeClient, csr: PKCS10CertificationRequest,
                          notBefore: DateTime = DateTime.now(), notAfter: DateTime = DateTime.now().plusDays(90),
                          numTry: Int = 0): Future[X509Certificate] = {
    debug("[%s] Issuing certificate for %s", client.endpoint, csr.getSubject)
    client.nonce.recvAndSync().flatMap { nextNonce =>
      val claims = Map[String, Object](
        "resource" -> "new-cert",
        "csr" -> java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(csr.getEncoded),
        "notBefore" -> notBefore.toString("yyyy-MM-dd'T'HH:mm:ssZ"),
        "notAfter" -> notAfter.toString("yyyy-MM-dd'T'HH:mm:ssZ"))
      val bytes = generateSignedJWS(client.keyPair, nextNonce, claims)
      httpPOST(client.newCert, mime, bytes, client).flatMap {
        case (status, body, headers, nonce) if status < 250 =>
          val r = body
          Option(headers.get("Location")).map(fetchCert(client, csr, notBefore, notAfter, _)).getOrElse {
            error("[%s] No Certificate-Location was supplied in response", client.endpoint)
            throw new IllegalStateException("No Certificate-Location was supplied in response: 403: " + r)
          }

        case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          debug("[%s] Expired nonce used, getting new one", client.endpoint)
          getNonce(client).flatMap { gotNonce =>
            issue(client, csr, notBefore, notAfter, numTry) // we don't count this as an error
          }

        case (status, body, headers, nonce) if numTry < 3 =>
          error("[%s] Unable to issue a certificate, retrying (try #%s)", client.endpoint, numTry)
          val p = Promise[X509Certificate]()
          Schedule.once(() => issue(client, csr, notBefore, notAfter, numTry + 1).onSuccess(p.setValue).onFailure(p.setException), 10.seconds)
          p

        case (status, body, headers, nonce) =>
          error("[%s] Unable to issue a certificate after %s tries: %s - %s ", client.endpoint, numTry, status, body)
          throw new IllegalStateException("Unable to issue certificate: " + status + ": " + body)
      }
    }
  }

  private def fetchCert(client: AcmeClient, csr: PKCS10CertificationRequest,
                        notBefore: DateTime, notAfter: DateTime,
                        certUrl: String, numTry: Int = 0): Future[X509Certificate] = {
    httpGETbinary(new URI(certUrl), Map("Accept" -> "application/pkix-cert")).flatMap {
      case (200, body, headers, nonce) =>
        info("[%s] Got certificate", client.endpoint)
        val inputStream = new ByteBufInputStream(body)
        val certParser = new X509CertParser
        certParser.engineInit(inputStream)
        val cert = certParser.engineRead()
        inputStream.close()
        cert match {
          case x509: X509Certificate =>
            Future.value(x509)
          case _ =>
            error("[%s] Unable toparse certificate", client.endpoint)
            throw new IllegalStateException("Unable to parse certificate: " + body)
        }

      case (202, body, headers, nonce) if numTry <= 12 =>
        info("[%s] Certificate not ready yet, retrying in a bit..", client.endpoint)
        val p = Promise[X509Certificate]()
        val retry = () => fetchCert(client, csr, notBefore, notAfter, certUrl, numTry).map(p.setValue).onFailure(p.setException)
        Schedule.once(retry, 10.seconds)
        p

      case (400, body, headers, nonce) if body.toString(CharsetUtil.UTF_8) contains "urn:acme:error:badNonce" =>
        debug("[%s] Expired nonce used, getting new one", client.endpoint)
        getNonce(client).flatMap { gotNonce =>
          fetchCert(client, csr, notBefore, notAfter, certUrl, numTry) // we don't count this as an error
        }

      case (status, body, headers, nonce) =>
        error("[%s] Unable to fetch certificate after %s tries", client.endpoint, numTry)
        throw new IllegalStateException("Unable to download certificate: " + status + ": " + body)
    }
  }

  private[acme] def revoke(client: AcmeClient, certificate: X509Certificate, numTry: Int = 0): Future[Unit] = {
    debug("[%s] Revoking certificate for %s", client.endpoint, certificate.getSubjectDN.getName)
    client.nonce.recvAndSync().flatMap { nextNonce =>
      val claims = Map[String, Object](
        "resource" -> "revoke-cert",
        "certificate" -> java.util.Base64.getUrlEncoder.withoutPadding().encodeToString(certificate.getEncoded))
      val bytes = generateSignedJWS(client.keyPair, nextNonce, claims)
      httpPOST(client.revokeCert, mime, bytes, client).flatMap {
        case (200, body, headers, nonce) =>
          info("[%s] Successfully revoked certificate", client.endpoint)
          Future.Done

        case (400, body, headers, nonce) if body contains "urn:acme:error:badNonce" =>
          debug("[%s] Expired nonce used, getting new one", client.endpoint)
          getNonce(client).flatMap { gotNonce =>
            revoke(client, certificate, numTry) // we don't count this as an error
          }

        case (status, body, headers, nonce) if numTry < 3 =>
          error("[%s] Unable to revoke certificate, retrying (try #%s)", client.endpoint, numTry)
          val p = Promise[Unit]()
          Schedule.once(() => revoke(client, certificate, numTry + 1).map(p.setValue).onFailure(p.setException), 10.seconds)
          p

        case (status, body, headers, nonce) =>
          error("[%s] Unable to revoke certificate after %s tries", client.endpoint, numTry)
          throw new IllegalStateException("Unable to revoke certificate: " + status + ": " + body)
      }
    }
  }

}
