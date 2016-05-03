package io.wasted.acme.test

import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference

import com.twitter.conversions.time._
import com.twitter.util.{Await, Promise}
import io.netty.handler.codec.http._
import io.wasted.acme.{AcmeAuthorization, AcmeAuthorizationState, AcmeClient}
import io.wasted.util.Logger
import io.wasted.util.http._
import org.joda.time.DateTime
import org.scalatest._
import org.scalatest.concurrent._

class WastedAcmeTest extends WordSpec with Logger with ScalaFutures with AsyncAssertions with BeforeAndAfter {

  val responder = new HttpResponder("wasted-http")
  val server = new AtomicReference[HttpServer[FullHttpRequest, HttpResponse]](null)
  val handle = new AtomicReference[(String, String)](null)
  val keyPair = {
    val file = new java.io.File(System.getProperty("user.home") + "/.acme.staging.pem")
    val source = scala.io.Source.fromFile(file)
    val s = source.getLines().mkString("\n")
    source.close()
    AcmeClient.pemToKeyPair(s)
  }

  //  val keyPair = AcmeClient.generateKeyPair()
  val hostname = "foo%s.home.el8.nl".format(new java.util.Date().getTime)

  val acmeClient = AcmeClient("https://acme-staging.api.letsencrypt.org/", keyPair, List("mailto:foo@" + hostname))

  before {
    server.set(HttpServer[FullHttpRequest, HttpResponse](NettyHttpCodec()).handler {
      case (ctx, req) =>
        req.map { req =>
          if (Option(handle.get).isEmpty) {
            error("No handle available yet")
            responder(HttpResponseStatus.NOT_FOUND)
          } else if (req.getUri == "/.well-known/acme-challenge/" + handle.get._1) {
            info("Provider came by")
            responder(HttpResponseStatus.OK, Some(handle.get._2))
          } else {
            error("Not found, whoops")
            responder(HttpResponseStatus.NOT_FOUND)
          }
        }
    }.bind(new InetSocketAddress(8080)))
  }

  "Let's Decrypt!" should {
    val acmeRegistered = Promise[Unit]()
    val acmeChallenge = Promise[AcmeAuthorization]()
    val acmeAuthorization = Promise[AcmeAuthorizationState.Value]()
    val acmeCertificate = Promise[X509Certificate]()

    "register an account" in {
      acmeClient.map { client =>
        client.registration()
          .onSuccess(acmeRegistered.setValue).onFailure(acmeRegistered.setException)
      }
      Await.result(acmeRegistered, 3.seconds)
    }

    "authorize a hostname" in {
      acmeRegistered.flatMap { regged =>
        acmeClient.map { client =>
          client.authorize(hostname)
            .onSuccess(acmeChallenge.setValue).onFailure(acmeChallenge.setException)
        }
      }
      Await.result(acmeChallenge, 30.seconds)
    }

    "complete the challenge" in {
      acmeChallenge.map { authInfo =>
        authInfo.challenges.find(_.`type` == "http-01").map { challenge =>
          info("found challenge: " + challenge)
          handle.set(challenge.token -> challenge.getHTTP01ChallengeContent)
          acmeClient.map { client =>
            client.challenge(challenge)
              .onSuccess(acmeAuthorization.setValue).onFailure(acmeAuthorization.setException)
          }
        }
      }
      Await.result(acmeAuthorization, 30.seconds)
    }

    "issue a certificate" in {
      acmeAuthorization.flatMap { authorization =>
        acmeClient.map { client =>
          val tmpKey = AcmeClient.generateKeyPair()
          val csr = AcmeClient.generateCertificationRequest(tmpKey, hostname :: Nil)
          val notBefore = DateTime.now()
          val notAfter = notBefore.plusHours(1)
          client.issue(csr, notBefore, notAfter)
            .onSuccess(acmeCertificate.setValue).onFailure(acmeCertificate.setException)
        }
      }
      Await.result(acmeCertificate, 2.minutes)
    }

    "test seeding of invalid nonce" in {
      Await.result(acmeClient.map { client =>
        // we get the valid nonce out of there
        client.nonce.recvAndAwait()
        // seed invalid nonce
        client.nonce ! "foo"
        assert(client.nonce.recvAndAwait() == "foo", "fake nonce is not working")
      }, 10.seconds)
    }

    "revoke the certificate with bad nonce" in {
      Await.result(acmeCertificate.flatMap { certificate =>
        acmeClient.map { client =>
          // seed invalid nonce
          client.nonce ! "foo"
          client.revoke(certificate)
        }
      }, 10.seconds)
    }

  }

  after(server.get.shutdown())
}

