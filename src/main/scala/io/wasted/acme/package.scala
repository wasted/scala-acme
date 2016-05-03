package io.wasted

import io.wasted.util.Tryo
import net.liftweb.json._
import org.joda.time.DateTime
import org.joda.time.format.{DateTimeFormat, ISODateTimeFormat}

package object acme {
  private[acme] object DateParser {
    private final val formatters = List(
      DateTimeFormat.forPattern("yyyy-MM-dd").withZoneUTC(),
      ISODateTimeFormat.dateTimeNoMillis())

    def apply(x: String): Option[DateTime] = {
      scala.util.Try(new DateTime(x)).toOption orElse
        formatters.flatMap(fmt => scala.util.Try(fmt.parseDateTime(x)).toOption).headOption
    }
    def parse(s: String, format: Formats) =
      format.dateFormat.parse(s).map(_.getTime).getOrElse(throw new MappingException("Invalid date format " + s))
  }

  private[acme] class DateTimeSerializer extends CustomSerializer[DateTime](format =>
    ({
      case JString(s) => DateParser(s).getOrElse {
        throw new MappingException("Invalid date format")
      }
      case JNull => null
    },
      {
        case d: DateTime => JString(format.dateFormat.format(d.toDate))
      }))

  /*
  *  Serializer and Deserializers for Enumeration
  */
  private[acme] class EnumerationSerializer(enumList: List[Enumeration]) extends net.liftweb.json.Serializer[Enumeration#Value] {
    import JsonDSL._
    val EnumerationClass = classOf[Enumeration#Value]
    val formats = Serialization.formats(NoTypeHints)

    //  Deserializer Function for Enumeration
    def deserialize(implicit format: Formats): PartialFunction[(TypeInfo, JValue), Enumeration#Value] = {
      case (TypeInfo(EnumerationClass, _), json) => json match {
        case JObject(List(JField(name, JString(value)))) if fetchEnumValue(enumList, value).isDefined => fetchEnumValue(enumList, value).get
        case JString(value) if fetchEnumValue(enumList, value).isDefined => fetchEnumValue(enumList, value).get
        case value => throw new MappingException("Can't convert " + value + " to " + EnumerationClass)
      }
    }

    def serialize(implicit format: Formats): PartialFunction[Any, JValue] = {
      case i: Enumeration#Value => i.toString
    }

    private def fetchEnumValue(enumList: List[Enumeration], value: String): Option[Enumeration#Value] = {
      var defaultEnumValue: Option[Enumeration#Value] = None
      for (enumItem <- enumList) {
        for (enumValue <- enumItem.values) {
          enumValue.toString == value match {
            case true => defaultEnumValue = Tryo(enumItem.withName(value))
            case _ =>
          }
        }
      }
      defaultEnumValue
    }

  }
}
