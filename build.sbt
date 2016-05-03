import scalariform.formatter.preferences._
import sbt.Tests._

name := "wasted-acme"

organization := "io.wasted"

version := scala.io.Source.fromFile("version").mkString.trim

scalaVersion := "2.11.8"

crossScalaVersions := Seq("2.10.6", "2.11.8")

scalacOptions ++= Seq("-unchecked", "-deprecation", "-feature", "-language:postfixOps", "-language:implicitConversions")

libraryDependencies ++= Seq(
  "io.wasted" %% "wasted-util" % scala.io.Source.fromFile("version").mkString.trim % "provided",
  "net.liftweb" %% "lift-json" % "2.6.2",
  "com.twitter" %% "util-core" % "6.30.0",
  "joda-time" % "joda-time" % "2.7",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "org.bouncycastle" % "bcmail-jdk15on" % "1.52"
)

// For testing
libraryDependencies ++= Seq(
 "org.scalatest" %% "scalatest" % "2.2.2" % "test"
)

publishTo := Some("wasted.io/repo" at "http://repo.wasted.io/mvn")

parallelExecution in Test := false

testGrouping <<= definedTests in Test map { tests =>
  tests.map { test =>
    new Group(
      name = test.name,
      tests = Seq(test),
      runPolicy = InProcess)
  }.sortWith(_.name < _.name)
}

scalariformSettings

ScalariformKeys.preferences := FormattingPreferences().setPreference(AlignParameters, true)

sourceGenerators in Compile <+= buildInfo

buildInfoSettings

buildInfoKeys := Seq[BuildInfoKey](name, version, scalaVersion, sbtVersion) ++ Seq[BuildInfoKey]("commit" -> ("git rev-parse HEAD"!!).trim)

buildInfoPackage := "io.wasted.acme.build"

site.settings

site.includeScaladoc()

ghpages.settings

git.remoteRepo := "git@github.com:wasted/scala-acme.git"

net.virtualvoid.sbt.graph.Plugin.graphSettings

resolvers ++= Seq(
  "Local Maven Repository" at "file://"+Path.userHome.absolutePath+"/.m2/repository",
  "wasted.io/repo" at "http://repo.wasted.io/mvn",
  "Sonatype Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots/",
  "Maven Repo" at "http://repo1.maven.org/maven2/",
  "Typesafe Ivy Repo" at "http://repo.typesafe.com/typesafe/ivy-releases",
  "Typesafe Maven Repo" at "http://repo.typesafe.com/typesafe/releases/",
  "Java.net Maven2 Repository" at "http://download.java.net/maven/2/"
)

isSnapshot := true
