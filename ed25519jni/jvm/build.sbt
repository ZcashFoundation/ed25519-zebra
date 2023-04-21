organization := "org.zfnd"

name := "ed25519jni"

version := "0.0.5-JNI-DEV"

scalaVersion := "3.1.3"

//scalacOptions ++= Seq("-Xmax-classfile-name", "140")

autoScalaLibrary := false // exclude scala-library from dependencies

crossPaths := false // drop off Scala suffix from artifact names.

libraryDependencies ++= Deps.ed25519jni

Compile / unmanagedResourceDirectories += baseDirectory.value / "natives"

publishArtifact := true

Compile / doc / javacOptions ++= Seq(
  "-windowtitle", "JNI bindings for ed25519-zebra"
)

Test / testOptions += Tests.Argument(TestFrameworks.ScalaCheck, "-verbosity", "3")
