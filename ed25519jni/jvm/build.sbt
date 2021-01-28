organization := "org.zfnd"

name := "ed25519jni"

version := "0.0.1"

scalaVersion := "2.12.10"

scalacOptions ++= Seq("-Xmax-classfile-name", "140")

autoScalaLibrary := false

crossPaths := false

libraryDependencies ++= Deps.ed25519jni

unmanagedResourceDirectories in Compile += baseDirectory.value / "natives"

publishArtifact := true

testOptions in Test += Tests.Argument(TestFrameworks.ScalaCheck, "-verbosity", "3")
