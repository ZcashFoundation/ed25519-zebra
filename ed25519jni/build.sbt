name := "ed25519jni"

version := "0.0.1"

autoScalaLibrary := false

crossPaths := false

libraryDependencies ++= Deps.ed25519jni

publishArtifact := true

testOptions in Test += Tests.Argument(TestFrameworks.ScalaCheck, "-verbosity", "3")
