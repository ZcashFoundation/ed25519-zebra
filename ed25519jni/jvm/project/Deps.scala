import sbt._

object Deps {

  object V {
    val nativeLoaderV = "2.4.0"
    val scalactic = "3.2.15"
    val scalaTest = "3.2.15"
    val slf4j = "1.7.30"
  }

  object Test {
    val nativeLoader = "org.scijava" % "native-lib-loader" % V.nativeLoaderV
    val scalactic = "org.scalactic" %% "scalactic" % V.scalactic
    val scalaTest = "org.scalatest" %% "scalatest" % V.scalaTest % "test"
    val slf4jApi = "org.slf4j" % "slf4j-api" % V.slf4j
    val slf4jSimple = "org.slf4j" % "slf4j-simple" % V.slf4j % "test"
  }

  val ed25519jni = List(
    Test.nativeLoader,
    Test.scalactic,
    Test.scalaTest,
    Test.slf4jApi,
    Test.slf4jSimple,
  )
}
