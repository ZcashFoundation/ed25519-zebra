lazy val root = project
  .in(file("."))
  .aggregate(
    ed25519jni
  )

lazy val ed25519jni = project
  .in(file("ed25519jni"))
  .settings(
    unmanagedResourceDirectories in Compile += baseDirectory.value / "natives"
  )
  .enablePlugins()

publishArtifact in root := false
