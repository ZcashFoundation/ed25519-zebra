# JNI
Code that provides a [JNI](https://en.wikipedia.org/wiki/Java_Native_Interface)
for the library is included. Allows any JNI-using language to interact with
specific `ed25519-zebra` calls and provides a minor analogue for some Rust
classes, allowing for things like basic sanity checks of certain values.  Tests
written in Scala have also been included.

Note that Scala 3 is required to build and test the JNI code.

## Build Requirements
- For PEM support, the `pem` feature must be enabled in both `Cargo.toml` files
  (`pem = ["der"]`).
- For PKCS #8 (DER) support, the `pkcs8` feature must be enabled in both `Cargo.toml`
  files (`pkcs8 = ["dep:pkcs8"]`).

## Compilation / Library Usage
To build the JNI code, there are several steps. The exact path forward depends
on the user's preferred deployment method. No matter what, the following steps
must be performed at the beginning.

- Run `cargo build` in the root directory. This generates the core Rust code.
- Run `cargo build` in the `ed25519jni/rust` subdirectory. This generates the Rust
  glue code libraries (`libed25519jni.a` and `libed25519jni.{so/dylib}`).

From here, there are two deployment methods: Direct library usage and JARs.

### JAR
<a name="jar"></a>

It's possible to generate a JAR that can be loaded into a project via
[SciJava's NativeLoader](https://javadoc.scijava.org/SciJava/org/scijava/nativelib/NativeLoader.html),
along with the Java JNI interface file. There are two extra steps to perform
after the mandatory compilation steps.

- Run `jni_jar_prereq.sh` from the `ed25519jni/scripts` subdirectory. Use the `-d`
  flag if working with debug builds. This script performs some JAR setup steps, and
  enables the local Scala tests against the JNI code.
- Run `sbt clean publishLocal` from the `ed25519jni/jvm` subdirectory. This
  generates the final `ed25519jni.jar` file in the {$HOME}/.ivy2/local subdirectory.

### Direct library usage
Use a preferred method to load the Rust core and JNI libraries directly as
needed. If necessary, include the JNI Java files too.

Note that the code is designed to support only the aforementioned JAR method. Local
changes may be required to support other deployment methods.

## Testing
### Prerequisites
To reiterate, before running any tests, execute the first step from the
[JAR compilation method](#jar) section above.

### Commands
The precise test command will depend on if you built the code with PKCS8 and/or
PEM support. Both are disabled by default. This also means that, without disabling
the associated tests or enabling the features, an `UnsatisfiedLinkError` Java error
will occur.

The following examples show how to run tests.

- `sbt test` - Run all tests. Must compile with PEM and PKCS #8 support.
- `sbt "testOnly * -- -l Pkcs8Test"` - Run all tests unrelated to PKCS #8.
- `sbt "testOnly * -- -l \"PemTest Pkcs8Test\""` - Run all tests unrelated to PEM
  and PKCS #8.

## Capabilities
Among other things, the JNI code can perform the following actions.

* Generate a random 32 byte signing key seed.
* Generate a 32 byte verification key from a signing key seed.
* Sign arbitrary data with a signing key seed.
* Verify a signature for arbitrary data with verification key bytes.
* Generate DER bytes and PEM strings for signing key seeds and verification key bytes, and read back the DER bytes and PEM strings into signing key seeds and verification key bytes.
