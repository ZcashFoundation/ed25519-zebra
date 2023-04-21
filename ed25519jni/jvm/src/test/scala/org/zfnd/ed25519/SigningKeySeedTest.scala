package org.zfnd.ed25519

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Arrays
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.must.Matchers
import scala.collection.mutable.HashSet

class SigningKeySeedTest extends AnyFlatSpec with Matchers {
  it must "wrap SigningKeySeed (RFC 8410 - DER)" taggedAs(Pkcs8Test) in {
    val sksValue = BigInt("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842", 16)
    val sks = SigningKeySeed.fromBytesOrThrow(sksValue.toByteArray.drop(1))

    val sks_der = sks.getEncoded()

    val expected_der = BigInt("302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842", 16)
    Arrays.equals(sks_der, expected_der.toByteArray) mustBe true
  }

  it must "wrap SigningKeySeed (RFC 8410 - PEM)" taggedAs(PemTest) in {
    val sksValue = BigInt("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842", 16)
    val sks = SigningKeySeed.fromBytesOrThrow(sksValue.toByteArray.drop(1))

    val sks_pem = sks.getPEM()

    val expected_pem = BigInt("2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43344341514177425159444b32567742434945494e5475637476354531684b31626259386664702b4b30362f6e776f792f48552b2b435871493945645668430a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d0a", 16)
    Arrays.equals(sks_pem.getBytes(), expected_pem.toByteArray) mustBe true
  }

  it must "decode DER encoding (RFC 8410) to SigningKeySeed" taggedAs(Pkcs8Test) in {
    val der = BigInt("302e020100300506032b657004220420d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842", 16)
    val vkb = SigningKeySeed.generatePrivate(der.toByteArray)

    val expected_vkb = BigInt("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842", 16)

    Arrays.equals(vkb.getSigningKeySeed, expected_vkb.toByteArray.drop(1)) mustBe true
  }

  it must "decode PEM encoding (RFC 8410) to SigningKeySeed" taggedAs(PemTest) in {
    val pem = BigInt("2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43344341514177425159444b32567742434945494e5475637476354531684b31626259386664702b4b30362f6e776f792f48552b2b435871493945645668430a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d", 16)
    val pem_str = new String(pem.toByteArray, StandardCharsets.UTF_8)
    val vkb = SigningKeySeed.generatePrivatePEM(pem_str)

    val expected_vkb = BigInt("D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842", 16)
    Arrays.equals(vkb.getSigningKeySeedCopy(), expected_vkb.toByteArray.drop(1)) mustBe true
  }
}
