package org.zfnd.ed25519

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Arrays
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.must.Matchers
import scala.collection.mutable.HashSet

class VerificationKeyBytesTest extends AnyFlatSpec with Matchers {
  private val RANDOM = new SecureRandom()

  it must "properly compare VerificationKeyBytes objects" in {
    val vkb1 = new Array[Byte](VerificationKeyBytes.BYTE_LENGTH)
    while ({
      RANDOM.nextBytes(vkb1)
      !VerificationKeyBytes.bytesAreValid(vkb1)
    }) {}

    val vkb2 = new Array[Byte](VerificationKeyBytes.BYTE_LENGTH)
    while ({
      RANDOM.nextBytes(vkb2)
      !VerificationKeyBytes.bytesAreValid(vkb2)
    }) {}

    val vkbObj1 = new VerificationKeyBytes(vkb1)
    val vkbObj2 = new VerificationKeyBytes(vkb1)
    val vkbObj3 = new VerificationKeyBytes(vkb2)
    vkbObj1 == vkbObj2 mustBe true
    vkbObj2 == vkbObj3 mustBe false
  }

  it must "properly handle VerificationKeyBytes in hashed data structures" in {
    val vkb = new Array[Byte](VerificationKeyBytes.BYTE_LENGTH)
    while ({
      RANDOM.nextBytes(vkb)
      !VerificationKeyBytes.bytesAreValid(vkb)
    }) {}

    val vkbObj1 = new VerificationKeyBytes(vkb)
    val vkbObj2 = new VerificationKeyBytes(vkb)

    val vkbSet: HashSet[VerificationKeyBytes] = HashSet(vkbObj1, vkbObj2)
    vkbSet.size must be(1)
    vkbSet.contains(new VerificationKeyBytes(vkb)) mustBe true
  }

  it must "reject bad VerificationKeyBytes creation attempts via fromBytes()" in {
    val vkb1 = new Array[Byte](2 * VerificationKeyBytes.BYTE_LENGTH)
    RANDOM.nextBytes(vkb1)
    val vkbObj1 = VerificationKeyBytes.fromBytes(vkb1)
    vkbObj1.isPresent() mustBe false
  }

  it must "wrap VerificationKeyBytes (RFC 8410 - DER)" taggedAs(Pkcs8Test) in {
    val vkbValue = BigInt("4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d", 16)
    val vkb = VerificationKeyBytes.fromBytesOrThrow(vkbValue.toByteArray)

    val vkb_der = vkb.getEncoded()

    val expected_der = BigInt("302a300506032b65700321004d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d", 16)
    Arrays.equals(vkb_der, expected_der.toByteArray) mustBe true
  }

  it must "wrap VerificationKeyBytes (RFC 8410 - PEM)" taggedAs(PemTest) in {
    val vkbValue = BigInt("4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d", 16)
    val vkb = VerificationKeyBytes.fromBytesOrThrow(vkbValue.toByteArray)

    val vkb_pem = vkb.getPEM()

    val expected_pem = BigInt("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b3256774179454154536b57667a385a4571623372666f704f67556146634265786e755046795a3748465651334f68547651303d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a", 16)
    Arrays.equals(vkb_pem.getBytes(), expected_pem.toByteArray) mustBe true
  }

  it must "decode DER encoding (RFC 8410) to VerificationKeyBytes" taggedAs(Pkcs8Test) in {
    val der = BigInt("302a300506032b65700321004d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d", 16)
    val vkb = VerificationKeyBytes.generatePublic(der.toByteArray)

    val expected_vkb = BigInt("4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d", 16)
    Arrays.equals(vkb.getVerificationKeyBytes, expected_vkb.toByteArray) mustBe true
  }

  it must "decode PEM encoding (RFC 8410) to VerificationKeyBytes" taggedAs(PemTest) in {
    val pem = BigInt("2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d436f77425159444b3256774179454154536b57667a385a4571623372666f704f67556146634265786e755046795a3748465651334f68547651303d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d", 16)
    val pem_str = new String(pem.toByteArray, StandardCharsets.UTF_8)
    val vkb = VerificationKeyBytes.generatePublicPEM(pem_str)

    val expected_vkb = BigInt("4d29167f3f1912a6f7adfa293a051a15c05ec67b8f17267b1c5550dce853bd0d", 16)
    Arrays.equals(vkb.getVerificationKeyBytesCopy, expected_vkb.toByteArray) mustBe true
  }
}
