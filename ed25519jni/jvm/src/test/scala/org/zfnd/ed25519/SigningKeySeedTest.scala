package org.zfnd.ed25519

import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Arrays
import org.scalatest.{ FlatSpec, MustMatchers }
import scala.collection.mutable.HashSet

class SigningKeySeedTest extends FlatSpec with MustMatchers {
  it must "wrap SigningKeySeed (RFC 8410 - DER)" in {
    val sksValue = BigInt("17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85", 16)
    val sks = SigningKeySeed.fromBytesOrThrow(sksValue.toByteArray)

    val sks_der = sks.getEncoded()

    val expected_der = BigInt("302c020100300506032b6570042017ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85", 16)
    Arrays.equals(sks_der, expected_der.toByteArray) mustBe true
  }

  it must "wrap SigningKeySeed (RFC 8410 - PEM)" in {
    val sksValue = BigInt("17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85", 16)
    val sks = SigningKeySeed.fromBytesOrThrow(sksValue.toByteArray)

    val sks_pem = sks.getPEM()

    val expected_pem = BigInt("2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43774341514177425159444b32567742434158375a787a3664746b6e73474a70684b4448462f4663434f43423847716e6676537854342f3965587168513d3d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d", 16)
    Arrays.equals(sks_pem.getBytes(), expected_pem.toByteArray) mustBe true
  }

  it must "decode DER encoding (RFC 8410) to SigningKeySeed" in {
    val der = BigInt("302c020100300506032b6570042017ed9c73e9db649ec189a612831c5fc570238207c1aa9dfbd2c53e3ff5e5ea85", 16)
    val vkb = SigningKeySeed.generatePrivate(der.toByteArray)

    val expected_vkb = BigInt("17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85", 16)

    Arrays.equals(vkb.getSigningKeySeed, expected_vkb.toByteArray) mustBe true
  }

  it must "decode PEM encoding (RFC 8410) to SigningKeySeed" in {
    val pem = BigInt("2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d0a4d43774341514177425159444b32567742434158375a787a3664746b6e73474a70684b4448462f4663434f43423847716e6676537854342f3965587168513d3d0a2d2d2d2d2d454e442050524956415445204b45592d2d2d2d2d", 16)
    val pem_str = new String(pem.toByteArray, StandardCharsets.UTF_8)
    val vkb = SigningKeySeed.generatePrivatePEM(pem_str)

    val expected_vkb = BigInt("17ED9C73E9DB649EC189A612831C5FC570238207C1AA9DFBD2C53E3FF5E5EA85", 16)
    Arrays.equals(vkb.getSigningKeySeedCopy(), expected_vkb.toByteArray) mustBe true
  }
}
