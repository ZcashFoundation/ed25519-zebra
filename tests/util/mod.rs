// functions are used in small_order but not recognized as such?
#![allow(dead_code)]

use color_eyre::{eyre::eyre, Report};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use ed25519_zebra as ed25519_zebra_zip215;

use std::convert::TryFrom;
pub struct TestCase {
    pub vk_bytes: [u8; 32],
    pub sig_bytes: [u8; 64],
    pub valid_legacy: bool,
    pub valid_zip215: bool,
}

impl core::fmt::Debug for TestCase {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.debug_struct("TestCase")
            .field("vk_bytes", &hex::encode(&self.vk_bytes[..]))
            .field("sig_bytes", &hex::encode(&self.sig_bytes[..]))
            .field("valid_legacy", &self.valid_legacy)
            .field("valid_zip215", &self.valid_zip215)
            .finish()
    }
}

impl TestCase {
    pub fn check(&self) -> Result<(), Report> {
        match (self.valid_legacy, self.check_legacy()) {
            (false, Err(_)) => Ok(()),
            (true, Ok(())) => Ok(()),
            (false, Ok(())) => Err(eyre!(
                "legacy-invalid signature case validated under legacy rules"
            )),
            (true, Err(e)) => {
                Err(e.wrap_err("legacy-valid signature case was rejected under legacy rules"))
            }
        }?;
        match (self.valid_zip215, self.check_zip215()) {
            (false, Err(_)) => Ok(()),
            (true, Ok(())) => Ok(()),
            (false, Ok(())) => Err(eyre!(
                "zip215-invalid signature case validated under zip215 rules"
            )),
            (true, Err(e)) => {
                Err(e.wrap_err("zip215-valid signature case was rejected under zip215 rules"))
            }
        }
    }

    fn check_legacy(&self) -> Result<(), Report> {
        use ed25519_zebra_legacy::{Signature, VerificationKey};
        let sig = Signature::from(self.sig_bytes);
        VerificationKey::try_from(self.vk_bytes).and_then(|vk| vk.verify(&sig, b"Zcash"))?;
        Ok(())
    }

    fn check_zip215(&self) -> Result<(), Report> {
        use ed25519_zebra_zip215::{Signature, VerificationKey};
        let sig = Signature::from(self.sig_bytes);
        VerificationKey::try_from(self.vk_bytes).and_then(|vk| vk.verify(&sig, b"Zcash"))?;
        Ok(())
    }
}

pub fn non_canonical_field_encodings() -> Vec<[u8; 32]> {
    // There are 19 finite field elements which can be represented
    // non-canonically as x + p with x + p fitting in 255 bits:
    let mut bytes = [
        237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
    ];
    let mut encodings = Vec::new();
    for i in 0..19u8 {
        bytes[0] = 237 + i;
        encodings.push(bytes);
    }
    encodings
}

// Compute all 25 non-canonical point encodings.  The first 5 are low order.
pub fn non_canonical_point_encodings() -> Vec<[u8; 32]> {
    // Points are encoded by the x-coordinate and a sign bit.
    // There are two ways to construct a non-canonical point encoding:
    //
    // (1) by using a non-canonical encoding of x (cf RFC8032§5.1.3.1)
    // (2) by selecting x so that both sign choices give the same point (cf RFC8032§5.1.3.4)
    //
    // Condition (2) is possible only when x = 0 (or is a non-canonical encoding of 0).

    let mut encodings = Vec::new();

    // The only non-canonical point encoding with canonical field encoding
    let mut zero_with_sign = [0; 32];
    zero_with_sign[31] |= 128;
    encodings.push(zero_with_sign);

    // Run through non-canonical field elements.
    // Not all field elements are x-coordinates of curve points, so check:
    for mut x in non_canonical_field_encodings().into_iter() {
        if CompressedEdwardsY(x).decompress().is_some() {
            encodings.push(x);
        }
        x[31] |= 128;
        if CompressedEdwardsY(x).decompress().is_some() {
            encodings.push(x);
        }
    }

    encodings
}

// Running this reveals that only the first 5 entries on the list have low order.
#[test]
fn print_non_canonical_points() {
    for encoding in non_canonical_point_encodings().into_iter() {
        let point = CompressedEdwardsY(encoding).decompress().unwrap();
        println!(
            "encoding {} has order {}",
            hex::encode(&encoding[..]),
            order(point)
        );
    }
}

pub fn order(point: EdwardsPoint) -> &'static str {
    use curve25519_dalek::traits::IsIdentity;
    if point.is_small_order() {
        let point2 = point + point;
        let point4 = point2 + point2;
        if point.is_identity() {
            "1"
        } else if point2.is_identity() {
            "2"
        } else if point4.is_identity() {
            "4"
        } else {
            "8"
        }
    } else {
        if point.is_torsion_free() {
            "p"
        } else {
            "8p"
        }
    }
}

#[test]
fn find_valid_excluded_encodings() {
    for (i, encoding) in EXCLUDED_POINT_ENCODINGS.iter().enumerate() {
        if let Some(point) = CompressedEdwardsY(*encoding).decompress() {
            println!("index {} is valid point of order {}", i, order(point));
        } else {
            println!("index {} is not a valid encoding", i);
        }
    }
}

/// These point encodings were specifically blacklisted by libsodium 1.0.15, in
/// an apparent (and unsuccessful) attempt to exclude points of low order.
///
/// To maintain exact compatibility with this version of libsodium, we encode
/// them here, following the Zcash protocol specification.
pub static EXCLUDED_POINT_ENCODINGS: [[u8; 32]; 11] = [
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    [
        0x13, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x85,
    ],
    [
        0xb4, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0xfa,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
    [
        0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ],
];
