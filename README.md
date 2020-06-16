Zcash-flavored Ed25519 for use in [Zebra][zebra].

Zcash uses Ed25519 for [JoinSplit signatures][zcash_protocol_jssig] with
particular validation rules around edge cases in Ed25519 signatures.  Ed25519,
as specified in [RFC8032], does not specify behaviour around these edge cases
and so does not require conformant implementations to agree on whether a
signature is valid.  For most applications, these edge cases are irrelevant,
but in Zcash, nodes must be able to reach consensus on which signatures would
be valid, so these validation behaviors are *consensus-critical*.

Because the Ed25519 validation rules are consensus-critical for Zcash, Zebra
requires an Ed25519 library that implements the Zcash-flavored validation rules
specifically, and since it is unreasonable to expect an upstream dependency to
maintain Zcash-specific behavior, this crate provides an Ed25519 implementation
matching the Zcash consensus rules exactly.

## Example

```
use std::convert::TryFrom;
use rand::thread_rng;
use ed25519_zebra::*;

let msg = b"Zcash";

// Signer's context
let (vk_bytes, sig_bytes) = {
    // Generate a signing key and sign the message
    let sk = SigningKey::new(thread_rng());
    let sig = sk.sign(msg);

    // Types can be converted to raw byte arrays with From/Into
    let sig_bytes: [u8; 64] = sig.into();
    let vk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

    (vk_bytes, sig_bytes)
};

// Verify the signature
assert!(
    VerificationKey::try_from(vk_bytes)
        .and_then(|vk| vk.verify(&sig_bytes.into(), msg))
        .is_ok()
);
```

[zcash_protocol_jssig]: https://zips.z.cash/protocol/protocol.pdf#concretejssig
[RFC8032]: https://tools.ietf.org/html/rfc8032
[zebra]: https://github.com/ZcashFoundation/zebra
