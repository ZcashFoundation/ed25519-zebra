# CHANGELOG

Entries are listed in reverse chronological order.

# 4.0.4

* Implement `PartialEq` and `Eq` in `SigningKey` and `VerificationKey` (#102)
* Add `alloc` feature by @nazar-pc in (#161, #174)

Note: to use Rust older than `1.85`, you will need to downgrade the `base64ct`
crate:

```
cargo update base64ct --precise 1.6.0
```

# 4.0.3

* Update `curve25519-dalek` to `4.1.0`

# 4.0.2

* Update `curve25519-dalek` to `4.0.0`

# 4.0.1

* Fix no-std build with serde activated (#87)
* Update `curve25519-dalek` to `4.0.0-rc.3`

# 4.0.0

* `Signature` is now an alias for `ed25519::Signature`
  * `impl From<Signature> for [u8; 64]` no longer exists; use `to_bytes()` instead.
* `signature::{Signer, Verifier} is now implemented for  `SigningKey` and `VerificationKey`.
* Updates `sha2` version to `0.10` and `curve25519-dalek` version to `4.0.0-rc.2`.
* Add DER & PEM support for SigningKeySeed and VerificationKeyBytes (RFC 8410) #46 https://github.com/ZcashFoundation/ed25519-zebra/pull/46
  * This is under the non-default `pem` and `pkcs8` features

MSRV increased to `1.65.0`.

# 3.1.0

* Add no_std support by @pvdrz in https://github.com/ZcashFoundation/ed25519-zebra/pull/57

# 3.0.0

* Fix typo by @rex4539 in https://github.com/ZcashFoundation/ed25519-zebra/pull/32
* Add Zeroize impl for SigningKey by @kim in https://github.com/ZcashFoundation/ed25519-zebra/pull/34
* Add JNI code for ed25519-zebra by @droark in https://github.com/ZcashFoundation/ed25519-zebra/pull/37
* Update rand_core to 0.6 and rand to 0.8 by @dconnolly in https://github.com/ZcashFoundation/ed25519-zebra/pull/44
* dependencies: update zeroize to 1.2 by @FintanH in https://github.com/ZcashFoundation/ed25519-zebra/pull/52

# 2.2.0

* Add `PartialOrd`, `Ord` implementations for `VerificationKeyBytes`.  While
  the derived ordering is not cryptographically meaningful, deriving these
  traits is useful because it allows, e.g., using `VerificationKeyBytes` as the
  key to a `BTreeMap` (contributed by @cloudhead).

# 2.1.2

* Updates `sha2` version to `0.9` and `curve25519-dalek` version to `3`.

# 2.1.1

* Add a missing multiplication by the cofactor in batch verification and test
  that individual and batch verification agree.  This corrects an omission that
  should have been included in `2.0.0`.

# 2.1.0

* Implements `Clone + Debug` for `batch::Item` and provides
  `batch::Item::verify_single` to perform fallback verification in case
  of batch failure.

# 2.0.0

* Implements ZIP 215, so that batched and individual verification
  agree on whether signatures are valid.

# 1.0.0

* Adds `impl TryFrom<&[u8]>` for all types.

# 1.0.0-pre.0

* Add a note about versioning to handle ZIP 215.

# 0.4.1

* Change `docs.rs` configuration in `Cargo.toml` to not refer to the removed
  `batch` feature so that the docs render correctly on `docs.rs`.

# 0.4.0

* The sync batch verification api is changed to remove a dependence on the
  message lifetime that made it difficult to use in async contexts.

# 0.3.0

* Change terminology from secret and public keys to signing and verification
  keys.
* Remove async batch verification in favor of a sync api; the async approach is
  to be developed in another crate.

# 0.2.3

* The previous implementation exactly matched the behavior of `libsodium`
  `1.0.15` with the `ED25519_COMPAT` configuration, but this configuration
  wasn't used by `zcashd`. This commit changes the validation rules to exactly
  match without `ED25519_COMPAT`, and highlights the remaining inconsistencies
  with the Zcash specification that were not addressed in the previous spec
  fix.

# 0.2.2

* Adds `impl AsRef<[u8]> for PublicKey`.
* Adds `impl AsRef<[u8]> for SecretKey`.

# 0.2.1

* Adds `impl AsRef<[u8]> for PublicKeyBytes`.

# 0.2.0

* Adds experimental futures-based batch verification API, gated by the `batch` feature.

# 0.1.0

Initial release, attempting to match the actual `zcashd` behavior.
