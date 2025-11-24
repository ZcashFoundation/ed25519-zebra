use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use core::convert::TryFrom;
use curve25519_dalek::scalar::Scalar;
use ed25519_zebra::*;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha512};

fn sigs_with_distinct_pubkeys() -> impl Iterator<Item = (VerificationKeyBytes, Signature)> {
    std::iter::repeat_with(|| {
        let sk = SigningKey::new(thread_rng());
        let pk_bytes = VerificationKeyBytes::from(&sk);
        let sig = sk.sign(b"");
        (pk_bytes, sig)
    })
}

fn sigs_with_same_pubkey() -> impl Iterator<Item = (VerificationKeyBytes, Signature)> {
    let sk = SigningKey::new(thread_rng());
    let pk_bytes = VerificationKeyBytes::from(&sk);
    std::iter::repeat_with(move || {
        let sig = sk.sign(b"");
        (pk_bytes, sig)
    })
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Verification");
    for n in [8usize, 16, 32, 64, 128, 256].iter() {
        group.throughput(Throughput::Elements(*n as u64));
        let sigs = sigs_with_distinct_pubkeys().take(*n).collect::<Vec<_>>();
        group.bench_with_input(
            BenchmarkId::new("Unbatched verification", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    for (vk_bytes, sig) in sigs.iter() {
                        let _ =
                            VerificationKey::try_from(*vk_bytes).and_then(|vk| vk.verify(sig, b""));
                    }
                })
            },
        );
        #[cfg(feature = "alloc")]
        group.bench_with_input(
            BenchmarkId::new("Distinct Pubkeys (Classic)", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify(thread_rng())
                })
            },
        );
        #[cfg(feature = "alloc")]
        group.bench_with_input(
            BenchmarkId::new("Distinct Pubkeys (hEEA)", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify_heea(thread_rng())
                })
            },
        );
        #[cfg(feature = "alloc")]
        let sigs = sigs_with_same_pubkey().take(*n).collect::<Vec<_>>();
        #[cfg(feature = "alloc")]
        group.bench_with_input(
            BenchmarkId::new("Same Pubkey (Classic)", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify(thread_rng())
                })
            },
        );
        #[cfg(feature = "alloc")]
        group.bench_with_input(
            BenchmarkId::new("Same Pubkey (hEEA)", n),
            &sigs,
            |b, sigs| {
                b.iter(|| {
                    let mut batch = batch::Verifier::new();
                    for (vk_bytes, sig) in sigs.iter().cloned() {
                        batch.queue((vk_bytes, sig, b""));
                    }
                    batch.verify_heea(thread_rng())
                })
            },
        );
    }
    group.finish();
}

fn bench_single_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single Verification");

    group.bench_function("ed25519_zebra", |b| {
        let sk = SigningKey::new(thread_rng());
        let vk = VerificationKey::from(&sk);
        let sig = sk.sign(b"");
        b.iter(|| {
            let _ = vk.verify(&sig, b"");
        })
    });

    group.bench_function("ed25519_hEEA", |b| {
        let sk = SigningKey::new(thread_rng());
        let vk = VerificationKey::from(&sk);
        let sig = sk.sign(b"");
        b.iter(|| {
            let _ = vk.verify_heea(&sig, b"");
        })
    });

    #[cfg(feature = "alloc")]
    group.bench_function("batch::Verifier single", |b| {
        let sk = SigningKey::new(thread_rng());
        let vk_bytes = VerificationKeyBytes::from(&sk);
        let sig = sk.sign(b"");
        b.iter(|| {
            let mut batch = batch::Verifier::new();
            batch.queue((vk_bytes, sig, b""));
            let _ = batch.verify(thread_rng());
        })
    });

    group.finish();
}

fn bench_generate_half_size_scalars(c: &mut Criterion) {
    let mut group = c.benchmark_group("Half-Size Scalars");

    // Pre-generate random scalars for benchmarking
    let mut rng = thread_rng();
    let random_scalars: Vec<Scalar> = (0..100)
        .map(|_| {
            let mut random_bytes = [0u8; 64];
            rng.fill_bytes(&mut random_bytes);
            Scalar::from_hash(Sha512::new().chain_update(&random_bytes))
        })
        .collect();

    group.bench_function("generate_half_size_scalars", |b| {
        let mut i = 0;
        b.iter(|| {
            let h = &random_scalars[i % random_scalars.len()];
            i += 1;
            heea::generate_half_size_scalars(h)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_generate_half_size_scalars,
    bench_single_verify,
    bench_batch_verify,
);
criterion_main!(benches);
