//! Crypto primitives: KDF (AES-KDF, Argon2), ciphers (AES-CBC, ChaCha20).
//!
//! Run: cargo bench --bench crypto_kdf

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use keepass_rs::{AesCipher, AesKdf, Argon2KdfEngine, CipherMode, KdfEngine};

fn bench_aes_kdf(c: &mut Criterion) {
    let kdf = AesKdf;
    let mut group = c.benchmark_group("aes_kdf");
    for rounds in [1_000u64, 10_000, 100_000] {
        let mut params = kdf.default_parameters();
        params.set_uint64("R", rounds);
        params.set_byte_array("S", &[0x42u8; 32]);
        group.bench_function(format!("rounds={rounds}"), |b| {
            b.iter(|| {
                let _ = kdf
                    .transform(black_box(b"password-1234567890"), black_box(&params))
                    .unwrap();
            })
        });
    }
    group.finish();
}

fn bench_argon2(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2");
    for (label, kdf) in [
        ("Argon2d", Argon2KdfEngine::argon2d()),
        ("Argon2id", Argon2KdfEngine::argon2id()),
    ] {
        let mut params = kdf.default_parameters();
        params.set_byte_array("S", &[0x42u8; 32]);
        // KeePass-typical: 16 MiB memory, 2 iterations, 2 lanes.
        // (M is in KiB; must be ≥ 8 × parallelism.)
        params.set_uint64("M", 16 * 1024);
        params.set_uint64("I", 2);
        params.set_uint32("P", 2);
        group.bench_function(label.to_string(), |b| {
            b.iter(|| {
                let _ = kdf
                    .transform(black_box(b"password-1234567890"), black_box(&params))
                    .unwrap();
            })
        });
    }
    group.finish();
}

fn bench_aes_cbc(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let iv = [0x13u8; 16];
    let mut group = c.benchmark_group("aes_cbc");
    for size in [1024usize, 16 * 1024, 256 * 1024] {
        let data = vec![0xABu8; size];
        group.bench_function(format!("encrypt_{size}B"), |b| {
            let enc = AesCipher::new(CipherMode::Encrypt, &key, &iv).unwrap();
            b.iter(|| {
                let _ = enc.process(black_box(&data)).unwrap();
            })
        });
        // Pre-encrypt for the decrypt bench.
        let enc = AesCipher::new(CipherMode::Encrypt, &key, &iv).unwrap();
        let ct = enc.process(&data).unwrap();
        group.bench_function(format!("decrypt_{size}B"), |b| {
            let dec = AesCipher::new(CipherMode::Decrypt, &key, &iv).unwrap();
            b.iter(|| {
                let _ = dec.process(black_box(&ct)).unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aes_kdf, bench_argon2, bench_aes_cbc);
criterion_main!(benches);
