use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};

fn bench_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("quantumvault");
    
    group.bench_function("keygen", |b| b.iter(|| {
        PQIdentity::generate().unwrap()
    }));
    
    let alice = PQIdentity::generate().unwrap();
    let bob = PQIdentity::generate().unwrap();
    let bob_pub = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();
    let msg = vec![0u8; 1024];

    group.bench_function("encrypt_and_sign_1kb", |b| b.iter(|| {
        PQFile::encrypt_and_sign(black_box(&msg), black_box(&bob_pub), black_box(&alice)).unwrap()
    }));

    let envelope = PQFile::encrypt_and_sign(&msg, &bob_pub, &alice).unwrap();
    let alice_pub = PQPublicKey::from_bytes(&alice.export_public().unwrap()).unwrap();

    group.bench_function("decrypt_and_verify_1kb", |b| b.iter(|| {
        PQFile::decrypt_and_verify(black_box(&envelope), black_box(&bob), black_box(Some(&alice_pub))).unwrap()
    }));
    
    group.finish();
}

criterion_group!(benches, bench_crypto);
criterion_main!(benches);
