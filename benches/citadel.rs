use citadel::*;
use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

fn citadel_benchmark(c: &mut Criterion) {
    // Compute the setup
    let (constraints, pk, vk) = Citadel::generate_setup();

    // Benchmark the prover
    let license = License::random(&mut OsRng);

    let log = &format!("Citadel Prover ({} constraints)", constraints);
    c.bench_function(log, |b| {
        b.iter(|| {
            pk.prove(&mut OsRng, &Citadel::new(license.clone()))
                .expect("failed to prove")
        })
    });

    // Benchmark the verifier
    let proof = Citadel::prove(license, pk);
    let log = &format!("Citadel Verifier ({} constraints)", constraints);
    c.bench_function(log, |b| b.iter(|| Citadel::verify(&proof, &vk)));
}

criterion_group! {
    name = citadel;
    config = Criterion::default().sample_size(10);
    targets = citadel_benchmark
}
criterion_main!(citadel);
