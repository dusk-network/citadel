use citadel::*;
use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

fn citadel_benchmark(c: &mut Criterion) {
    // Compute the setup
    let (pp, constraints, pk, vd) = citadel_setup();

    // Benchmark the prover
    let branch = poseidon_branch_random(&mut OsRng);
    let license = License::random(&mut OsRng);

    let log = &format!("Citadel Prover ({} constraints)", constraints);
    c.bench_function(log, |b| {
        b.iter(|| citadel_prove(&pp, &license, &branch, &pk))
    });

    // Benchmark the verifier
    let proof = citadel_prove(&pp, &license, &branch, &pk);
    let log = &format!("Citadel Verifier ({} constraints)", constraints);
    c.bench_function(log, |b| b.iter(|| citadel_verify(&pp, &vd, &proof)));
}

criterion_group! {
    name = citadel;
    config = Criterion::default().sample_size(10);
    targets = citadel_benchmark
}
criterion_main!(citadel);
