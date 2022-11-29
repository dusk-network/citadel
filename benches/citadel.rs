use citadel::*;
use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

fn citadel_benchmark(c: &mut Criterion) {
    // Compute the setup
    let (pp, constraints, pk, vd) = Citadel::generate_setup();

    // Benchmark the prover
    let branch = Citadel::poseidon_branch_random(&mut OsRng);
    let license = License::random(&mut OsRng);

    let log = &format!("Citadel Prover ({} constraints)", constraints);
    c.bench_function(log, |b| b.iter(|| license.prove(&pp, &branch, &pk)));

    // Benchmark the verifier
    let proof = license.prove(&pp, &branch, &pk);
    let log = &format!("Citadel Verifier ({} constraints)", constraints);
    c.bench_function(log, |b| b.iter(|| License::verify(&pp, &vd, &proof)));
}

criterion_group! {
    name = citadel;
    config = Criterion::default().sample_size(10);
    targets = citadel_benchmark
}
criterion_main!(citadel);
