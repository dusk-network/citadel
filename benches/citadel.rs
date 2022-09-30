use citadel::*;
use criterion::{criterion_group, criterion_main, Criterion};

fn citadel_benchmark(c: &mut Criterion) {
    // Compute the setup
    let (pp, constraints, circuit, pk, vd) = citadel_setup();

    // Benchmark the prover
    let log = &format!("Citadel Prover ({} constraints)", constraints);
    c.bench_function(log, |b| b.iter(|| citadel_prover(&pp, &circuit, &pk)));

    // Benchmark the verifier
    let proof = citadel_prover(&pp, &circuit, &pk);
    let log = &format!("Citadel Verifier ({} constraints)", constraints);
    c.bench_function(log, |b| b.iter(|| citadel_verifier(&pp, &vd, &proof)));
}

criterion_group! {
    name = citadel;
    config = Criterion::default().sample_size(10);
    targets = citadel_benchmark
}
criterion_main!(citadel);
