# Citadel Core

![Build Status](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/zk-citadel.svg)](https://crates.io/crates/zk-citadel)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This package contains the off-chain Citadel protocol API: encrypted request and license objects, session cookies, policy-aware cookie verification, deployment-bound hash/KDF helpers, Citadel Schnorr transcripts, and the license circuit behind the `zk` feature.

**DISCLAIMER**: this package **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Tests

The package can be tested by running:

```
cargo test --release --features zk
cargo test --release --no-default-features --features zk
```

Documentation can be checked by running:

```
cargo doc --no-deps --features zk
```

## Benchmarks

The package can be benchmarked by running:

```
cargo bench --features zk
```

## License

This project is licensed under the [Mozilla Public License 2.0](../LICENSE).
