# Citadel Core

![Build Status](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/zk-citadel.svg)](https://crates.io/crates/zk-citadel)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This package contains the off-chain Citadel protocol API: encrypted request and license objects, session cookies, policy-aware cookie verification, deployment-bound hash/KDF helpers, Citadel Schnorr transcripts, and the license circuit behind the `zk` feature.

**DISCLAIMER**: this package **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Tests

The crate exposes `bls-backend-blst` and `bls-backend-dusk`; consumers must
enable exactly one. Repository tests use BLST:

```sh
cargo test -p zk-citadel --release --no-default-features \
  --features rkyv-impl,std,zk,bls-backend-blst
```

Documentation can be checked by running:

```sh
cargo doc -p zk-citadel --no-deps --no-default-features \
  --features rkyv-impl,std,zk,bls-backend-blst
```

## Benchmarks

The package can be benchmarked by running:

```sh
cargo bench -p zk-citadel --profile release --no-default-features \
  --features rkyv-impl,std,zk,bls-backend-blst
```

## License

This project is licensed under the [Mozilla Public License 2.0](../LICENSE).
