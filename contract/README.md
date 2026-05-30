# Citadel Contract

![Build Status](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This package contains the Citadel contract. It stores encrypted requests for LP discovery, encrypted licenses and license hashes, accepted Merkle roots, public session records, and deployment metadata used by wallets and Service Providers.

**DISCLAIMER**: this contract **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Usage

First, compile the license circuit (`/target/prover` and `/target/verifier`) as follows:

```
cargo build --release
```

Then, compile the license contract:

```
cargo build --target wasm32-unknown-unknown --release
```

Finally, execute the tests:

```
cargo test --release --test license_contract
```

The build script first tries to download the Dusk trusted setup and verify its SHA-256 hash. If the download is unavailable it generates local setup material so tests can run, but those generated keys are not deployment-ready.

## License

This project is licensed under the [Mozilla Public License 2.0](../LICENSE).
