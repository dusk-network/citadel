# Citadel Contract

![Build Status](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This package contains the Citadel contract. It stores encrypted licenses and license hashes, accepted Merkle roots, public session records, and deployment metadata used by wallets and Service Providers. Request delivery is handled outside the base contract by the selected deployment or application transport.

**DISCLAIMER**: this contract **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Usage

From the repository root, the preferred BLST build and test commands are:

```sh
make contract
make test-contract
```

The equivalent direct Cargo commands must select a backend explicitly. To
generate the circuit artifacts and build the native contract with BLST:

```sh
cargo build -p license-contract --release --no-default-features \
  --features contract,bls-backend-blst
```

Then compile the wasm contract and run the VM tests:

```sh
rustup target add wasm32-unknown-unknown
cargo build -p license-contract --target wasm32-unknown-unknown --release \
  --no-default-features \
  --features contract,bls-backend-blst
cargo test -p license-contract --release --no-default-features \
  --features contract,bls-backend-blst --test license_contract
```

Use `bls-backend-dusk` instead when explicitly selecting the Dusk backend.

The build script first tries to download the Dusk trusted setup and verify its SHA-256 hash. If the download is unavailable it generates local setup material so tests can run, but those generated keys are not deployment-ready.

## License

This project is licensed under the [Mozilla Public License 2.0](../LICENSE).
