# Citadel Contract

![Build Status](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This package contains the Citadel contract.

**DISCLAIMER**: this contract **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Usage

First, compile the license circuit (`/target/prover` and `/target/verifier`) as follows:

```
cargo b --release
```

Then, compile the license contract:

```
cargo b --target wasm32-unknown-unknown --release
```

Finally, execute the tests:

```
cargo t --release
```
