<div align="center">
  <h1>Citadel: Self-Sovereign Identities on Dusk</h1>

  <p><strong>Private credentials. Public confidence. Prove, don’t reveal.</strong></p>

  <p>
    <img src="https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg" alt="Build Status">
    <a href="https://crates.io/crates/zk-citadel"><img src="https://img.shields.io/crates/v/zk-citadel.svg?label=zk-citadel" alt="zk-citadel on crates.io"></a>
    <a href="https://crates.io/crates/zk-citadel-wallet"><img src="https://img.shields.io/crates/v/zk-citadel-wallet.svg?label=zk-citadel-wallet" alt="zk-citadel-wallet on crates.io"></a>
    <a href="https://github.com/dusk-network/citadel"><img src="https://img.shields.io/badge/github-citadel-blueviolet?logo=github" alt="Repository"></a>
  </p>
</div>

This repository contains the implementation of Citadel, a Dusk-oriented self-sovereign identity prototype. A user requests an encrypted license from a License Provider, proves on-chain in zero knowledge that a registered license exists, and discloses a session cookie to a Service Provider that applies its own policy.

The protocol reference is [`docs/specs.md`](docs/specs.md). The threat model and residual risks are documented in [`docs/security.md`](docs/security.md). Our implementation is based on the original idea from this [paper](https://arxiv.org/pdf/2301.09378).

> **⚠️ DISCLAIMER:** the code in this repository **has not gone through an exhaustive security review**, so it is not intended to be used in a production environment.

This repository is structured as follows:

- :computer: [**Core**](core): protocol objects, request/license/session workflows, domain-separated helpers, Citadel Schnorr transcripts, and the license circuit.
- :pencil: [**License Contract**](contract): license registry, Merkle root history, proof verification, session registry, and deployment metadata.
- :briefcase: [**Wallet**](wallet): host-side CLI/TUI for Citadel wallet, deployment, and contract interactions.
- :scroll: [**Docs**](docs): the normative protocol specification and threat model for this prototype.

## Getting Started

Use the Rust toolchain from [`rust-toolchain.toml`](rust-toolchain.toml). The root
[`Makefile`](Makefile) is the preferred entry point for local and CI workflows.

All build, test, benchmark, and wallet targets compile in release mode. The ZK
targets keep Cargo default features enabled while adding `zk`, so
`dusk-plonk/std` remains enabled and PlonK can use its parallel `std`/rayon
path.

### Build Contract

```sh
make contract
```

Builds the release contract artifacts, ensures the `wasm32-unknown-unknown`
target is installed, and compiles the contract wasm as described in
[`contract/README.md`](contract/README.md).

### Test Contract

```sh
make test-contract
```

Builds contract artifacts first, then runs the contract VM tests.

### Test Core

```sh
make test-core
```

Runs the core test suite in release mode with `zk` enabled.

### Benchmarks

```sh
make bench
```

Runs the core benchmarks with `zk` enabled. To compile benchmarks without
running them, use:

```sh
make bench BENCH_ARGS=--no-run
```

### Run Wallet

```sh
make run-wallet
```

Builds and runs the Citadel wallet. Pass CLI arguments with `WALLET_ARGS`:

```sh
make run-wallet WALLET_ARGS="--help"
```

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
