<div align="center">
  <h1>Citadel: Self-Sovereign Identities on Dusk</h1>

  <p><strong>Private credentials. Public confidence. Prove, don’t reveal.</strong></p>

  <p>
    <img src="https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg" alt="Build Status">
    <a href="https://crates.io/crates/zk-citadel"><img src="https://img.shields.io/crates/v/zk-citadel.svg" alt="zk-citadel on crates.io"></a>
    <a href="https://github.com/dusk-network/citadel"><img src="https://img.shields.io/badge/github-citadel-blueviolet?logo=github" alt="Repository"></a>
  </p>
</div>

This repository contains the implementation of Citadel, a Dusk-oriented self-sovereign identity prototype. A user requests an encrypted license from a License Provider, proves on-chain in zero knowledge that a registered license exists, and discloses a session cookie to a Service Provider that applies its own policy.

The protocol reference is [`docs/specs.md`](docs/specs.md). The threat model and residual risks are documented in [`docs/security.md`](docs/security.md). Our implementation is based on the original idea from this [paper](https://arxiv.org/pdf/2301.09378).

This repository is structured as follows:

- :computer: [**Core**](core): protocol objects, request/license/session workflows, domain-separated helpers, Citadel Schnorr transcripts, and the license circuit.
- :pencil: [**License Contract**](contract): license registry, Merkle root history, proof verification, session registry, and deployment metadata.
- :scroll: [**Docs**](docs): the normative protocol specification and threat model for this prototype.

## Development

Use the Rust toolchain from [`rust-toolchain.toml`](rust-toolchain.toml). From the repository root:

```sh
cargo build --release
rustup target add wasm32-unknown-unknown
cd contract && cargo build --target wasm32-unknown-unknown --release
cd ..
cargo test --release --features zk
cargo doc --workspace --no-deps --features zk
```

Contract VM tests need the generated `target/prover`, `target/verifier`, and wasm artifact:

```sh
cd contract
cargo test --release --test license_contract
```

**DISCLAIMER**: the code in this repository **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
