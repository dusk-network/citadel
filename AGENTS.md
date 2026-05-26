# AGENTS.md

## Workspace purpose

Citadel is a Dusk-oriented self-sovereign identity prototype. A user requests an encrypted license from a License Provider (LP), proves on-chain in zero knowledge that a registered license exists and is authorized, then discloses a session cookie to a Service Provider (SP). The on-chain contract verifies proof validity and records sessions; service authorization remains SP policy.

This repository is academic/prototype code and has not had exhaustive security review. Do not treat it as production-ready without circuit, contract, dependency, and operational review.

## Primary sources of truth

- `docs/specs.md` is the normative protocol reference. Read it before changing protocol semantics.
- Important spec sections:
  - [§2 Core Concepts](docs/specs.md#2-core-concepts): parties, identifiers, secrets, data objects, lifecycle.
  - [§4 Deployment And Encoding Requirements](docs/specs.md#4-deployment-and-encoding-requirements): deployment metadata, `deployment_id`, domain separation, canonical encodings.
  - [§5 Cryptographic Building Blocks](docs/specs.md#5-cryptographic-building-blocks): Jubjub/Phoenix keys, Poseidon domains, stealth addresses, Schnorr, commitments, AEAD/KDF, Merkle tree.
  - [§6 Data Objects](docs/specs.md#6-data-objects): Request, License, Session, base cookie, selective-disclosure cookie formats.
  - [§8 Protocol Flow](docs/specs.md#8-protocol-flow): end-to-end issuance, proof, contract, and SP verification flow.
  - [§9 License Circuit](docs/specs.md#9-license-circuit): license circuit public inputs, private witnesses, and enforced statements.
  - [§10 Challenge And Reuse Semantics](docs/specs.md#10-challenge-and-reuse-semantics), [§11 Attributes And Disclosure](docs/specs.md#11-attributes-and-disclosure), [§12 Revocation, Expiration, And Replay](docs/specs.md#12-revocation-expiration-and-replay): challenge/nullifier semantics, attributes, selective disclosure, revocation, expiration, replay.
  - [§15 Conformance Checklist](docs/specs.md#15-conformance-checklist), [§16 Minimal Safe Deployment Guidance](docs/specs.md#16-minimal-safe-deployment-guidance): conformance checklist and minimal safe deployment guidance.

## Protocol invariants to preserve

- Keep the license-use public input order fixed for this circuit version:
  `session_id`, `session_hash`, `com_0`, `com_1.x`, `com_1.y`, `com_2.x`, `com_2.y`, `root`.
- `deployment_id` is carried by protocol objects/cookies, but is not a circuit public input in the base circuit. It is a deployment constant used to derive domain-separated hash contexts.
- All externally supplied points, scalars, encodings, signatures, Merkle openings, cookies, and public inputs must be canonically validated before cryptographic use.
- `session_id = H(lpk_p, c)` is the on-chain nullifier. Duplicate `session_id` rejection only prevents a second accepted on-chain session for the same hidden license and accepted challenge; it does not prevent cookie replay.
- `session_hash` binds the public session to `pk_sp.A` and fresh `r_session`.
- `com_0` commits to `pk_lp.A`; `com_1` commits to `attr_data`; `com_2` commits to challenge `c`.
- The circuit must not receive `lsk` directly. It verifies a double-key Schnorr statement proving the same hidden scalar opens `lpk = lsk * G` and `lpk_p = lsk * G'`.
- The base circuit does not enforce SP trust or authorization policy. SPs must check accepted issuer keys, attributes, exact challenge policy, root freshness, expiration, revocation, replay/binding, and rate limits.
- Base session cookies are bearer credentials. Treat them as sensitive and define replay/binding semantics in the SP profile.
- Request-based issuance is the preferred privacy mode. Direct issuance is explicitly lower privacy because the LP can know the user's static key or application identity.
- Do not silently mix protocol/circuit versions, domain constants, public input order, generator sets, Merkle parameters, verifier keys, or signature/hash preimages.

## Code organization

- Root `Cargo.toml`: Rust workspace with members `core` and `contract`.
- `docs/specs.md`: protocol specification and security/conformance reference.
- `core/` (`zk-citadel` crate): off-chain protocol API, data objects, helpers, and ZK circuit code.
  - `core/src/assets/`: protocol objects exchanged by participants:
    - `request.rs`: encrypted user-to-LP license requests.
    - `license.rs`: LP-issued encrypted licenses and direct/request issuance paths.
    - `session.rs`: on-chain session parsing and base cookie verification.
  - `core/src/helpers.rs`: Merkle arity, public input indices, deployment metadata, domain tags, and canonical hash/KDF helpers.
  - `core/src/zk/`: `LicenseCircuit` and reusable `use_license` gadgets. This is behind the `zk` feature.
  - `core/tests/citadel.rs`: end-to-end protocol test for request issuance, direct issuance, proving, verification, and cookie/session checks.
  - `core/benches/license_circuit.rs`: circuit benchmark.
- `contract/` (`license-contract` crate): Dusk contract for license registry and session registry.
  - `contract/src/state.rs`: contract state and methods: `issue_license`, `get_licenses`, `get_merkle_opening`, `use_license`, `get_session`, `get_metadata`, `get_info`.
  - `contract/src/license_types.rs`: rkyv-serializable call/return types and public-input constants.
  - `contract/src/collection.rs`: simple in-memory map abstraction for contract state.
  - `contract/build.rs`: downloads or generates PlonK setup material and writes `target/prover` and `target/verifier` used by tests and contract build.
  - `contract/tests/license_contract.rs`: VM integration tests for issuing licenses, fetching Merkle openings, using licenses, and fetching sessions.

## Development commands

Use the Rust toolchain from `rust-toolchain.toml` (`1.94`, edition 2024). `Cargo.lock` is intentionally ignored in this workspace.

From the repository root:

```sh
cargo build --release
rustup target add wasm32-unknown-unknown
cd contract && cargo build --target wasm32-unknown-unknown --release
cd ..
cargo test --release --features zk
cargo test --release --no-default-features --features zk
cargo bench --no-run --features zk
```

Core-only checks:

```sh
cd core
cargo test --release --features zk
cargo test --release --no-default-features --features zk
cargo bench --features zk
```

Contract flow:

```sh
cargo build --release                     # creates target/prover and target/verifier
cd contract
cargo build --target wasm32-unknown-unknown --release
cargo test --release --features zk
```

Notes:
- Contract tests include `target/prover`, `target/verifier`, and the wasm artifact, so run the contract flow before `contract` VM tests.
- `contract/build.rs` first tries to download the trusted setup from `https://nodes.dusk.network/trusted-setup` and verify its SHA-256 hash. If download fails it generates local setup material and warns that this is unsafe for real use. Do not present fallback-generated keys as deployment-ready.
- `target/` artifacts are generated and ignored. Do not commit proving/verifier keys or wasm build outputs unless the repository policy changes.

## Change guidance for agents

- Prefer small, spec-aligned changes. If a change affects protocol semantics, update `docs/specs.md` and related tests in the same patch.
- Keep constants in `core/src/helpers.rs`, `core/src/zk/*`, `contract/src/license_types.rs`, and `contract/src/state.rs` synchronized, especially public input length/order, Merkle depth/arity, root history size, deployment metadata, and domain derivations.
- The current contract uses `DEPTH = 16`, `ROOT_HISTORY_SIZE = 8`, `PUBLIC_INPUTS_LEN = 8`, and default deployment metadata with zero `deployment_id`, zero `chain_id`, zero `contract_id`, and protocol version one.
- When touching circuit shape, public inputs, domain preimages, Merkle parameters, or proof verification, regenerate/check `target/prover` and `target/verifier`, rebuild the wasm contract, and run the VM tests.
- When touching cookies or SP verification, remember that the generic `Session::verify` only checks openings; issuer trust, attribute semantics, challenge acceptance, replay, expiration, and revocation are profile-level SP checks.
- Preserve `#![deny(missing_docs)]` expectations in `core` and keep public APIs documented.
- Preserve the MPL-2.0 license header style used by existing Rust files when adding new Rust source files.
- Prefer structured serialization/deserialization APIs already in use (`rkyv`, `dusk-bytes`, canonical `from_bytes`/point checks) over hand-rolled byte parsing. When byte parsing is unavoidable, validate lengths and canonical encodings explicitly.
- Treat `DEFAULT_DEPLOYMENT` as prototype/default plumbing, not as a license to erase deployment-profile checks in new externally facing code.
- Avoid adding unaudited cryptographic shortcuts, ad hoc serialization, non-domain-separated hashes, reused randomness, or unchecked point/scalar decoding.
