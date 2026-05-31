# Citadel Wallet

[![crates.io](https://img.shields.io/crates/v/zk-citadel-wallet.svg)](https://crates.io/crates/zk-citadel-wallet)
[![docs.rs](https://docs.rs/zk-citadel-wallet/badge.svg)](https://docs.rs/zk-citadel-wallet)
[![CI](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg)](https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml)
[![License](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/dusk-network/citadel/blob/main/LICENSE)

`zk-citadel-wallet` is a host-side CLI/TUI for the Citadel protocol. It
deploys the license contract, issues encrypted licenses, creates request-based
issuance blobs, proves license use, and stores accepted session cookies.

The wallet intentionally reuses the encrypted `rusk-wallet` wallet file instead
of introducing a separate Citadel key store. Dusk account derivation, signing,
deployment, and write calls go through `rusk-wallet`; read-only contract queries
are performed directly over RUES.

This crate is prototype tooling. The underlying Citadel protocol and contract
are not production-ready without further circuit, contract, dependency, and
operational review.

## Usage

To use the interactive wallet, simply execute:

```sh
cargo run --release
```

Also, you can install the last released version from `crates.io`:

```sh
cargo install zk-citadel-wallet
```

## Requirements

- Create or restore the Dusk wallet with `rusk-wallet`, then pass its directory
  with `--wallet-dir` or use the default `~/.dusk/rusk-wallet`.
- Point `--state`, `--prover`, and `--archiver` at the intended Rusk services.
  `--prover` and `--archiver` default to `--state`.
- Build matching Citadel contract artifacts before `deploy` or `use-license`.
  From the Citadel repository root, run `make contract`.

Artifact defaults are relative to the current working directory:

- `deploy` reads `target/wasm32-unknown-unknown/release/license_contract.wasm`;
  override with `--code` or `CITADEL_CONTRACT_WASM`.
- `use-license` reads `target/prover`; override with `CITADEL_PROVER_PATH`.

Passwords can be provided with `--password` or `CITADEL_WALLET_PASSWORD`.
Without either, the CLI prompts when it needs to open the wallet.

Local Citadel state is stored next to the Rusk wallet in `citadel_wallet.dat`
and `citadel_session_cookies.dat`. Both files are encrypted with AES-GCM using
a Citadel-specific key derived from the password-protected wallet material.
Session cookies are bearer credentials; handle them as sensitive.

## Non-interactive API

Deploy a compiled contract and store it as active:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  --state http://127.0.0.1:8080 \
  deploy
```

Store an already deployed contract as active:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  set-contract \
  --contract-id <64_HEX_CHARS>
```

Print this wallet's License Provider address:

```sh
zk-citadel-wallet --wallet-dir ~/.dusk/rusk-wallet issuer
```

Create an encrypted request blob for request-based issuance:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  receive-license \
  --issuer-address <LP_SHIELDED_ADDRESS>
```

Issue a license from an encrypted request:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  --state http://127.0.0.1:8080 \
  issue-request-license \
  --request-blob <REQUEST_BLOB_HEX> \
  --attributes "tier=academic"
```

Issue a license directly to a shielded address:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  --state http://127.0.0.1:8080 \
  issue-license \
  --attributes "tier=academic" \
  --shielded-address <RECIPIENT_SHIELDED_ADDRESS>
```

List licenses owned by profile 0:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  --state http://127.0.0.1:8080 \
  list-licenses
```

Use one owned license by tree position:

```sh
zk-citadel-wallet \
  --wallet-dir ~/.dusk/rusk-wallet \
  --state http://127.0.0.1:8080 \
  use-license \
  --position <POSITION_FROM_LIST_LICENSES> \
  --service-provider <SP_SHIELDED_ADDRESS> \
  --challenge "event-2026-05"
```

`use-license` prints the accepted `session_id`, prints a hex-encoded base
`session_cookie`, and saves that cookie to the encrypted local cookie store.

The default call gas limits are conservative caps for the prototype wallet:
`issue-request-license` and `issue-license` default to `300000000`, while
`use-license` defaults to `50000000`. Contract calls default to a gas price of
`1` Lux, while deployment keeps the Dusk deployment minimum of `2000` Lux. At
the default call gas price, failed `issue-license` and `use-license` execution
is capped at roughly 0.3 DUSK and 0.05 DUSK respectively. Pass `--gas-limit`
or `--gas-price` to tune the cap or inclusion price for a specific node or
contract build.

Inspect saved cookies, accepted sessions, and contract state:

```sh
zk-citadel-wallet --wallet-dir ~/.dusk/rusk-wallet list-cookies
zk-citadel-wallet --wallet-dir ~/.dusk/rusk-wallet get-session --session-id <SESSION_ID_HEX>
zk-citadel-wallet --wallet-dir ~/.dusk/rusk-wallet metadata
zk-citadel-wallet --wallet-dir ~/.dusk/rusk-wallet roots
zk-citadel-wallet --wallet-dir ~/.dusk/rusk-wallet info
```

## License

This project is licensed under the [Mozilla Public License 2.0](https://github.com/dusk-network/citadel/blob/main/LICENSE).
