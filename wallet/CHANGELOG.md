# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `verify-session-cookie` CLI/TUI workflow for checking a disclosed session
  cookie against on-chain session data, an expected challenge, and the wallet's
  service-provider key.
- Add a release-mode `make test-wallet` target and include it in wallet CI.

### Changed

- Change default call gas pricing to use lower Lux gas prices with separate
  gas limits for issuance and license-use calls.
- Improve TUI input handling by enabling bracketed paste, filtering whitespace
  from pasted hex-like values, and ignoring key-release events.

## [0.1.0] - 2026-05-31

### Added

- Add the initial `zk-citadel-wallet` CLI/TUI implementation with contract 
  deployment, license issuance, license use, and contract queries.

<!-- ISSUES -->

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/citadel/compare/wallet-0.1.0...HEAD
[0.1.0]: https://github.com/dusk-network/citadel/releases/tag/wallet-0.1.0
