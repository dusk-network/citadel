# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Migrated Merkle tree implementation from Poseidon252 0.28 to dusk_merkle 0.2 [#41]

## [0.2.0] - 2023-05-17

### Added

- Add the specification for Citadel [#21]
- Add the implementation of the new structs [#30]
- Add the implementation of the new license methods [#32]
- Add the state module [#40]

### Changed

- Allow the user to craft the challenge [#34]

## [0.1.0] - 2023-01-24

### Added

- Add the structs and functions needed for the Citadel protocol
- Add the gadget to prove ownership of licenses
- Add the tests for Citadel
- Add workflows for the Github Actions

<!-- ISSUES -->
[#40]: https://github.com/dusk-network/citadel/issues/40
[#34]: https://github.com/dusk-network/citadel/issues/34
[#32]: https://github.com/dusk-network/citadel/issues/32
[#30]: https://github.com/dusk-network/citadel/issues/30
[#21]: https://github.com/dusk-network/citadel/issues/21

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/citadel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dusk-network/citadel/releases/tag/v0.2.0
[0.1.0]: https://github.com/dusk-network/citadel/releases/tag/v0.1.0