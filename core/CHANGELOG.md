# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `circuit` module

### Changed

- Refactor the crate [#98]

## [0.14.0] - 2024-08-14

### Changed

- Update `phoenix-core` dependency to "0.32"
- Update dusk-plonk to v0.20
- Update dusk-poseidon to v0.40
- Update jubjub-schnorr to v0.5
- Update poseidon-merkle to v0.7

## [0.12.0] - 2024-07-03

### Changed

- Update `jubjub-schnorr` dependency to "0.4"
- Update `phoenix-core` dependency to "0.30.0-rc"
- Use AES instead of PoseidonCipher [#109]
- Update `dusk-poseidon` dependency to "0.39" [#111]
- Update `poseidon-merkle` dependency to "0.6"

### Removed

- Remove `utils` module as it was only used for testing
- Remove `nstack` dependency [#113]

## [0.11.0] - 2024-04-10

### Changed

- Update `jubjub-schnorr` dependency to "0.2"
- Update `phoenix-core` dependency to "0.26"

## [0.10.0] - 2024-02-28

### Removed

- Remove `Shelter` code

## [0.9.0] - 2024-01-24

### Changed

- Exchanged `dusk-schnorr@0.18` dependency for `jubjub-schnorr@0.1`

## [0.8.0] - 2024-01-03

### Changed

- Update `dusk-schnorr` dependency to "0.18"
- Update `dusk-poseidon` dependency to "0.33"
- Update `poseidon-merkle` dependency to "0.5"
- Update `dusk-plonk` dependency to "0.19"
- Update `phoenix-core` dependency to "0.24"

## [0.7.0] - 2023-12-13

### Addded

- Add `phoenix-core` dependency at "0.23"

### Changed

- Update `dusk-bls12_381` dependency to "0.13"
- Update `dusk-jubjub` dependency to "0.14"
- Update `dusk-schnorr` dependency to "0.17"
- Update `dusk-poseidon` dependency to "0.32"
- Update `poseidon-merkle` dependency to "0.4"
- Update `dusk-plonk` dependency to "0.18"
- Restructure specs [#86]

### Removed

- Remove `dusk-pki` dependency

## [0.6.0] - 2023-11-22

### Added

- Add not panicking function for verifying session [#87]

### Changed

- Changed SC verification to add SP public key verification.

## [0.5.1] - 2023-11-01

### Changed

- fixed benches
- Change `attr` to `attr_data`[#80]

## [0.5.0] - 2023-10-12

### Changed

- update `dusk-bls12_381` dependency to "0.12"
- update `dusk-jubjub` dependency to "0.13"
- update `dusk-pki` dependency to "0.13"
- update `dusk-schnorr` dependency to "0.14"
- update `dusk-poseidon` dependency to "0.31"
- update `poseidon-merkle` dependency to "0.3"
- update `dusk-plonk` dependency to "0.14"
- Removed pos field from the license struct
- Refactored utils to accept external license and opening

### Added

- Add `ff` dependency

## [0.4.1] - 2023-08-09

### Added

- Add Utils implementation

## [0.4.0] - 2023-06-28

### Changed

- Updated dusk_plonk to 0.14

## [0.3.0] - 2023-06-28

### Added

- Add Shelter implementation
- Rkyv derivation for all protocol structs

### Removed

- Remove the local state module [#54]

### Changed

- Migrated Merkle tree implementation from Poseidon252 0.28 to dusk_merkle 0.2 [#41]
- Updated dusk_merkle to 0.4

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
[#98]: https://github.com/dusk-network/citadel/issues/98
[#113]: https://github.com/dusk-network/citadel/issues/113
[#111]: https://github.com/dusk-network/citadel/issues/111
[#109]: https://github.com/dusk-network/citadel/issues/109
[#87]: https://github.com/dusk-network/citadel/issues/87
[#86]: https://github.com/dusk-network/citadel/issues/86
[#80]: https://github.com/dusk-network/citadel/issues/80
[#54]: https://github.com/dusk-network/citadel/issues/54
[#41]: https://github.com/dusk-network/citadel/issues/41
[#40]: https://github.com/dusk-network/citadel/issues/40
[#34]: https://github.com/dusk-network/citadel/issues/34
[#32]: https://github.com/dusk-network/citadel/issues/32
[#30]: https://github.com/dusk-network/citadel/issues/30
[#21]: https://github.com/dusk-network/citadel/issues/21

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/citadel/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/dusk-network/citadel/compare/v0.12.0...v0.14.0
[0.12.0]: https://github.com/dusk-network/citadel/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dusk-network/citadel/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/dusk-network/citadel/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dusk-network/citadel/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/dusk-network/citadel/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dusk-network/citadel/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dusk-network/citadel/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/dusk-network/citadel/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/citadel/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/dusk-network/citadel/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/dusk-network/citadel/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/citadel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dusk-network/citadel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/citadel/releases/tag/v0.1.0
