# Citadel: Self-Sovereign Identities on Dusk

![Build Status](https://github.com/dusk-network/citadel/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This repository contains the implementation of Citadel, a protocol that integrates a self-sovereign identity system into the Dusk blockchain. A document with all the details about the protocol can be found [here](https://github.com/dusk-network/citadel/tree/main/docs/specs.pdf).

It also contains Shelter, a version of Citadel meant for non-Blockchain use cases. Documentation on this version will be provided soon.

**DISCLAIMER**: this library **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Tests

The library can be tested by running:

```
cargo t --release
```

## Benchmarks

The library can be benchmarked by running:

```
cargo bench
```
