# Citadel: Self-Sovereign Identities on Dusk Network

![Build Status](https://github.com/dusk-network/citadel/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-citadel-blueviolet?logo=github)](https://github.com/dusk-network/citadel)

This repository contains the implementation of Citadel, a protocol that integrates a self-sovereign identity system into the Dusk Network blockchain. An academic paper with further details about the protocol can be found [here](https://arxiv.org/pdf/2301.09378.pdf).

**DISCLAIMER**: this library **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Tests

The library can be tested by running:

```
cd citadel
cargo t --release
```

## Benchmarks

The library can be benchmarked by running:

```
cd citadel
cargo bench
```
