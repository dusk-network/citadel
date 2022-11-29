# Citadel: Self-Sovereign Identities on Dusk Network

This repository contains a proof-of-concept implementation of Citadel, a protocol that integrates a self-sovereign identity system into the Dusk Network blockchain. An academic paper with further details about the protocol will be provided soon.

**DISCLAIMER**: as stated above, this repository contains a proof-of-concept. As such, **it has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

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

## Running a demo

A demo where a server grants access to users that are able to provide a valid license, can be run as follows.

### Generate the SRS

A SRS is needed by both parties. This can be generated into `setup/` by running:

```
cargo r --release setup
```

### Setting up the server

Run the following command in a terminal providing a listening port:

```
cargo r --release server <port>
```

### Prove ownership of a valid license

Run the following command in a terminal providing the server's IP and port:

```
cargo r --release client <ip> <port>
```
