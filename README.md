<div align="center">
  <h1>Citadel: Self-Sovereign Identities on Dusk</h1>

  <p><strong>Private credentials. Public confidence. Prove, don’t reveal.</strong></p>

  <p>
    <img src="https://github.com/dusk-network/citadel/actions/workflows/dusk_ci.yml/badge.svg" alt="Build Status">
    <a href="https://crates.io/crates/zk-citadel"><img src="https://img.shields.io/crates/v/zk-citadel.svg" alt="zk-citadel on crates.io"></a>
    <a href="https://github.com/dusk-network/citadel"><img src="https://img.shields.io/badge/github-citadel-blueviolet?logo=github" alt="Repository"></a>
  </p>
</div>

This repository contains the implementation of Citadel, a protocol that integrates a self-sovereign identity system into the Dusk blockchain. Our implementation is based on the original idea from this [paper](https://arxiv.org/pdf/2301.09378).

This repository is structured as follows:

- :computer: [**Core**](core): the core Citadel protocol implementation, containing all the involved data types, the protocol workflows, and the license circuit.
- :pencil: [**License Contract**](contract): The license contract, along with all the required code to test and deploy it.
- :scroll: [**Docs**](docs): A folder where you can find the documentation concerning our Citadel specific implementation.

**DISCLAIMER**: the code in this repository **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
