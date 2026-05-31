// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[dusk_forge::contract]
pub mod license_contract {
    use core::ops::Range;

    use alloc::vec::Vec;

    use dusk_bls12_381::BlsScalar;
    use dusk_core::abi::{block_height, feed, verify_plonk};
    use dusk_jubjub::JubJubAffine;
    use dusk_poseidon::{Domain, Hash};
    use license_contract::{
        collection::Map,
        error::Error,
        license_types::{
            ContractInfo, DeploymentMetadata, IssueLicenseArg, LicenseOpening, LicenseSession,
            LicenseSessionId, LicenseTree, MAX_LICENSE_BLOB_SIZE, PI_ROOT, PI_SESSION_ID,
            PUBLIC_INPUTS_LEN, UseLicenseArg,
        },
        verifier_data_license_circuit,
    };

    include!(concat!(env!("OUT_DIR"), "/metadata_hashes.rs"));

    const MERKLE_ARITY: usize = 4;
    const DEPTH: usize = 16; // the depth of LicenseCircuit's Merkle tree
    const ROOT_HISTORY_SIZE: usize = 8;
    const CITADEL_CONTEXT_V1_TAG: BlsScalar = BlsScalar::zero();
    const DEFAULT_DEPLOYMENT_ID: BlsScalar = BlsScalar::zero();
    const CITADEL_LICENSE_HASH_V1_TAG: u64 = 0x04;

    #[derive(Debug, Clone, PartialEq)]
    struct LicenseEntry {
        pub block_height: u64,
        pub license: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub struct LicenseContractState {
        sessions: Map<LicenseSessionId, LicenseSession>,
        licenses: Map<u64, LicenseEntry>,
        license_hashes: Map<BlsScalar, ()>,
        accepted_roots: Vec<BlsScalar>,
        tree: LicenseTree<DEPTH>,
    }

    impl LicenseContractState {
        pub const fn new() -> Self {
            Self {
                sessions: Map::new(),
                licenses: Map::new(),
                license_hashes: Map::new(),
                accepted_roots: Vec::new(),
                tree: LicenseTree::<DEPTH>::new(),
            }
        }

        #[allow(dead_code)]
        fn identifier() -> &'static [u8; 7] {
            b"license"
        }

        /// Inserts a license into the collection of licenses.
        /// Method intended to be called by the License Provider.
        pub fn issue_license(&mut self, arg: IssueLicenseArg) {
            if arg.license.is_empty() {
                panic!("License cannot be empty");
            }
            if arg.license.len() > MAX_LICENSE_BLOB_SIZE {
                panic!("License exceeds maximum size");
            }
            if self.tree.len() >= self.tree.capacity() {
                panic!("License tree is full");
            }

            let hash = Self::license_hash(arg.lpk_u, arg.lpk_v);
            if self.license_hashes.get(&hash).is_some() {
                panic!("License already issued");
            }

            let item = poseidon_merkle::Item { hash, data: () };
            let mut pos = self.tree.len();
            while self.tree.contains(pos) {
                pos += 1;
            }
            self.tree.insert(pos, item);
            self.license_hashes.insert(hash, ());
            let root = self.tree.root().hash;
            self.record_accepted_root(root);

            let block_height = block_height();
            self.licenses.insert(
                pos,
                LicenseEntry {
                    block_height,
                    license: arg.license,
                },
            );
        }

        /// Returns licenses for a given range of block-heights.
        /// Method intended to be called by the user.
        #[contract(feeds = "(u64, Vec<u8>)")]
        pub fn get_licenses(&mut self, block_heights: Range<u64>) {
            for (pos, license) in self
                .licenses
                .entries_filter(|(_, le)| block_heights.contains(&le.block_height))
                .map(|(pos, le)| (*pos, le.license.clone()))
            {
                feed((pos, license));
            }
        }

        /// Returns a license at a given license tree position.
        /// Method intended to be called by wallets and clients.
        pub fn get_license(&self, position: u64) -> Option<Vec<u8>> {
            self.licenses
                .get(&position)
                .map(|entry| entry.license.clone())
        }

        /// Returns merkle opening for a given position in the merkle tree of
        /// license hashes. Returns none if the given position slot in the tree is
        /// empty. Method intended to be called by the user.
        pub fn get_merkle_opening(&mut self, position: u64) -> Option<LicenseOpening<DEPTH>> {
            self.tree.opening(position)
        }

        /// Verifies the proof of a given license, if successful,
        /// creates a session with the corresponding session id.
        /// Method intended to be called by the user.
        pub fn use_license(&mut self, use_license_arg: UseLicenseArg) {
            if use_license_arg.public_inputs.len() != PUBLIC_INPUTS_LEN {
                panic!("Wrong public input length");
            }
            if !self.accepts_root(use_license_arg.public_inputs[PI_ROOT]) {
                panic!("Root is not accepted");
            }

            let session_id = LicenseSessionId {
                id: use_license_arg.public_inputs[PI_SESSION_ID],
            };
            if self.sessions.get(&session_id).is_some() {
                panic!("License already nullified");
            }

            Self::assert_proof(
                verifier_data_license_circuit(),
                use_license_arg.proof,
                use_license_arg.public_inputs.clone(),
            )
            .unwrap_or_else(|_| panic!("Proof verification failed"));

            // after a successful proof verification we can add a session to a
            // shared list of sessions
            let license_session = LicenseSession {
                public_inputs: use_license_arg.public_inputs,
            };
            self.sessions.insert(session_id, license_session);
        }

        /// Returns session with a given session id.
        /// Method intended to be called by the Service Provider.
        pub fn get_session(&self, session_id: LicenseSessionId) -> Option<LicenseSession> {
            self.sessions.get(&session_id).cloned()
        }

        fn assert_proof(
            verifier_data: &[u8],
            proof: Vec<u8>,
            public_inputs: Vec<BlsScalar>,
        ) -> Result<(), Error> {
            verify_plonk(verifier_data.to_vec(), proof, public_inputs)
                .then_some(())
                .ok_or(Error::ProofVerification)
        }

        fn license_hash(lpk_u: BlsScalar, lpk_v: BlsScalar) -> BlsScalar {
            let lpk = JubJubAffine::from_raw_unchecked(lpk_u, lpk_v);
            if !bool::from(lpk.is_on_curve()) || !bool::from(lpk.is_prime_order()) {
                panic!("Invalid license public key");
            }

            // The base contract is deployed with the prototype deployment ID
            // fixed to zero, matching `DEFAULT_DEPLOYMENT` in the core crate.
            let ctx = Hash::digest(
                Domain::Other,
                &[
                    CITADEL_CONTEXT_V1_TAG,
                    DEFAULT_DEPLOYMENT_ID,
                    BlsScalar::from(CITADEL_LICENSE_HASH_V1_TAG),
                ],
            )[0];

            Hash::digest(Domain::Other, &[ctx, lpk_u, lpk_v])[0]
        }

        fn record_accepted_root(&mut self, root: BlsScalar) {
            self.accepted_roots.push(root);
            while self.accepted_roots.len() > ROOT_HISTORY_SIZE {
                self.accepted_roots.remove(0);
            }
        }

        fn accepts_root(&self, root: BlsScalar) -> bool {
            self.accepted_roots.iter().any(|accepted| accepted == &root)
        }

        fn current_root(&self) -> BlsScalar {
            self.tree.root().hash
        }

        /// Deployment metadata needed by wallets and service providers.
        pub fn get_metadata(&self) -> DeploymentMetadata {
            DeploymentMetadata {
                deployment_id: BlsScalar::zero(),
                protocol_version: BlsScalar::one(),
                chain_id: BlsScalar::zero(),
                contract_id: BlsScalar::zero(),
                verifier_key_hash: VERIFIER_KEY_HASH,
                circuit_hash: CIRCUIT_HASH,
                merkle_arity: MERKLE_ARITY as u32,
                merkle_depth: DEPTH as u32,
                root_history_size: ROOT_HISTORY_SIZE as u32,
                public_inputs_len: PUBLIC_INPUTS_LEN as u32,
                max_license_blob_size: MAX_LICENSE_BLOB_SIZE as u32,
            }
        }

        /// Current Merkle root of the license tree.
        pub fn get_current_root(&self) -> BlsScalar {
            self.current_root()
        }

        /// Accepted Merkle roots under the contract root-history policy.
        pub fn get_accepted_roots(&self) -> Vec<BlsScalar> {
            self.accepted_roots.clone()
        }

        /// Named state summary for wallets, LPs, SPs, and web clients.
        pub fn get_state_info(&self) -> ContractInfo {
            ContractInfo {
                licenses: self.licenses.len() as u32,
                tree_len: self.tree.len() as u32,
                sessions: self.sessions.len() as u32,
                accepted_roots: self.accepted_roots.len() as u32,
                current_root: self.current_root(),
            }
        }

        /// Info about contract state
        pub fn get_info(&self) -> (u32, u32, u32) {
            (
                self.licenses.len() as u32,
                self.tree.len() as u32,
                self.sessions.len() as u32,
            )
        }
    }
}
