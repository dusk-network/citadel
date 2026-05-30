// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bls12_381::BlsScalar;

/// Maximum encrypted license blob size accepted by the contract.
pub const MAX_LICENSE_BLOB_SIZE: usize = 4096;
/// Number of public inputs expected by the license-use verifier.
pub const PUBLIC_INPUTS_LEN: usize = 8;
/// Public input index for the session nullifier.
pub const PI_SESSION_ID: usize = 0;
/// Public input index for the Merkle root.
#[allow(dead_code)]
pub const PI_ROOT: usize = 7;

/// Contract license tree type for the configured Merkle height.
#[allow(dead_code)]
pub type LicenseTree<const H: usize> = poseidon_merkle::Tree<(), H>;
/// Contract Merkle opening type for the configured Merkle height.
#[allow(dead_code)]
pub type LicenseOpening<const H: usize> = poseidon_merkle::Opening<(), H>;

/// Issue License Argument.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct IssueLicenseArg {
    /// Versioned encrypted license blob.
    pub license: Vec<u8>,
    /// U-coordinate of the license public key committed into the Merkle tree.
    pub lpk_u: BlsScalar,
    /// V-coordinate of the license public key committed into the Merkle tree.
    pub lpk_v: BlsScalar,
}

/// Use License Argument.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct UseLicenseArg {
    /// Serialized PlonK proof for the license-use circuit.
    pub proof: Vec<u8>,
    /// Public inputs in the fixed circuit order.
    pub public_inputs: Vec<BlsScalar>,
}

/// License Session Id
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct LicenseSessionId {
    /// Public nullifier derived from the hidden secondary license key and challenge.
    pub id: BlsScalar,
}

/// License Session
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct LicenseSession {
    /// License-use circuit public inputs stored for SP lookup.
    pub public_inputs: Vec<BlsScalar>,
}

impl LicenseSession {
    /// Returns the session ID if the stored public inputs have the expected shape.
    pub fn session_id(&self) -> Option<LicenseSessionId> {
        if self.public_inputs.len() != PUBLIC_INPUTS_LEN {
            return None;
        }

        LicenseSessionId {
            id: self.public_inputs[PI_SESSION_ID],
        }
        .into()
    }
}

/// Public deployment metadata exposed by the contract.
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct DeploymentMetadata {
    /// Compact deployment identifier used by protocol objects.
    pub deployment_id: BlsScalar,
    /// Protocol version expected by this contract.
    pub protocol_version: BlsScalar,
    /// Chain identifier encoded into the deployment profile.
    pub chain_id: BlsScalar,
    /// Contract identifier encoded into the deployment profile.
    pub contract_id: BlsScalar,
    /// Hash of the verifier key included by this build.
    pub verifier_key_hash: BlsScalar,
    /// Hash identifying the circuit shape included by this build.
    pub circuit_hash: BlsScalar,
    /// Merkle tree arity.
    pub merkle_arity: u32,
    /// Merkle tree depth.
    pub merkle_depth: u32,
    /// Number of accepted roots retained by the contract.
    pub root_history_size: u32,
    /// Number of public inputs required by the verifier.
    pub public_inputs_len: u32,
    /// Maximum encrypted license blob size.
    pub max_license_blob_size: u32,
}

/// Public contract state summary exposed for clients.
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct ContractInfo {
    /// Number of stored license blobs.
    pub licenses: u32,
    /// Number of populated license-tree leaves.
    pub tree_len: u32,
    /// Number of accepted sessions.
    pub sessions: u32,
    /// Number of accepted Merkle roots currently retained.
    pub accepted_roots: u32,
    /// Current license-tree root.
    pub current_root: BlsScalar,
}
