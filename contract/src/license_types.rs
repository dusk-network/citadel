// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bls12_381::BlsScalar;
pub const PUBLIC_INPUTS_LEN: usize = 8;
pub const PI_SESSION_ID: usize = 0;
#[allow(dead_code)]
pub const PI_ROOT: usize = 7;

#[allow(dead_code)]
pub type LicenseTree<const H: usize> = poseidon_merkle::Tree<(), H>;
#[allow(dead_code)]
pub type LicenseOpening<const H: usize> = poseidon_merkle::Opening<(), H>;

/// Issue License Argument.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct IssueLicenseArg {
    pub license: Vec<u8>,
    pub lpk_u: BlsScalar,
    pub lpk_v: BlsScalar,
}

/// Use License Argument.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct UseLicenseArg {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<BlsScalar>,
}

/// License Session Id
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct LicenseSessionId {
    pub id: BlsScalar,
}

/// License Session
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct LicenseSession {
    pub public_inputs: Vec<BlsScalar>,
}

impl LicenseSession {
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
    pub deployment_id: BlsScalar,
    pub protocol_version: BlsScalar,
    pub chain_id: BlsScalar,
    pub contract_id: BlsScalar,
    pub merkle_depth: u32,
    pub root_history_size: u32,
    pub public_inputs_len: u32,
}
