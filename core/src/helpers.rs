// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Shared constants and helper functions for Citadel protocol computations.
//!
//! The helpers in this module are the non-structural protocol glue used by the
//! off-chain API and circuit gadgets: public-input ordering, Merkle arity,
//! deployment context derivation, and domain-separated hashes/KDFs.

use std::vec::Vec;

use dusk_jubjub::{JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::BlsScalar;
use dusk_poseidon::{Domain, Hash};

/// Arity of the Citadel license Merkle tree.
pub const MERKLE_ARITY: usize = 4;

/// Number of public inputs for the base license-use circuit.
pub const PUBLIC_INPUTS_LEN: usize = 8;

/// Public input index for `session_id`.
pub const PI_SESSION_ID: usize = 0;
/// Public input index for `session_hash`.
pub const PI_SESSION_HASH: usize = 1;
/// Public input index for `com_0`.
pub const PI_COM_0: usize = 2;
/// Public input index for `com_1.x`.
pub const PI_COM_1_X: usize = 3;
/// Public input index for `com_1.y`.
pub const PI_COM_1_Y: usize = 4;
/// Public input index for `com_2.x`.
pub const PI_COM_2_X: usize = 5;
/// Public input index for `com_2.y`.
pub const PI_COM_2_Y: usize = 6;
/// Public input index for `root`.
pub const PI_ROOT: usize = 7;

/// Deployment constants bound into all Citadel protocol hashes.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Deployment {
    /// Compact deployment identifier used in protocol objects and hash contexts.
    pub id: BlsScalar,
    /// Protocol version.
    pub version: BlsScalar,
    /// Chain or deployment identifier.
    pub chain_id: BlsScalar,
    /// Contract identifier represented as a field element for circuit hashes.
    pub contract_id: BlsScalar,
}

impl Deployment {
    /// Creates a new deployment descriptor.
    pub const fn new(
        id: BlsScalar,
        version: BlsScalar,
        chain_id: BlsScalar,
        contract_id: BlsScalar,
    ) -> Self {
        Self {
            id,
            version,
            chain_id,
            contract_id,
        }
    }

    /// Computes the compact deployment/domain context scalar.
    pub fn context(&self, domain: CitadelDomain) -> BlsScalar {
        Hash::digest(Domain::Other, &[BlsScalar::zero(), self.id, domain.tag()])[0]
    }

    fn preimage(&self, domain: CitadelDomain, tail: &[BlsScalar]) -> Vec<BlsScalar> {
        let mut input = Vec::with_capacity(tail.len() + 1);
        input.push(self.context(domain));
        input.extend_from_slice(tail);
        input
    }
}

impl Default for Deployment {
    fn default() -> Self {
        Self {
            id: BlsScalar::zero(),
            version: BlsScalar::one(),
            chain_id: BlsScalar::zero(),
            contract_id: BlsScalar::zero(),
        }
    }
}

/// The default academic/prototype deployment used by the existing API.
pub const DEFAULT_DEPLOYMENT: Deployment = Deployment::new(
    BlsScalar::zero(),
    BlsScalar::one(),
    BlsScalar::zero(),
    BlsScalar::zero(),
);

/// Citadel-specific Poseidon domain tags.
#[derive(Debug, Clone, Copy)]
pub enum CitadelDomain {
    /// `CITADEL_STEALTH_DERIVE_V1`
    StealthDerive,
    /// `CITADEL_REQUEST_KEY_V1`
    RequestKey,
    /// `CITADEL_LICENSE_KEY_V1`
    LicenseKey,
    /// `CITADEL_LICENSE_HASH_V1`
    LicenseHash,
    /// `CITADEL_LICENSE_SIG_MSG_V1`
    LicenseSigMsg,
    /// `CITADEL_SESSION_HASH_V1`
    SessionHash,
    /// `CITADEL_SESSION_AUTH_V1`
    SessionAuth,
    /// `CITADEL_SESSION_ID_V1`
    SessionId,
    /// `CITADEL_LP_COMMITMENT_V1`
    LpCommitment,
    /// `CITADEL_REQUEST_ID_V1`
    RequestId,
}

impl CitadelDomain {
    /// Field tag used as the first element of each Poseidon preimage.
    pub fn tag(self) -> BlsScalar {
        match self {
            Self::StealthDerive => BlsScalar::from(0x01u64),
            Self::RequestKey => BlsScalar::from(0x02u64),
            Self::LicenseKey => BlsScalar::from(0x03u64),
            Self::LicenseHash => BlsScalar::from(0x04u64),
            Self::LicenseSigMsg => BlsScalar::from(0x05u64),
            Self::SessionHash => BlsScalar::from(0x06u64),
            Self::SessionAuth => BlsScalar::from(0x07u64),
            Self::SessionId => BlsScalar::from(0x08u64),
            Self::LpCommitment => BlsScalar::from(0x09u64),
            Self::RequestId => BlsScalar::from(0x0au64),
        }
    }
}

/// Computes a Citadel hash over a deployment-bound preimage.
pub fn hash<const N: usize>(
    domain: CitadelDomain,
    deployment: Deployment,
    tail: [BlsScalar; N],
) -> BlsScalar {
    Hash::digest(Domain::Other, &deployment.preimage(domain, &tail))[0]
}

/// Computes a Citadel hash truncated into the Jubjub scalar field.
pub fn hash_truncated<const N: usize>(
    domain: CitadelDomain,
    deployment: Deployment,
    tail: [BlsScalar; N],
) -> JubJubScalar {
    Hash::digest_truncated(Domain::Other, &deployment.preimage(domain, &tail))[0]
}

/// Computes the license leaf hash from the visible license public key.
pub fn license_hash(deployment: Deployment, lpk: JubJubAffine) -> BlsScalar {
    hash(
        CitadelDomain::LicenseHash,
        deployment,
        [lpk.get_u(), lpk.get_v()],
    )
}

/// Computes the LP license signature message.
pub fn license_sig_message(
    deployment: Deployment,
    lpk: JubJubAffine,
    attr_data: JubJubScalar,
) -> BlsScalar {
    hash(
        CitadelDomain::LicenseSigMsg,
        deployment,
        [lpk.get_u(), lpk.get_v(), BlsScalar::from(attr_data)],
    )
}

/// Computes a session hash bound to the SP service point.
pub fn session_hash(
    deployment: Deployment,
    pk_sp_a: JubJubAffine,
    r_session: BlsScalar,
) -> BlsScalar {
    hash(
        CitadelDomain::SessionHash,
        deployment,
        [pk_sp_a.get_u(), pk_sp_a.get_v(), r_session],
    )
}

/// Computes a session ID from the secondary license public key and challenge.
pub fn session_id(deployment: Deployment, lpk_p: JubJubAffine, c: JubJubScalar) -> BlsScalar {
    hash(
        CitadelDomain::SessionId,
        deployment,
        [lpk_p.get_u(), lpk_p.get_v(), BlsScalar::from(c)],
    )
}

/// Computes the LP public-key commitment.
pub fn lp_commitment(deployment: Deployment, pk_lp_a: JubJubAffine, s_0: BlsScalar) -> BlsScalar {
    hash(
        CitadelDomain::LpCommitment,
        deployment,
        [pk_lp_a.get_u(), pk_lp_a.get_v(), s_0],
    )
}

/// Computes the session authorization message for the double-key signature.
pub fn session_auth(
    deployment: Deployment,
    session_id: BlsScalar,
    session_hash: BlsScalar,
    com_0: BlsScalar,
    com_1: JubJubAffine,
    com_2: JubJubAffine,
    root: BlsScalar,
) -> BlsScalar {
    hash(
        CitadelDomain::SessionAuth,
        deployment,
        [
            session_id,
            session_hash,
            com_0,
            com_1.get_u(),
            com_1.get_v(),
            com_2.get_u(),
            com_2.get_v(),
            root,
        ],
    )
}

/// Computes the domain-separated license encryption key material.
pub fn license_key(
    deployment: Deployment,
    lsk: JubJubScalar,
    lpk: JubJubAffine,
    r: JubJubAffine,
) -> JubJubAffine {
    use dusk_jubjub::GENERATOR_EXTENDED;

    JubJubAffine::from(
        GENERATOR_EXTENDED
            * hash_truncated(
                CitadelDomain::LicenseKey,
                deployment,
                [
                    BlsScalar::from(lsk),
                    lpk.get_u(),
                    lpk.get_v(),
                    r.get_u(),
                    r.get_v(),
                ],
            ),
    )
}
