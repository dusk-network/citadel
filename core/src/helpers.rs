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

use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::BlsScalar;
use dusk_poseidon::{Domain, Hash};
use phoenix_core::{PublicKey, StealthAddress};

/// Arity of the Citadel license Merkle tree.
pub const MERKLE_ARITY: usize = 4;

/// Number of public inputs for the base license-use circuit.
pub const PUBLIC_INPUTS_LEN: usize = 8;

/// Version used by the base request, license, and session-cookie envelopes.
pub const OBJECT_VERSION_V1: BlsScalar = BlsScalar::one();

/// Field tag for `CITADEL_CONTEXT_V1`.
pub const CITADEL_CONTEXT_V1_TAG: BlsScalar = BlsScalar::zero();

/// Base-cookie mode value carried in session cookies.
pub const COOKIE_MODE_BASE: BlsScalar = BlsScalar::one();

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
        Hash::digest(
            Domain::Other,
            &[CITADEL_CONTEXT_V1_TAG, self.id, domain.tag()],
        )[0]
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
    /// `CITADEL_LICENSE_SIG_CHALLENGE_V1`
    LicenseSigChallenge,
    /// `CITADEL_SESSION_HASH_V1`
    SessionHash,
    /// `CITADEL_SESSION_AUTH_V1`
    SessionAuth,
    /// `CITADEL_SESSION_SIG_CHALLENGE_V1`
    SessionSigChallenge,
    /// `CITADEL_SESSION_ID_V1`
    SessionId,
    /// `CITADEL_LP_COMMITMENT_V1`
    LpCommitment,
    /// `CITADEL_REQUEST_ID_V1`
    RequestId,
    /// `CITADEL_ATTR_DATA_V1`
    AttrData,
    /// `CITADEL_POLICY_ID_V1`
    PolicyId,
    /// `CITADEL_POLICY_CHALLENGE_V1`
    PolicyChallenge,
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
            // Keep existing hash-domain tags stable and append new transcript
            // domains to avoid silently changing registry/session hashes.
            Self::LicenseSigChallenge => BlsScalar::from(0x0bu64),
            Self::SessionHash => BlsScalar::from(0x06u64),
            Self::SessionAuth => BlsScalar::from(0x07u64),
            Self::SessionSigChallenge => BlsScalar::from(0x0cu64),
            Self::SessionId => BlsScalar::from(0x08u64),
            Self::LpCommitment => BlsScalar::from(0x09u64),
            Self::RequestId => BlsScalar::from(0x0au64),
            Self::AttrData => BlsScalar::from(0x0du64),
            Self::PolicyId => BlsScalar::from(0x0eu64),
            Self::PolicyChallenge => BlsScalar::from(0x0fu64),
        }
    }
}

/// Computes a Citadel hash over a deployment-bound dynamic preimage.
pub fn hash_slice(domain: CitadelDomain, deployment: Deployment, tail: &[BlsScalar]) -> BlsScalar {
    Hash::digest(Domain::Other, &deployment.preimage(domain, tail))[0]
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

/// Computes a Citadel scalar hash over a deployment-bound dynamic preimage.
pub fn hash_slice_truncated(
    domain: CitadelDomain,
    deployment: Deployment,
    tail: &[BlsScalar],
) -> JubJubScalar {
    Hash::digest_truncated(Domain::Other, &deployment.preimage(domain, tail))[0]
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

/// Computes the LP signature transcript challenge scalar.
pub fn license_sig_challenge(
    deployment: Deployment,
    pk_lp_a: JubJubAffine,
    r: JubJubAffine,
    msg_lic: BlsScalar,
) -> JubJubScalar {
    hash_truncated(
        CitadelDomain::LicenseSigChallenge,
        deployment,
        [
            pk_lp_a.get_u(),
            pk_lp_a.get_v(),
            r.get_u(),
            r.get_v(),
            msg_lic,
        ],
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

/// Computes the double-key session signature transcript challenge scalar.
pub fn session_sig_challenge(
    deployment: Deployment,
    lpk: JubJubAffine,
    lpk_p: JubJubAffine,
    r: JubJubAffine,
    r_p: JubJubAffine,
    session_auth: BlsScalar,
) -> JubJubScalar {
    hash_truncated(
        CitadelDomain::SessionSigChallenge,
        deployment,
        [
            lpk.get_u(),
            lpk.get_v(),
            lpk_p.get_u(),
            lpk_p.get_v(),
            r.get_u(),
            r.get_v(),
            r_p.get_u(),
            r_p.get_v(),
            session_auth,
        ],
    )
}

/// Computes schema-scoped attribute data from a field digest and blinding.
pub fn attr_data(
    deployment: Deployment,
    schema_id: BlsScalar,
    canonical_attributes_digest: BlsScalar,
    r_attr: JubJubScalar,
) -> JubJubScalar {
    hash_truncated(
        CitadelDomain::AttrData,
        deployment,
        [
            schema_id,
            canonical_attributes_digest,
            BlsScalar::from(r_attr),
        ],
    )
}

/// Computes a policy identifier from deployment-defined policy fields.
pub fn policy_id(
    deployment: Deployment,
    service_id: BlsScalar,
    policy_version: BlsScalar,
    policy_digest: BlsScalar,
) -> BlsScalar {
    hash(
        CitadelDomain::PolicyId,
        deployment,
        [deployment.id, service_id, policy_version, policy_digest],
    )
}

/// Computes the recommended SP policy challenge scalar.
pub fn policy_challenge(
    deployment: Deployment,
    sp_id: BlsScalar,
    service_id: BlsScalar,
    policy_id: BlsScalar,
    epoch_or_event_id: BlsScalar,
    sp_nonce: BlsScalar,
) -> JubJubScalar {
    hash_truncated(
        CitadelDomain::PolicyChallenge,
        deployment,
        [
            deployment.id,
            sp_id,
            service_id,
            policy_id,
            epoch_or_event_id,
            sp_nonce,
        ],
    )
}

/// Computes a request ID from the visible version, deployment, stealth address,
/// and encrypted request payload.
pub fn request_id(
    deployment: Deployment,
    version: BlsScalar,
    rsa: &StealthAddress,
    enc: &[u8],
) -> BlsScalar {
    let mut tail = Vec::with_capacity(8 + enc.len().div_ceil(31));
    tail.push(version);
    tail.push(deployment.id);
    push_stealth_address(&mut tail, rsa);
    push_bytes_as_fields(&mut tail, enc);
    hash_slice(CitadelDomain::RequestId, deployment, &tail)
}

/// Computes the request-encryption KDF salt from visible request context.
pub fn request_encryption_salt(
    deployment: Deployment,
    version: BlsScalar,
    rsa: &StealthAddress,
    pk_lp: &PublicKey,
) -> [u8; BlsScalar::SIZE] {
    let mut tail = Vec::with_capacity(10);
    tail.push(version);
    tail.push(deployment.id);
    push_stealth_address(&mut tail, rsa);
    push_public_key(&mut tail, pk_lp);
    hash_slice(CitadelDomain::RequestKey, deployment, &tail).to_bytes()
}

/// Computes the license-encryption KDF salt from visible license context.
pub fn license_encryption_salt(
    deployment: Deployment,
    version: BlsScalar,
    lsa: &StealthAddress,
) -> [u8; BlsScalar::SIZE] {
    let mut tail = Vec::with_capacity(6);
    tail.push(version);
    tail.push(deployment.id);
    push_stealth_address(&mut tail, lsa);
    hash_slice(CitadelDomain::LicenseKey, deployment, &tail).to_bytes()
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

fn push_stealth_address(tail: &mut Vec<BlsScalar>, sa: &StealthAddress) {
    let note_pk = JubJubAffine::from(sa.note_pk().as_ref());
    let r = JubJubAffine::from(sa.R());
    tail.extend_from_slice(&[note_pk.get_u(), note_pk.get_v(), r.get_u(), r.get_v()]);
}

fn push_public_key(tail: &mut Vec<BlsScalar>, pk: &PublicKey) {
    let a = JubJubAffine::from(pk.A());
    let b = JubJubAffine::from(pk.B());
    tail.extend_from_slice(&[a.get_u(), a.get_v(), b.get_u(), b.get_v()]);
}

fn push_bytes_as_fields(tail: &mut Vec<BlsScalar>, bytes: &[u8]) {
    tail.push(BlsScalar::from(bytes.len() as u64));
    for chunk in bytes.chunks(31) {
        let mut field_bytes = [0u8; BlsScalar::SIZE];
        field_bytes[..chunk.len()].copy_from_slice(chunk);
        let field = Option::<BlsScalar>::from(BlsScalar::from_bytes(&field_bytes))
            .expect("31-byte little-endian chunks are canonical field elements");
        tail.push(field);
    }
}
