// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use phoenix_core::PublicKey;

use crate::error::Error;
use crate::helpers::{
    COOKIE_MODE_BASE, DEFAULT_DEPLOYMENT, OBJECT_VERSION_V1, PI_COM_0, PI_COM_1_X, PI_COM_1_Y,
    PI_COM_2_X, PI_COM_2_Y, PI_ROOT, PI_SESSION_HASH, PI_SESSION_ID, PUBLIC_INPUTS_LEN,
    attr_data as compute_attr_data, lp_commitment, public_key_is_valid, public_key_point_is_valid,
    session_hash,
};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

/// The struct defining a Citadel session, a set of public values shared
/// on-chain that represent the use of a service by an unknown user
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug)]
pub struct Session {
    /// The hash of the public key of the SP and a nonce
    pub session_hash: BlsScalar,
    /// The ID of the [`Session`], computed as the hash of
    /// the lpk' and the challenge
    pub session_id: BlsScalar,
    /// The hash commitment 0 from the license circuit,
    /// that commits to the public key of the LP
    pub com_0: BlsScalar,
    /// The Pedersen commitment 1 from the license circuit,
    /// that commits to the attribute data
    pub com_1: JubJubExtended,
    /// The Pedersen commitment 2 from the license circuit,
    /// that commits to the challenge
    pub com_2: JubJubExtended,
    /// Merkle root used by the accepted proof.
    pub root: BlsScalar,
}

impl Session {
    /// Method that generates a [`Session`] from a public inputs vector
    pub fn from(public_inputs: &[BlsScalar]) -> Result<Self, Error> {
        if public_inputs.len() != PUBLIC_INPUTS_LEN {
            return Err(Error::InvalidPublicInputs);
        }

        let session_id = public_inputs[PI_SESSION_ID];
        let session_hash = public_inputs[PI_SESSION_HASH];

        let com_0 = public_inputs[PI_COM_0];
        let com_1 = checked_point(public_inputs[PI_COM_1_X], public_inputs[PI_COM_1_Y])?;
        let com_2 = checked_point(public_inputs[PI_COM_2_X], public_inputs[PI_COM_2_Y])?;
        let root = public_inputs[PI_ROOT];

        Ok(Self {
            session_hash,
            session_id,

            com_0,
            com_1,
            com_2,
            root,
        })
    }

    /// Method that verifies a [`SessionCookie`], by checking if all the
    /// openings and explicit policy fields match the given [`Session`].
    pub fn verify(&self, sc: SessionCookie, policy: &SessionPolicy) -> Result<(), Error> {
        validate_public_key(&sc.pk_sp)?;
        validate_public_key(&policy.pk_sp)?;

        if sc.version != policy.cookie_version {
            return Err(Error::WrongCookieVersion);
        }

        if sc.deployment_id != policy.deployment.id {
            return Err(Error::WrongDeployment);
        }

        if sc.cookie_mode != policy.cookie_mode {
            return Err(Error::WrongCookieMode);
        }

        if sc.policy_id != policy.policy_id {
            return Err(Error::WrongPolicyId);
        }

        if sc.session_id != self.session_id {
            return Err(Error::WrongSessionId);
        }

        if sc.pk_sp != policy.pk_sp {
            return Err(Error::WrongServiceProvider);
        }

        if !policy.issuer.matches(&sc.pk_lp)? {
            return Err(Error::WrongLicenseProvider);
        }

        if sc.c != policy.challenge {
            return Err(Error::WrongChallenge);
        }

        if let Some(expected_attr_data) = policy.expected_attr_data
            && sc.attr_data != expected_attr_data
        {
            return Err(Error::WrongAttributeData);
        }

        if let Some(expected_root) = policy.expected_root
            && self.root != expected_root
        {
            return Err(Error::WrongRoot);
        }

        if policy.require_attribute_opening {
            let opening = sc.attr_opening.ok_or(Error::MissingAttributeOpening)?;
            let opened_attr_data = compute_attr_data(
                policy.deployment,
                opening.schema_id,
                opening.canonical_attributes_digest,
                opening.r_attr,
            );
            if opened_attr_data != sc.attr_data {
                return Err(Error::WrongAttributeOpening);
            }
        }

        let pk_sp_a = JubJubAffine::from(sc.pk_sp.A());
        let session_hash = session_hash(policy.deployment, pk_sp_a, sc.r_session);
        if session_hash != self.session_hash {
            return Err(Error::WrongSessionHash);
        }

        let pk_lp_a = JubJubAffine::from(sc.pk_lp.A());
        let com_0 = lp_commitment(policy.deployment, pk_lp_a, sc.s_0);
        if com_0 != self.com_0 {
            return Err(Error::WrongLicenseProviderComm);
        }

        let com_1 = (GENERATOR_EXTENDED * sc.attr_data) + (GENERATOR_NUMS_EXTENDED * sc.s_1);
        if com_1 != self.com_1 {
            return Err(Error::WrongAttributeDataComm);
        }

        let com_2 = (GENERATOR_EXTENDED * sc.c) + (GENERATOR_NUMS_EXTENDED * sc.s_2);
        if com_2 != self.com_2 {
            return Err(Error::WrongChallengeComm);
        }

        Ok(())
    }
}

/// Base-cookie attribute opening for digest-style `attr_data`.
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttributeOpening {
    /// Schema identifier used in the attribute digest.
    pub schema_id: BlsScalar,
    /// Canonical attribute-data digest defined by the schema.
    pub canonical_attributes_digest: BlsScalar,
    /// Attribute blinding randomness.
    pub r_attr: JubJubScalar,
}

/// Issuer identifier rule used by a Service Provider policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IssuerIdentifier {
    /// Full canonical LP Phoenix public key, when the profile identifies issuers by full key.
    pub full_public_key: Option<PublicKey>,
    /// LP signing point `pk_lp.A`, when the profile identifies issuers by signing point.
    pub signing_point: Option<JubJubAffine>,
}

impl IssuerIdentifier {
    /// Creates an issuer identifier that trusts a full LP public key.
    pub fn full_public_key(pk_lp: PublicKey) -> Self {
        Self {
            full_public_key: Some(pk_lp),
            signing_point: None,
        }
    }

    /// Creates an issuer identifier that trusts an LP signing point.
    pub fn signing_point(pk_lp_a: JubJubAffine) -> Self {
        Self {
            full_public_key: None,
            signing_point: Some(pk_lp_a),
        }
    }

    fn matches(self, pk_lp: &PublicKey) -> Result<bool, Error> {
        validate_public_key(pk_lp)?;

        if let Some(expected) = self.full_public_key {
            validate_public_key(&expected)?;
            if expected == *pk_lp {
                return Ok(true);
            }
        }

        if let Some(expected_a) = self.signing_point {
            validate_public_key_point(expected_a)?;
            if JubJubAffine::from(pk_lp.A()) == expected_a {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// SP policy profile selected before verifying a base session cookie.
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy {
    /// Deployment profile accepted by this policy.
    pub deployment: crate::helpers::Deployment,
    /// Cookie object version accepted by this policy.
    pub cookie_version: BlsScalar,
    /// Cookie mode accepted by this policy.
    pub cookie_mode: BlsScalar,
    /// Policy identifier that must be present in the cookie.
    pub policy_id: BlsScalar,
    /// SP service key that the session hash must bind to.
    pub pk_sp: PublicKey,
    /// Accepted issuer identifier for this policy.
    pub issuer: IssuerIdentifier,
    /// Exact challenge accepted by this policy.
    pub challenge: JubJubScalar,
    /// Optional exact attribute-data value required by this policy.
    pub expected_attr_data: Option<JubJubScalar>,
    /// Optional exact root freshness check for this policy.
    pub expected_root: Option<BlsScalar>,
    /// Whether digest-style attributes must be opened in the base cookie.
    pub require_attribute_opening: bool,
}

impl SessionPolicy {
    /// Creates a default base-cookie policy for the default deployment.
    pub fn new(
        policy_id: BlsScalar,
        pk_sp: PublicKey,
        pk_lp: PublicKey,
        challenge: JubJubScalar,
    ) -> Self {
        Self {
            deployment: DEFAULT_DEPLOYMENT,
            cookie_version: OBJECT_VERSION_V1,
            cookie_mode: COOKIE_MODE_BASE,
            policy_id,
            pk_sp,
            issuer: IssuerIdentifier::full_public_key(pk_lp),
            challenge,
            expected_attr_data: None,
            expected_root: None,
            require_attribute_opening: false,
        }
    }

    /// Accepts an issuer by signing point instead of full Phoenix public key.
    pub fn with_issuer_signing_point(mut self, pk_lp_a: JubJubAffine) -> Self {
        self.issuer = IssuerIdentifier::signing_point(pk_lp_a);
        self
    }

    /// Sets a non-default deployment for this policy.
    pub fn with_deployment(mut self, deployment: crate::helpers::Deployment) -> Self {
        self.deployment = deployment;
        self
    }

    /// Requires an exact `attr_data` value.
    pub fn with_expected_attr_data(mut self, attr_data: JubJubScalar) -> Self {
        self.expected_attr_data = Some(attr_data);
        self
    }

    /// Requires a specific Merkle root.
    pub fn with_expected_root(mut self, root: BlsScalar) -> Self {
        self.expected_root = Some(root);
        self
    }

    /// Requires a valid base-cookie attribute opening.
    pub fn require_attribute_opening(mut self) -> Self {
        self.require_attribute_opening = true;
        self
    }
}

fn checked_point(x: BlsScalar, y: BlsScalar) -> Result<JubJubExtended, Error> {
    let affine = JubJubAffine::from_raw_unchecked(x, y);
    validate_commitment_point(affine)?;

    Ok(JubJubExtended::from(affine))
}

fn validate_commitment_point(point: JubJubAffine) -> Result<(), Error> {
    if !bool::from(point.is_on_curve())
        || !bool::from(point.is_prime_order())
        || point == JubJubAffine::identity()
    {
        return Err(Error::InvalidCommitment);
    }

    Ok(())
}

fn validate_public_key(pk: &PublicKey) -> Result<(), Error> {
    public_key_is_valid(pk)
        .then_some(())
        .ok_or(Error::InvalidPublicKey)
}

fn validate_public_key_point(point: JubJubAffine) -> Result<(), Error> {
    public_key_point_is_valid(point)
        .then_some(())
        .ok_or(Error::InvalidPublicKey)
}

/// The struct defining a session cookie, a secret value
/// known only by the user and the SP, used to verify that
/// a given session is correct
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy)]
pub struct SessionCookie {
    /// Cookie object version.
    pub version: BlsScalar,
    /// Compact deployment identifier.
    pub deployment_id: BlsScalar,
    /// Cookie mode. The base cookie uses [`COOKIE_MODE_BASE`].
    pub cookie_mode: BlsScalar,
    /// Selected SP policy profile.
    pub policy_id: BlsScalar,
    /// Public key of the SP
    pub pk_sp: PublicKey,
    /// Randomness for session_hash
    pub r_session: BlsScalar,
    /// The ID of the session
    pub session_id: BlsScalar,

    /// Public key of the LP
    pub pk_lp: PublicKey,
    /// Attribute data of the license
    pub attr_data: JubJubScalar,
    /// Optional opening for digest-style attribute data.
    pub attr_opening: Option<AttributeOpening>,
    /// Challenge value
    pub c: JubJubScalar,

    /// Randomness for com_0
    pub s_0: BlsScalar,
    /// Randomness for com_1
    pub s_1: JubJubScalar,
    /// Randomness for com_2
    pub s_2: JubJubScalar,
    /// Optional profile-defined account/channel/client/nonce binding fields.
    pub binding_data: [BlsScalar; 4],
}

impl Default for SessionCookie {
    fn default() -> Self {
        let pk = PublicKey::new(JubJubExtended::identity(), JubJubExtended::identity());
        Self {
            version: OBJECT_VERSION_V1,
            deployment_id: BlsScalar::zero(),
            cookie_mode: COOKIE_MODE_BASE,
            policy_id: BlsScalar::zero(),
            pk_sp: pk,
            r_session: BlsScalar::zero(),
            session_id: BlsScalar::zero(),
            pk_lp: pk,
            attr_data: JubJubScalar::zero(),
            attr_opening: None,
            c: JubJubScalar::zero(),
            s_0: BlsScalar::zero(),
            s_1: JubJubScalar::zero(),
            s_2: JubJubScalar::zero(),
            binding_data: [BlsScalar::zero(); 4],
        }
    }
}
