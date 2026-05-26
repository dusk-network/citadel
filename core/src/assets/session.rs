// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use phoenix_core::PublicKey;

use crate::error::Error;
use crate::helpers::{
    DEFAULT_DEPLOYMENT, PI_COM_0, PI_COM_1_X, PI_COM_1_Y, PI_COM_2_X, PI_COM_2_Y, PI_SESSION_HASH,
    PI_SESSION_ID, PUBLIC_INPUTS_LEN, lp_commitment, session_hash,
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

        Ok(Self {
            session_hash,
            session_id,

            com_0,
            com_1,
            com_2,
        })
    }

    /// Method that verifies a [`SessionCookie`], by checking if all the
    /// openings match the commitments of the given [`Session`]
    pub fn verify(&self, sc: SessionCookie) -> Result<(), Error> {
        if sc.deployment_id != DEFAULT_DEPLOYMENT.id {
            return Err(Error::WrongDeployment);
        }

        if sc.session_id != self.session_id {
            return Err(Error::WrongSessionId);
        }

        let pk_sp_a = JubJubAffine::from(sc.pk_sp.A());
        let session_hash = session_hash(DEFAULT_DEPLOYMENT, pk_sp_a, sc.r);
        if session_hash != self.session_hash {
            return Err(Error::WrongSessionHash);
        }

        let pk_lp_a = JubJubAffine::from(sc.pk_lp.A());
        let com_0 = lp_commitment(DEFAULT_DEPLOYMENT, pk_lp_a, sc.s_0);
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

fn checked_point(x: BlsScalar, y: BlsScalar) -> Result<JubJubExtended, Error> {
    let affine = JubJubAffine::from_raw_unchecked(x, y);
    if !bool::from(affine.is_on_curve()) || !bool::from(affine.is_prime_order()) {
        return Err(Error::InvalidCommitment);
    }

    Ok(JubJubExtended::from(affine))
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
    /// Compact deployment identifier.
    pub deployment_id: BlsScalar,
    /// Public key of the SP
    pub pk_sp: PublicKey,
    /// Randomness for session_hash
    pub r: BlsScalar,
    /// The ID of the session
    pub session_id: BlsScalar,

    /// Public key of the LP
    pub pk_lp: PublicKey,
    /// Attribute data of the license
    pub attr_data: JubJubScalar,
    /// Challenge value
    pub c: JubJubScalar,

    /// Randomness for com_0
    pub s_0: BlsScalar,
    /// Randomness for com_1
    pub s_1: JubJubScalar,
    /// Randomness for com_2
    pub s_2: JubJubScalar,
}

impl Default for SessionCookie {
    fn default() -> Self {
        let pk = PublicKey::new(JubJubExtended::identity(), JubJubExtended::identity());
        Self {
            deployment_id: BlsScalar::zero(),
            pk_sp: pk,
            r: BlsScalar::zero(),
            session_id: BlsScalar::zero(),
            pk_lp: pk,
            attr_data: JubJubScalar::zero(),
            c: JubJubScalar::zero(),
            s_0: BlsScalar::zero(),
            s_1: JubJubScalar::zero(),
            s_2: JubJubScalar::zero(),
        }
    }
}
