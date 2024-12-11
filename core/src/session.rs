// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_poseidon::{Domain, Hash};

use crate::error::Error;

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
    pub fn from(public_inputs: &[BlsScalar]) -> Self {
        let session_id = public_inputs[0];
        let session_hash = public_inputs[1];

        let com_0 = public_inputs[2];
        let com_1 = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            public_inputs[3],
            public_inputs[4],
        ));
        let com_2 = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            public_inputs[5],
            public_inputs[6],
        ));

        Self {
            session_hash,
            session_id,

            com_0,
            com_1,
            com_2,
        }
    }

    /// Method that verifies a [`SessionCookie`], by checking if all the
    /// openings match the commitments of the given [`Session`]
    pub fn verify(&self, sc: SessionCookie) -> Result<(), Error> {
        let session_hash =
            Hash::digest(Domain::Other, &[sc.pk_sp.get_u(), sc.pk_sp.get_v(), sc.r])[0];
        if session_hash != self.session_hash {
            return Err(Error::WrongSessionHash);
        }

        let com_0 = Hash::digest(Domain::Other, &[sc.pk_lp.get_u(), sc.pk_lp.get_v(), sc.s_0])[0];
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

/// The struct defining a session cookie, a secret value
/// known only by the user and the SP, used to verify that
/// a given session is correct
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Default, Debug, Clone, Copy)]
pub struct SessionCookie {
    /// Public key of the SP
    pub pk_sp: JubJubAffine,
    /// Randomness for session_hash
    pub r: BlsScalar,
    /// The ID of the session
    pub session_id: BlsScalar,

    /// Public key of the LP
    pub pk_lp: JubJubAffine,
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
