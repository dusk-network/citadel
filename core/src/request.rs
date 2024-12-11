// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{dhke, GENERATOR_EXTENDED};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use phoenix_core::{
    aes::{encrypt, ENCRYPTION_EXTRA_SIZE},
    Error, PublicKey, SecretKey, StealthAddress,
};

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

pub(crate) const REQ_PLAINTEXT_SIZE: usize = StealthAddress::SIZE + JubJubAffine::SIZE;
const REQ_ENCRYPTION_SIZE: usize = REQ_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

/// The struct defining a Citadel request, a set of information that
/// a user sends to the network to inform a LP that the user is
/// requesting a license from them
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug)]
pub struct Request {
    /// The stealth address for the request
    pub rsa: StealthAddress,
    /// The encryption of the license stealth address and the k_lic symmetric key
    pub enc: [u8; REQ_ENCRYPTION_SIZE],
}

impl Request {
    /// Method to create a new [`Request`] given ther user keys and the public key of LP
    pub fn new<R: RngCore + CryptoRng>(
        sk_user: &SecretKey,
        pk_user: &PublicKey,
        pk_lp: &PublicKey,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let lsa = pk_user.gen_stealth_address(&JubJubScalar::random(&mut *rng));
        let lsk = sk_user.gen_note_sk(&lsa);
        let k_lic = JubJubAffine::from(
            GENERATOR_EXTENDED
                * Hash::digest_truncated(Domain::Other, &[(*lsk.as_ref()).into()])[0],
        );

        let r_dh = JubJubScalar::random(&mut *rng);
        let rsa = pk_lp.gen_stealth_address(&r_dh);
        let k_dh = dhke(&r_dh, pk_lp.A());

        let mut plaintext = lsa.to_bytes().to_vec();
        plaintext.append(&mut k_lic.to_bytes().to_vec());

        let enc = encrypt(&k_dh, &plaintext, rng)?;

        Ok(Self { rsa, enc })
    }
}
