// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::dhke;
use ff::Field;
use phoenix_core::{
    aes::{encrypt, ENCRYPTION_EXTRA_SIZE},
    Error, PublicKey, StealthAddress,
};

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

pub(crate) const REQ_PLAINTEXT_SIZE: usize = StealthAddress::SIZE + JubJubAffine::SIZE;
const REQ_ENCRYPTION_SIZE: usize = REQ_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug)]
pub struct Request {
    pub rsa: StealthAddress,            // request stealth address
    pub enc: [u8; REQ_ENCRYPTION_SIZE], // encryption of the license stealth address and k_lic
}

impl Request {
    pub fn new<R: RngCore + CryptoRng>(
        pk_lp: &PublicKey,
        lsa: &StealthAddress,
        k_lic: &JubJubAffine,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let r_dh = JubJubScalar::random(&mut *rng);
        let rsa = pk_lp.gen_stealth_address(&r_dh);
        let k_dh = dhke(&r_dh, pk_lp.A());

        let mut plaintext = lsa.to_bytes().to_vec();
        plaintext.append(&mut k_lic.to_bytes().to_vec());

        let enc = encrypt(&k_dh, &plaintext, rng)?;

        Ok(Self { rsa, enc })
    }
}
