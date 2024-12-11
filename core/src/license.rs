// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::dhke;
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_schnorr::{SecretKey as LicenseSecretKey, Signature};
use phoenix_core::{
    aes::{decrypt, encrypt, ENCRYPTION_EXTRA_SIZE},
    Error, PublicKey, SecretKey, StealthAddress,
};

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

use crate::request::{Request, REQ_PLAINTEXT_SIZE};

pub(crate) const LIC_PLAINTEXT_SIZE: usize = Signature::SIZE + JubJubScalar::SIZE;
const LIC_ENCRYPTION_SIZE: usize = LIC_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

/// Enumeration used to create new licenses
pub enum LicenseOrigin {
    /// From a [`Request`] sent on-chain
    FromRequest(Request),
    /// From a [`PublicKey`] of a given user
    FromPublicKey(PublicKey),
}

/// The struct defining a Citadel license, an asset that represents
/// the right of a user to use a specific service
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone)]
pub struct License {
    /// The stealth address of the license
    pub lsa: StealthAddress,
    /// The encryption of the license signature and the attribute data     
    pub enc: [u8; LIC_ENCRYPTION_SIZE],
}

impl License {
    /// Method to generate a new [`License`]
    pub fn new<R: RngCore + CryptoRng>(
        attr_data: &JubJubScalar,
        sk_lp: &SecretKey,
        lo: &LicenseOrigin,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (lsa, k_lic) = match lo {
            LicenseOrigin::FromRequest(req) => {
                let k_dh = dhke(sk_lp.a(), req.rsa.R());
                let dec: [u8; REQ_PLAINTEXT_SIZE] = decrypt(&k_dh, &req.enc)?;

                let mut lsa_bytes = [0u8; StealthAddress::SIZE];
                lsa_bytes.copy_from_slice(&dec[..StealthAddress::SIZE]);
                let lsa =
                    StealthAddress::from_bytes(&lsa_bytes).expect("Deserialization was correct.");

                let mut k_lic_bytes = [0u8; JubJubAffine::SIZE];
                k_lic_bytes.copy_from_slice(&dec[StealthAddress::SIZE..]);
                let k_lic =
                    JubJubAffine::from_bytes(k_lic_bytes).expect("Deserialization was correct.");

                (lsa, k_lic)
            }
            LicenseOrigin::FromPublicKey(pk_user) => {
                let r_dh = JubJubScalar::random(&mut *rng);
                let lsa = pk_user.gen_stealth_address(&r_dh);
                let k_lic = dhke(&r_dh, pk_user.A());

                (lsa, k_lic)
            }
        };

        let lpk = JubJubAffine::from(lsa.note_pk().as_ref());

        let message = Hash::digest(
            Domain::Other,
            &[lpk.get_u(), lpk.get_v(), BlsScalar::from(*attr_data)],
        )[0];
        let sig_lic = LicenseSecretKey::from(sk_lp.a()).sign(rng, message);

        let mut plaintext = sig_lic.to_bytes().to_vec();
        plaintext.append(&mut attr_data.to_bytes().to_vec());

        let enc = encrypt(&k_lic, &plaintext, rng)?;

        Ok(Self { lsa, enc })
    }
}
