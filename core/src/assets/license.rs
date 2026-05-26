// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::dhke;
use ff::Field;
use jubjub_schnorr::{SecretKey as LicenseSecretKey, Signature};
use phoenix_core::{
    Error, PublicKey, SecretKey, StealthAddress,
    aes::{ENCRYPTION_EXTRA_SIZE, decrypt, encrypt},
};

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

use crate::assets::{REQ_PLAINTEXT_SIZE, Request};
use crate::helpers::{DEFAULT_DEPLOYMENT, Deployment, license_sig_message};

pub(crate) const LIC_PLAINTEXT_SIZE: usize = Signature::SIZE + JubJubScalar::SIZE;
const LIC_ENCRYPTION_SIZE: usize = LIC_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

/// Enumeration used to create new licenses
pub enum LicenseOrigin {
    /// From a [`Request`] sent on-chain
    FromRequest(Box<Request>),
    /// From a [`PublicKey`] of a given user
    FromPublicKey(Box<PublicKey>),
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
    /// Compact deployment identifier.
    pub deployment_id: BlsScalar,
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
        Self::new_with_deployment(attr_data, sk_lp, lo, DEFAULT_DEPLOYMENT, rng)
    }

    /// Method to generate a new [`License`] bound to a deployment.
    pub fn new_with_deployment<R: RngCore + CryptoRng>(
        attr_data: &JubJubScalar,
        sk_lp: &SecretKey,
        lo: &LicenseOrigin,
        deployment: Deployment,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let (lsa, k_lic) = match lo {
            LicenseOrigin::FromRequest(req) => {
                if req.deployment_id != deployment.id {
                    return Err(Error::InvalidData);
                }

                let k_dh = dhke(sk_lp.a(), req.rsa.R());

                let salt = req.rsa.note_pk().to_bytes();
                let dec: [u8; REQ_PLAINTEXT_SIZE] = decrypt(&k_dh, &salt, &req.enc)?;

                let mut lsa_bytes = [0u8; StealthAddress::SIZE];
                lsa_bytes.copy_from_slice(&dec[..StealthAddress::SIZE]);
                let lsa = StealthAddress::from_bytes(&lsa_bytes)?;

                let mut k_lic_bytes = [0u8; JubJubAffine::SIZE];
                let mut offset = StealthAddress::SIZE;
                k_lic_bytes.copy_from_slice(&dec[offset..offset + JubJubAffine::SIZE]);
                let k_lic = Option::<JubJubAffine>::from(JubJubAffine::from_bytes(k_lic_bytes))
                    .ok_or(Error::InvalidData)?;
                offset += JubJubAffine::SIZE;

                let mut deployment_id_bytes = [0u8; BlsScalar::SIZE];
                deployment_id_bytes.copy_from_slice(&dec[offset..offset + BlsScalar::SIZE]);
                let deployment_id =
                    Option::<BlsScalar>::from(BlsScalar::from_bytes(&deployment_id_bytes))
                        .ok_or(Error::InvalidData)?;
                offset += BlsScalar::SIZE;

                let mut pk_lp_bytes = [0u8; PublicKey::SIZE];
                pk_lp_bytes.copy_from_slice(&dec[offset..offset + PublicKey::SIZE]);
                let intended_pk_lp = PublicKey::from_bytes(&pk_lp_bytes)?;
                let actual_pk_lp = PublicKey::from(sk_lp);

                if deployment_id != deployment.id || intended_pk_lp != actual_pk_lp {
                    return Err(Error::InvalidData);
                }

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

        let message = license_sig_message(deployment, lpk, *attr_data);
        let sig_lic = LicenseSecretKey::from(sk_lp.a()).sign(rng, message);

        let mut plaintext = sig_lic.to_bytes().to_vec();
        plaintext.append(&mut attr_data.to_bytes().to_vec());

        let salt = lsa.note_pk().to_bytes();
        let enc = encrypt(&k_lic, &salt, &plaintext, rng)?;

        Ok(Self {
            deployment_id: deployment.id,
            lsa,
            enc,
        })
    }
}
