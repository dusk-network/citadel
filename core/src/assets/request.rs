// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::dhke;
use ff::Field;
use phoenix_core::{
    Error, PublicKey, SecretKey, StealthAddress,
    aes::{ENCRYPTION_EXTRA_SIZE, encrypt},
};

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

use crate::helpers::{
    DEFAULT_DEPLOYMENT, Deployment, OBJECT_VERSION_V1, license_key, request_encryption_salt,
    request_id,
};

const DEPLOYMENT_CONTEXT_SIZE: usize = BlsScalar::SIZE;
const OBJECT_VERSION_SIZE: usize = BlsScalar::SIZE;
pub(crate) const REQ_PLAINTEXT_SIZE: usize = StealthAddress::SIZE
    + JubJubAffine::SIZE
    + OBJECT_VERSION_SIZE
    + DEPLOYMENT_CONTEXT_SIZE
    + PublicKey::SIZE;
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
    /// Object version.
    pub version: BlsScalar,
    /// Compact deployment identifier.
    pub deployment_id: BlsScalar,
    /// The stealth address for the request
    pub rsa: StealthAddress,
    /// The encryption of the license stealth address and the k_lic symmetric key
    pub enc: [u8; REQ_ENCRYPTION_SIZE],
}

impl Request {
    /// Method to create a new [`Request`] given the user keys and the public key of LP.
    pub fn new<R: RngCore + CryptoRng>(
        sk_user: &SecretKey,
        pk_user: &PublicKey,
        pk_lp: &PublicKey,
        rng: &mut R,
    ) -> Result<Self, Error> {
        Self::new_with_deployment(sk_user, pk_user, pk_lp, DEFAULT_DEPLOYMENT, rng)
    }

    /// Method to create a new [`Request`] bound to a deployment.
    pub fn new_with_deployment<R: RngCore + CryptoRng>(
        sk_user: &SecretKey,
        pk_user: &PublicKey,
        pk_lp: &PublicKey,
        deployment: Deployment,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let lsa = pk_user.gen_stealth_address(&JubJubScalar::random(&mut *rng));
        let lsk = sk_user.gen_note_sk(&lsa);
        let k_lic = license_key(
            deployment,
            *lsk.as_ref(),
            JubJubAffine::from(lsa.note_pk().as_ref()),
            JubJubAffine::from(lsa.R()),
        );

        let r_dh = JubJubScalar::random(&mut *rng);
        let rsa = pk_lp.gen_stealth_address(&r_dh);
        let k_dh = dhke(&r_dh, pk_lp.A());

        let mut plaintext = lsa.to_bytes().to_vec();
        plaintext.append(&mut k_lic.to_bytes().to_vec());
        plaintext.append(&mut OBJECT_VERSION_V1.to_bytes().to_vec());
        plaintext.append(&mut deployment.id.to_bytes().to_vec());
        plaintext.append(&mut pk_lp.to_bytes().to_vec());

        let salt = request_encryption_salt(deployment, OBJECT_VERSION_V1, &rsa, pk_lp);
        let enc = encrypt(&k_dh, &salt, &plaintext, rng)?;

        Ok(Self {
            version: OBJECT_VERSION_V1,
            deployment_id: deployment.id,
            rsa,
            enc,
        })
    }

    /// Computes the request ID defined by the protocol.
    pub fn id(&self) -> BlsScalar {
        request_id(
            Deployment::new(
                self.deployment_id,
                self.version,
                BlsScalar::zero(),
                BlsScalar::zero(),
            ),
            self.version,
            &self.rsa,
            &self.enc,
        )
    }
}
