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
    aes::{ENCRYPTION_EXTRA_SIZE, decrypt, encrypt},
};

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

use crate::assets::{REQ_PLAINTEXT_SIZE, Request};
use crate::helpers::{
    DEFAULT_DEPLOYMENT, Deployment, OBJECT_VERSION_V1, license_encryption_salt, license_key,
    license_sig_message, public_key_is_valid, request_encryption_salt,
};
use crate::signatures::LicenseSignature;

const LICENSE_CONTEXT_SIZE: usize = LicenseContext::SIZE;
pub(crate) const LIC_PLAINTEXT_SIZE: usize =
    LicenseSignature::SIZE + JubJubScalar::SIZE + PublicKey::SIZE + LICENSE_CONTEXT_SIZE;
const LIC_ENCRYPTION_SIZE: usize = LIC_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

/// Enumeration used to create new licenses
pub enum LicenseOrigin {
    /// From a transport-neutral encrypted [`Request`] delivered to the LP.
    FromRequest(Box<Request>),
    /// From a [`PublicKey`] of a given user
    FromPublicKey(Box<PublicKey>),
}

/// Context authenticated inside an encrypted license payload.
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LicenseContext {
    /// Object version authenticated by the encrypted payload.
    pub version: BlsScalar,
    /// Compact deployment identifier authenticated by the encrypted payload.
    pub deployment_id: BlsScalar,
    /// Schema identifier for `attr_data`.
    pub schema_id: BlsScalar,
    /// Issuance metadata encoded by the deployment profile.
    pub issued_at: BlsScalar,
    /// Expiration value, or zero as the prototype no-expiration marker.
    pub expires_at: BlsScalar,
    /// Revocation handle, or zero as the prototype no-revocation marker.
    pub revocation_id: BlsScalar,
}

impl LicenseContext {
    /// Serialized size of [`LicenseContext`].
    pub const SIZE: usize = BlsScalar::SIZE * 6;

    /// Creates the default prototype context for the selected deployment.
    pub fn prototype(deployment: Deployment) -> Self {
        Self {
            version: OBJECT_VERSION_V1,
            deployment_id: deployment.id,
            schema_id: BlsScalar::zero(),
            issued_at: BlsScalar::zero(),
            expires_at: BlsScalar::zero(),
            revocation_id: BlsScalar::zero(),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let mut offset = 0;
        write_scalar(&mut bytes, &mut offset, self.version);
        write_scalar(&mut bytes, &mut offset, self.deployment_id);
        write_scalar(&mut bytes, &mut offset, self.schema_id);
        write_scalar(&mut bytes, &mut offset, self.issued_at);
        write_scalar(&mut bytes, &mut offset, self.expires_at);
        write_scalar(&mut bytes, &mut offset, self.revocation_id);
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        let mut offset = 0;
        let version = read_scalar(bytes, &mut offset)?;
        let deployment_id = read_scalar(bytes, &mut offset)?;
        let schema_id = read_scalar(bytes, &mut offset)?;
        let issued_at = read_scalar(bytes, &mut offset)?;
        let expires_at = read_scalar(bytes, &mut offset)?;
        let revocation_id = read_scalar(bytes, &mut offset)?;

        Ok(Self {
            version,
            deployment_id,
            schema_id,
            issued_at,
            expires_at,
            revocation_id,
        })
    }
}

/// Decrypted and authenticated Citadel license payload.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LicensePayload {
    /// LP signature over `H(lpk.u, lpk.v, attr_data)`.
    pub sig_lic: LicenseSignature,
    /// Schema-scoped attribute digest or non-personal scalar signed by the LP.
    pub attr_data: JubJubScalar,
    /// Full canonical Phoenix public key of the License Provider.
    pub pk_lp: PublicKey,
    /// Non-personal license metadata authenticated by the payload.
    pub context: LicenseContext,
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
    /// Object version.
    pub version: BlsScalar,
    /// Compact deployment identifier.
    pub deployment_id: BlsScalar,
    /// The stealth address of the license
    pub lsa: StealthAddress,
    /// The encryption of the license signature and the attribute data     
    pub enc: [u8; LIC_ENCRYPTION_SIZE],
}

/// License construction parameters.
///
/// Callers that want the prototype defaults can pass [`LicenseOptions::default`],
/// which uses `DEFAULT_DEPLOYMENT` and zero values for schema, issuance,
/// expiration, and revocation context.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LicenseOptions {
    /// Deployment profile for the license envelope and cryptographic domains.
    pub deployment: Deployment,
    /// Schema identifier for `attr_data`.
    pub schema_id: BlsScalar,
    /// Issuance metadata encoded by the deployment profile.
    pub issued_at: BlsScalar,
    /// Expiration value, or zero as the prototype no-expiration marker.
    pub expires_at: BlsScalar,
    /// Revocation handle, or zero as the prototype no-revocation marker.
    pub revocation_id: BlsScalar,
}

impl Default for LicenseOptions {
    fn default() -> Self {
        Self {
            deployment: DEFAULT_DEPLOYMENT,
            schema_id: BlsScalar::zero(),
            issued_at: BlsScalar::zero(),
            expires_at: BlsScalar::zero(),
            revocation_id: BlsScalar::zero(),
        }
    }
}

impl License {
    /// Method to generate a new [`License`] with explicit construction options.
    pub fn new<R: RngCore + CryptoRng>(
        attr_data: &JubJubScalar,
        sk_lp: &SecretKey,
        lo: &LicenseOrigin,
        options: LicenseOptions,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let deployment = options.deployment;
        let (lsa, k_lic) = match lo {
            LicenseOrigin::FromRequest(req) => {
                if req.version != OBJECT_VERSION_V1 {
                    return Err(Error::InvalidData);
                }
                if req.deployment_id != deployment.id {
                    return Err(Error::InvalidData);
                }

                let actual_pk_lp = PublicKey::from(sk_lp);
                let k_dh = dhke(sk_lp.a(), req.rsa.R());

                let salt =
                    request_encryption_salt(deployment, req.version, &req.rsa, &actual_pk_lp);
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

                let mut request_version_bytes = [0u8; BlsScalar::SIZE];
                request_version_bytes.copy_from_slice(&dec[offset..offset + BlsScalar::SIZE]);
                let request_version =
                    Option::<BlsScalar>::from(BlsScalar::from_bytes(&request_version_bytes))
                        .ok_or(Error::InvalidData)?;
                offset += BlsScalar::SIZE;

                let mut deployment_id_bytes = [0u8; BlsScalar::SIZE];
                deployment_id_bytes.copy_from_slice(&dec[offset..offset + BlsScalar::SIZE]);
                let deployment_id =
                    Option::<BlsScalar>::from(BlsScalar::from_bytes(&deployment_id_bytes))
                        .ok_or(Error::InvalidData)?;
                offset += BlsScalar::SIZE;

                let mut pk_lp_bytes = [0u8; PublicKey::SIZE];
                pk_lp_bytes.copy_from_slice(&dec[offset..offset + PublicKey::SIZE]);
                let intended_pk_lp = PublicKey::from_bytes(&pk_lp_bytes)?;

                if request_version != req.version
                    || deployment_id != deployment.id
                    || intended_pk_lp != actual_pk_lp
                {
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
        let pk_lp = PublicKey::from(sk_lp);
        let pk_lp_a = JubJubAffine::from(pk_lp.A());
        let sig_lic = LicenseSignature::sign(rng, deployment, sk_lp.a(), pk_lp_a, message);
        let mut context = LicenseContext::prototype(deployment);
        context.schema_id = options.schema_id;
        context.issued_at = options.issued_at;
        context.expires_at = options.expires_at;
        context.revocation_id = options.revocation_id;

        let mut plaintext = sig_lic.to_bytes().to_vec();
        plaintext.append(&mut attr_data.to_bytes().to_vec());
        plaintext.append(&mut pk_lp.to_bytes().to_vec());
        plaintext.append(&mut context.to_bytes().to_vec());

        let salt = license_encryption_salt(deployment, OBJECT_VERSION_V1, &lsa);
        let enc = encrypt(&k_lic, &salt, &plaintext, rng)?;

        Ok(Self {
            version: OBJECT_VERSION_V1,
            deployment_id: deployment.id,
            lsa,
            enc,
        })
    }

    /// Decrypts, decodes, and verifies the license payload for an owning key.
    pub fn open(&self, sk: &SecretKey) -> Result<LicensePayload, Error> {
        if self.version != OBJECT_VERSION_V1 {
            return Err(Error::InvalidData);
        }

        let deployment = Deployment::new(
            self.deployment_id,
            self.version,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        let lpk = JubJubAffine::from(self.lsa.note_pk().as_ref());
        let lsa_r = JubJubAffine::from(self.lsa.R());
        let lsk = sk.gen_note_sk(&self.lsa);
        let salt = license_encryption_salt(deployment, self.version, &self.lsa);
        let direct_key = dhke(sk.a(), self.lsa.R());
        let dec: [u8; LIC_PLAINTEXT_SIZE] = match decrypt(&direct_key, &salt, &self.enc) {
            Ok(dec) => dec,
            Err(_err) => {
                let request_key = license_key(deployment, *lsk.as_ref(), lpk, lsa_r);
                decrypt(&request_key, &salt, &self.enc)?
            }
        };

        let payload = decode_license_plaintext(&dec)?;
        if payload.context.version != self.version
            || payload.context.deployment_id != self.deployment_id
        {
            return Err(Error::InvalidData);
        }

        let pk_lp_a = JubJubAffine::from(payload.pk_lp.A());
        let message = license_sig_message(deployment, lpk, payload.attr_data);
        if !payload.sig_lic.verify(deployment, pk_lp_a, message) {
            return Err(Error::InvalidData);
        }

        Ok(payload)
    }
}

pub(crate) fn decode_license_plaintext(
    bytes: &[u8; LIC_PLAINTEXT_SIZE],
) -> Result<LicensePayload, Error> {
    let mut sig_lic_bytes = [0u8; LicenseSignature::SIZE];
    sig_lic_bytes.copy_from_slice(&bytes[..LicenseSignature::SIZE]);
    let sig_lic = LicenseSignature::from_bytes(&sig_lic_bytes)?;

    let mut attr_data_bytes = [0u8; JubJubScalar::SIZE];
    let mut offset = LicenseSignature::SIZE;
    attr_data_bytes.copy_from_slice(&bytes[offset..offset + JubJubScalar::SIZE]);
    let attr_data = Option::<JubJubScalar>::from(JubJubScalar::from_bytes(&attr_data_bytes))
        .ok_or(Error::InvalidData)?;
    offset += JubJubScalar::SIZE;

    let mut pk_lp_bytes = [0u8; PublicKey::SIZE];
    pk_lp_bytes.copy_from_slice(&bytes[offset..offset + PublicKey::SIZE]);
    let pk_lp = PublicKey::from_bytes(&pk_lp_bytes)?;
    if !public_key_is_valid(&pk_lp) {
        return Err(Error::InvalidData);
    }
    offset += PublicKey::SIZE;

    let mut context_bytes = [0u8; LicenseContext::SIZE];
    context_bytes.copy_from_slice(&bytes[offset..offset + LicenseContext::SIZE]);
    let context = LicenseContext::from_bytes(&context_bytes)?;

    Ok(LicensePayload {
        sig_lic,
        attr_data,
        pk_lp,
        context,
    })
}

fn write_scalar(bytes: &mut [u8], offset: &mut usize, scalar: BlsScalar) {
    bytes[*offset..*offset + BlsScalar::SIZE].copy_from_slice(&scalar.to_bytes());
    *offset += BlsScalar::SIZE;
}

fn read_scalar(bytes: &[u8], offset: &mut usize) -> Result<BlsScalar, Error> {
    let mut scalar_bytes = [0u8; BlsScalar::SIZE];
    scalar_bytes.copy_from_slice(&bytes[*offset..*offset + BlsScalar::SIZE]);
    *offset += BlsScalar::SIZE;

    Option::<BlsScalar>::from(BlsScalar::from_bytes(&scalar_bytes)).ok_or(Error::InvalidData)
}
