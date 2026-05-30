// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Citadel-specific Schnorr signatures and transcript helpers.
//!
//! These wrappers keep Citadel's LP and session-authorization transcripts
//! explicit instead of relying on the generic `jubjub-schnorr` transcript.

use dusk_bytes::{Error as BytesError, Serializable};
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED, JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::BlsScalar;
use ff::Field;
use rand_core::{CryptoRng, RngCore};

use crate::helpers::{Deployment, license_sig_challenge, session_sig_challenge};

/// LP Schnorr signature over a Citadel license message.
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[allow(non_snake_case)]
pub struct LicenseSignature {
    z: JubJubScalar,
    r: dusk_jubjub::JubJubExtended,
}

impl LicenseSignature {
    /// Exposes the response scalar.
    pub fn z(&self) -> &JubJubScalar {
        &self.z
    }

    /// Exposes the nonce point.
    #[allow(non_snake_case)]
    pub fn R(&self) -> &dusk_jubjub::JubJubExtended {
        &self.r
    }

    /// Signs a license message using the Citadel LP signature transcript.
    pub fn sign<R: RngCore + CryptoRng>(
        rng: &mut R,
        deployment: Deployment,
        signing_secret: &JubJubScalar,
        signing_point: JubJubAffine,
        msg_lic: BlsScalar,
    ) -> Self {
        let nonce = JubJubScalar::random(rng);
        let r = GENERATOR_EXTENDED * nonce;
        let r_affine = JubJubAffine::from(r);
        let challenge = license_sig_challenge(deployment, signing_point, r_affine, msg_lic);
        let z = nonce + challenge * signing_secret;

        Self { z, r }
    }

    /// Verifies the Citadel LP signature transcript outside the circuit.
    pub fn verify(
        &self,
        deployment: Deployment,
        signing_point: JubJubAffine,
        msg_lic: BlsScalar,
    ) -> bool {
        let r = JubJubAffine::from(self.r);
        let challenge = license_sig_challenge(deployment, signing_point, r, msg_lic);
        let lhs = GENERATOR_EXTENDED * self.z;
        let rhs = self.r + (dusk_jubjub::JubJubExtended::from(signing_point) * challenge);

        lhs == rhs
    }
}

impl Serializable<64> for LicenseSignature {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..JubJubScalar::SIZE].copy_from_slice(&self.z.to_bytes());
        buf[JubJubScalar::SIZE..].copy_from_slice(&JubJubAffine::from(self.r).to_bytes());
        buf
    }

    #[allow(non_snake_case)]
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut z_bytes = [0u8; JubJubScalar::SIZE];
        z_bytes.copy_from_slice(&bytes[..JubJubScalar::SIZE]);
        let z = Option::<JubJubScalar>::from(JubJubScalar::from_bytes(&z_bytes))
            .ok_or(BytesError::InvalidData)?;

        let mut r_bytes = [0u8; JubJubAffine::SIZE];
        r_bytes.copy_from_slice(&bytes[JubJubScalar::SIZE..]);
        let r = Option::<JubJubAffine>::from(JubJubAffine::from_bytes(r_bytes))
            .ok_or(BytesError::InvalidData)?
            .into();

        Ok(Self { z, r })
    }
}

/// Double-key Schnorr signature over the public session tuple.
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[allow(non_snake_case)]
pub struct SessionAuthSignature {
    z: JubJubScalar,
    r: dusk_jubjub::JubJubExtended,
    r_prime: dusk_jubjub::JubJubExtended,
}

impl SessionAuthSignature {
    /// Exposes the response scalar.
    pub fn z(&self) -> &JubJubScalar {
        &self.z
    }

    /// Exposes the nonce point for `G`.
    #[allow(non_snake_case)]
    pub fn R(&self) -> &dusk_jubjub::JubJubExtended {
        &self.r
    }

    /// Exposes the nonce point for `G'`.
    #[allow(non_snake_case)]
    pub fn R_prime(&self) -> &dusk_jubjub::JubJubExtended {
        &self.r_prime
    }

    /// Signs a session-authorization message using the Citadel double-key transcript.
    #[allow(non_snake_case)]
    pub fn sign<R: RngCore + CryptoRng>(
        rng: &mut R,
        deployment: Deployment,
        license_secret: &JubJubScalar,
        lpk: JubJubAffine,
        lpk_p: JubJubAffine,
        session_auth: BlsScalar,
    ) -> Self {
        let nonce = JubJubScalar::random(rng);
        let r = GENERATOR_EXTENDED * nonce;
        let r_prime = GENERATOR_NUMS_EXTENDED * nonce;
        let challenge = session_sig_challenge(
            deployment,
            lpk,
            lpk_p,
            JubJubAffine::from(r),
            JubJubAffine::from(r_prime),
            session_auth,
        );
        let z = nonce + challenge * license_secret;

        Self { z, r, r_prime }
    }

    /// Verifies the double-key session-authorization transcript outside the circuit.
    pub fn verify(
        &self,
        deployment: Deployment,
        lpk: JubJubAffine,
        lpk_p: JubJubAffine,
        session_auth: BlsScalar,
    ) -> bool {
        let challenge = session_sig_challenge(
            deployment,
            lpk,
            lpk_p,
            JubJubAffine::from(self.r),
            JubJubAffine::from(self.r_prime),
            session_auth,
        );

        let lhs = GENERATOR_EXTENDED * self.z;
        let rhs = self.r + (dusk_jubjub::JubJubExtended::from(lpk) * challenge);
        let lhs_prime = GENERATOR_NUMS_EXTENDED * self.z;
        let rhs_prime = self.r_prime + (dusk_jubjub::JubJubExtended::from(lpk_p) * challenge);

        lhs == rhs && lhs_prime == rhs_prime
    }
}

impl Serializable<96> for SessionAuthSignature {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..JubJubScalar::SIZE].copy_from_slice(&self.z.to_bytes());
        buf[JubJubScalar::SIZE..64].copy_from_slice(&JubJubAffine::from(self.r).to_bytes());
        buf[64..].copy_from_slice(&JubJubAffine::from(self.r_prime).to_bytes());
        buf
    }

    #[allow(non_snake_case)]
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut z_bytes = [0u8; JubJubScalar::SIZE];
        z_bytes.copy_from_slice(&bytes[..JubJubScalar::SIZE]);
        let z = Option::<JubJubScalar>::from(JubJubScalar::from_bytes(&z_bytes))
            .ok_or(BytesError::InvalidData)?;

        let mut r_bytes = [0u8; JubJubAffine::SIZE];
        r_bytes.copy_from_slice(&bytes[JubJubScalar::SIZE..64]);
        let r = Option::<JubJubAffine>::from(JubJubAffine::from_bytes(r_bytes))
            .ok_or(BytesError::InvalidData)?
            .into();

        let mut r_prime_bytes = [0u8; JubJubAffine::SIZE];
        r_prime_bytes.copy_from_slice(&bytes[64..]);
        let r_prime = Option::<JubJubAffine>::from(JubJubAffine::from_bytes(r_prime_bytes))
            .ok_or(BytesError::InvalidData)?
            .into();

        Ok(Self { z, r, r_prime })
    }
}
