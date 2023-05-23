// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::JubJubAffine;
use dusk_jubjub::{dhke, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_merkle::poseidon::Opening;
use dusk_merkle::poseidon::Tree;
use dusk_pki::{PublicKey, PublicSpendKey, SecretKey, SecretSpendKey, StealthAddress};
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge;
use dusk_schnorr::Signature;
// use rand_core::{CryptoRng, RngCore};

use dusk_plonk::prelude::*;

use crate::unit::{PoseidonItem, Unit};

pub struct Request {
    pub rsa: StealthAddress,   // request stealth address
    pub enc_1: PoseidonCipher, // encryption of the license stealth address and k_lic
    pub nonce_1: BlsScalar,    // IV for the encryption
    pub enc_2: PoseidonCipher, // encryption of the license stealth address and k_lic
    pub nonce_2: BlsScalar,    // IV for the encryption
    pub enc_3: PoseidonCipher, // encryption of the license stealth address and k_lic
    pub nonce_3: BlsScalar,    // IV for the encryption
}

pub struct Session {
    pub session_hash: BlsScalar,
    pub session_id: BlsScalar,

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2
}

impl Session {
    pub fn from(public_inputs: &[BlsScalar]) -> Self {
        // public inputs are in negated form, we negate them again to assert correctly
        let session_id = -public_inputs[0];
        let session_hash = -public_inputs[1];

        let com_0 = -public_inputs[2];
        let com_1 = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            -public_inputs[3],
            -public_inputs[4],
        ));
        let com_2 = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            -public_inputs[5],
            -public_inputs[6],
        ));

        Self {
            session_hash,
            session_id,

            com_0,
            com_1,
            com_2,
        }
    }

    pub fn verify(&self, sc: SessionCookie, pk_lp: JubJubAffine) {
        assert_eq!(pk_lp, sc.pk_lp);

        let session_hash = sponge::hash(&[sc.pk_sp.get_x(), sc.pk_sp.get_y(), sc.r]);
        assert_eq!(session_hash, self.session_hash);

        let com_0 = sponge::hash(&[pk_lp.get_x(), pk_lp.get_y(), sc.s_0]);
        assert_eq!(com_0, self.com_0);

        let com_1 = (GENERATOR_EXTENDED * sc.attr) + (GENERATOR_NUMS_EXTENDED * sc.s_1);
        assert_eq!(com_1, self.com_1);

        let com_2 = (GENERATOR_EXTENDED * sc.c) + (GENERATOR_NUMS_EXTENDED * sc.s_2);
        assert_eq!(com_2, self.com_2);
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct SessionCookie {
    pub pk_sp: JubJubAffine, // public key of the SP
    pub r: BlsScalar,        // randomness for session_hash
    pub session_id: BlsScalar,

    pub pk_lp: JubJubAffine, // public key of the LP
    pub attr: JubJubScalar,  // attributes of the license
    pub c: JubJubScalar,     // challenge value

    pub s_0: BlsScalar,    // randomness for com_0
    pub s_1: JubJubScalar, // randomness for com_1
    pub s_2: JubJubScalar, // randomness for com_2
}

#[derive(Default, Clone, PartialEq)]
pub struct License {
    pub lsa: StealthAddress,   // license stealth address
    pub enc_1: PoseidonCipher, // encryption of the license signature and attributes
    pub nonce_1: BlsScalar,    // IV for the encryption
    pub enc_2: PoseidonCipher, // encryption of the license signature and attributes
    pub nonce_2: BlsScalar,    // IV for the encryption
    pub pos: u64,              // position of the license in the Merkle tree of licenses
}

#[derive(Debug, Clone, Copy)]
pub struct LicenseProverParameters<const DEPTH: usize, const ARITY: usize> {
    pub lpk: JubJubAffine,   // license public key
    pub lpk_p: JubJubAffine, // license public key prime
    pub sig_lic: Signature,  // signature of the license

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2

    pub session_hash: BlsScalar,                   // hash of the session
    pub sig_session_hash: dusk_schnorr::Proof,     // signature of the session_hash
    pub merkle_proof: Opening<Unit, DEPTH, ARITY>, // Merkle proof for the Proof of Validity
}

impl<const DEPTH: usize, const ARITY: usize> Default for LicenseProverParameters<DEPTH, ARITY> {
    fn default() -> Self {
        let mut tree = Tree::new();
        let item = PoseidonItem {
            hash: BlsScalar::zero(),
            data: Unit,
        };
        tree.insert(0, item);
        let merkle_proof = tree.opening(0).expect("There is a leaf at position 0");
        Self {
            lpk: JubJubAffine::default(),
            lpk_p: JubJubAffine::default(),
            sig_lic: Signature::default(),

            com_0: BlsScalar::default(),
            com_1: JubJubExtended::default(),
            com_2: JubJubExtended::default(),

            session_hash: BlsScalar::default(),
            sig_session_hash: dusk_schnorr::Proof::default(),
            merkle_proof,
        }
    }
}

