// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::JubJubAffine;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{PublicSpendKey, SecretKey, SecretSpendKey, StealthAddress};
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge;
use dusk_schnorr::Signature;
use rand_core::{CryptoRng, RngCore};

use dusk_bytes::Serializable;

use dusk_plonk::prelude::*;
use dusk_poseidon::tree::{PoseidonBranch, PoseidonLeaf, PoseidonTree};
use nstack::annotation::Keyed;

const DEPTH: usize = 17; // depth of the 4-ary Merkle tree
type Tree = PoseidonTree<DataLeaf, (), DEPTH>;

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct DataLeaf {
    note_hash: BlsScalar,
    pos: u64,
}

// Keyed needs to be implemented for a leaf type and the tree key.
impl Keyed<()> for DataLeaf {
    fn key(&self) -> &() {
        &()
    }
}

impl DataLeaf {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let note_hash = BlsScalar::random(rng);
        let pos = 0;

        Self { note_hash, pos }
    }
    pub fn new(hash: BlsScalar, n: u64) -> DataLeaf {
        DataLeaf {
            note_hash: hash,
            pos: n,
        }
    }
}

impl From<u64> for DataLeaf {
    fn from(n: u64) -> DataLeaf {
        DataLeaf {
            note_hash: BlsScalar::from(n),
            pos: n,
        }
    }
}

impl PoseidonLeaf for DataLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        // the note hash (the leaf) is computed into the circuit
        self.note_hash
    }

    fn pos(&self) -> &u64 {
        &self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

#[derive(Default, Debug, Clone)]
pub struct Session {
    pub session_hash: BlsScalar,  // hash of the session
    pub nullifier_lic: BlsScalar, // license nullifier

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2
}

impl Session {
    pub fn from(public_inputs: Vec<BlsScalar>) -> Self {
        // public inputs are in negated form, we negate them again to assert correctly
        let nullifier_lic = -public_inputs[0];
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
            nullifier_lic,

            com_0,
            com_1,
            com_2,
        }
    }

    pub fn verify(&self, sc: SessionCookie, pk_sp: JubJubAffine) {
        assert_eq!(pk_sp, sc.pk_sp);

        let session_hash = sponge::hash(&[sc.pk_ssp.get_x(), sc.pk_ssp.get_y(), sc.r]);

        assert_eq!(session_hash, self.session_hash);

        // public inputs are in negated form, we negate them again to assert correctly
        let com_0 = sponge::hash(&[pk_sp.get_x(), pk_sp.get_y(), sc.s_0]);
        assert_eq!(com_0, self.com_0);

        let com_1 = (GENERATOR_EXTENDED * sc.attr) + (GENERATOR_NUMS_EXTENDED * sc.s_1);
        assert_eq!(com_1, self.com_1);

        let com_2 = (GENERATOR_EXTENDED * sc.c) + (GENERATOR_NUMS_EXTENDED * sc.s_2);
        assert_eq!(com_2, self.com_2);
    }
}

#[derive(Default, Debug, Clone)]
pub struct SessionCookie {
    pub pk_ssp: JubJubAffine,     // public key of the session SP
    pub r: BlsScalar,             // randomness for session_hash
    pub nullifier_lic: BlsScalar, // license nullifier

    pub pk_sp: JubJubAffine, // public key of the SP
    pub attr: JubJubScalar,  // attributes of the license
    pub c: JubJubScalar,     // challenge value

    pub s_0: BlsScalar,    // randomness for com_0
    pub s_1: JubJubScalar, // randomness for com_1
    pub s_2: JubJubScalar, // randomness for com_2
}

impl SessionCookie {
    pub fn new(
        pk_ssp: JubJubAffine,
        r: BlsScalar,
        nullifier_lic: BlsScalar,

        pk_sp: JubJubAffine,
        attr: JubJubScalar,
        c: JubJubScalar,

        s_0: BlsScalar,
        s_1: JubJubScalar,
        s_2: JubJubScalar,
    ) -> Self {
        Self {
            pk_ssp,
            r,
            nullifier_lic,

            pk_sp,
            attr,
            c,

            s_0,
            s_1,
            s_2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct License {
    pub lsa: StealthAddress,   // license stealth address
    pub enc_1: PoseidonCipher, // encryption of the license signature and attributes
    pub nonce_1: BlsScalar,    // IV for the encryption
    pub enc_2: PoseidonCipher, // encryption of the license signature and attributes
    pub nonce_2: BlsScalar,    // IV for the encryption
    pub pos: BlsScalar,        // position of the license in the Merkle tree of licenses
}

impl License {
    pub fn new<R: RngCore + CryptoRng>(
        attr: JubJubScalar,
        ssk_sp: SecretSpendKey,
        lsa: StealthAddress,
        k_lic: JubJubAffine,
        rng: &mut R,
    ) -> Self {
        let lpk = JubJubAffine::from(*lsa.pk_r().as_ref());

        let message = sponge::hash(&[lpk.get_x(), lpk.get_y(), BlsScalar::from(attr)]);

        let sig_lic = Signature::new(&SecretKey::from(ssk_sp.a()), rng, message);
        let sig_lic_r = JubJubAffine::from(sig_lic.R());

        let nonce_1 = BlsScalar::random(rng);
        let nonce_2 = BlsScalar::random(rng);

        let enc_1 = PoseidonCipher::encrypt(
            &[BlsScalar::from(*sig_lic.u()), BlsScalar::from(attr)],
            &k_lic,
            &nonce_1,
        );

        let enc_2 =
            PoseidonCipher::encrypt(&[sig_lic_r.get_x(), sig_lic_r.get_y()], &k_lic, &nonce_2);

        let pos = BlsScalar::from(1u64);

        Self {
            lsa,
            enc_1,
            nonce_1,
            enc_2,
            nonce_2,
            pos,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct LicenseProverParameters {
    pub lpk: JubJubAffine,   // license public key
    pub lpk_p: JubJubAffine, // license public key prime
    pub sig_lic: Signature,  // signature of the license

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2

    pub session_hash: BlsScalar,               // hash of the session
    pub sig_session_hash: dusk_schnorr::Proof, // signature of the ssa_hash
    pub merkle_proof: PoseidonBranch<DEPTH>,   // Merkle proof for the Proof of Validity
}

impl LicenseProverParameters {
    pub fn new<R: RngCore + CryptoRng>(
        lsa: StealthAddress,
        ssk: SecretSpendKey,
        lic: License,
        psk_sp: PublicSpendKey,
        psk_ssp: PublicSpendKey,
        k_lic: JubJubAffine,
        rng: &mut R,
    ) -> (Self, SessionCookie) {
        let dec_1 = lic
            .enc_1
            .decrypt(&k_lic, &lic.nonce_1)
            .expect("decryption should succeed");

        let dec_2 = lic
            .enc_2
            .decrypt(&k_lic, &lic.nonce_2)
            .expect("decryption should succeed");

        let attr = JubJubScalar::from_bytes(&dec_1[1].to_bytes()).unwrap();
        let sig_lic = Signature::from_bytes(
            &[
                dec_1[0].to_bytes(),
                JubJubAffine::from_raw_unchecked(dec_2[0], dec_2[1]).to_bytes(),
            ]
            .concat()
            .try_into()
            .expect("slice with incorrect length"),
        )
        .unwrap();

        let lsk = ssk.sk_r(&lsa);
        let lpk_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * lsk.as_ref());

        let s_0 = BlsScalar::random(rng);
        let s_1 = JubJubScalar::random(rng);
        let s_2 = JubJubScalar::random(rng);

        let c = JubJubScalar::from(20221126u64);

        let pk_ssp = JubJubAffine::from(*psk_ssp.A());
        let r = BlsScalar::random(rng);

        let session_hash = sponge::hash(&[pk_ssp.get_x(), pk_ssp.get_y(), r]);

        let sig_session_hash = dusk_schnorr::Proof::new(&lsk, rng, session_hash);

        let nullifier_lic = sponge::hash(&[lpk_p.get_x(), lpk_p.get_y(), BlsScalar::from(c)]);

        let pk_sp = JubJubAffine::from(*psk_sp.A());

        let com_0 = sponge::hash(&[pk_sp.get_x(), pk_sp.get_y(), s_0]);
        let com_1 = (GENERATOR_EXTENDED * attr) + (GENERATOR_NUMS_EXTENDED * s_1);
        let com_2 = (GENERATOR_EXTENDED * c) + (GENERATOR_NUMS_EXTENDED * s_2);

        let lpk = JubJubAffine::from(*lsa.pk_r().as_ref());
        let note_hash = sponge::hash(&[lpk.get_x(), lpk.get_y()]);

        let mut tree = Tree::default();
        let pos_tree = tree.push(DataLeaf::new(note_hash, 0));

        for i in 1..1024 {
            let l = DataLeaf::from(i as u64);
            tree.push(l);
        }

        let merkle_proof = tree.branch(pos_tree).expect("Tree was read successfully");

        (
            Self {
                lpk,
                lpk_p,
                sig_lic,

                com_0,
                com_1,
                com_2,

                session_hash,
                sig_session_hash,
                merkle_proof,
            },
            SessionCookie {
                pk_ssp,
                r,
                nullifier_lic,
                pk_sp,
                attr,
                c,
                s_0,
                s_1,
                s_2,
            },
        )
    }
}
