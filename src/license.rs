// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::JubJubAffine;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{SecretKey, SecretSpendKey, StealthAddress};
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
pub struct SessionCookie {
    pub nullifier_lic: BlsScalar,

    pub pk_sp: JubJubAffine,
    pub attr: JubJubScalar,
    pub c: JubJubScalar,

    pub s_0: BlsScalar,
    pub s_1: JubJubScalar,
    pub s_2: JubJubScalar,
}

impl SessionCookie {
    pub fn new(
        nullifier_lic: BlsScalar,

        pk_sp: JubJubAffine,
        attr: JubJubScalar,
        c: JubJubScalar,

        s_0: BlsScalar,
        s_1: JubJubScalar,
        s_2: JubJubScalar,
    ) -> Self {
        Self {
            nullifier_lic,

            pk_sp,
            attr,
            c,

            s_0,
            s_1,
            s_2,
        }
    }

    pub fn verify(&self, public_inputs: Vec<BlsScalar>, pk_sp: JubJubAffine) {
        assert_eq!(pk_sp.get_x(), self.pk_sp.get_x());
        assert_eq!(pk_sp.get_y(), self.pk_sp.get_y());

        // public inputs are in negated form, we negate them again to assert correctly
        let com_0 = sponge::hash(&[self.pk_sp.get_x(), self.pk_sp.get_y(), self.s_0]);
        assert_eq!(com_0, -public_inputs[2]);

        let com_1 = (GENERATOR_EXTENDED * self.attr) + (GENERATOR_NUMS_EXTENDED * self.s_1);
        assert_eq!(JubJubAffine::from(com_1).get_x(), -public_inputs[3]);
        assert_eq!(JubJubAffine::from(com_1).get_y(), -public_inputs[4]);

        let com_2 = (GENERATOR_EXTENDED * self.c) + (GENERATOR_NUMS_EXTENDED * self.s_2);
        assert_eq!(JubJubAffine::from(com_2).get_x(), -public_inputs[5]);
        assert_eq!(JubJubAffine::from(com_2).get_y(), -public_inputs[6]);
    }
}

#[derive(Debug, Clone)]
pub struct License {
    pub lsa: StealthAddress,   // license public key
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
        let enc_2 = PoseidonCipher::encrypt(
            &[BlsScalar::from(sig_lic_r.get_x()), sig_lic_r.get_y()],
            &k_lic,
            &nonce_2,
        );
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
    pub lpk: JubJubAffine,
    pub lpk_p: JubJubAffine,     // license public key prime
    pub sig_lic_u: JubJubScalar, // signature of the license
    pub sig_lic_r: JubJubAffine, // signature of the license

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2

    pub tx_hash: BlsScalar, // hash of the transaction nullifying the license
    pub sig_tx: dusk_schnorr::Proof, // signature of the tx_hash
    pub merkle_proof: PoseidonBranch<DEPTH>, // Merkle proof for the Proof of Validity
}

impl LicenseProverParameters {
    pub fn new<R: RngCore + CryptoRng>(
        lsa: StealthAddress,
        ssk: SecretSpendKey,
        lic: License,
        pk_sp: JubJubAffine,
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
        let sig_lic_u = JubJubScalar::from_bytes(&dec_1[0].to_bytes()).unwrap();
        let sig_lic_r = JubJubAffine::from_raw_unchecked(
            BlsScalar::from_bytes(&dec_2[0].to_bytes()).unwrap(),
            BlsScalar::from_bytes(&dec_2[1].to_bytes()).unwrap(),
        );

        let lsk = ssk.sk_r(&lsa);
        let lpk_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * lsk.as_ref());

        let s_0 = BlsScalar::random(rng);
        let s_1 = JubJubScalar::random(rng);
        let s_2 = JubJubScalar::random(rng);

        let c = JubJubScalar::from(20221126u64);
        let tx_hash = BlsScalar::from(112233445566778899u64);
        let sig_tx = dusk_schnorr::Proof::new(&lsk, rng, tx_hash);

        let nullifier_lic = sponge::hash(&[lpk_p.get_x(), lpk_p.get_y(), BlsScalar::from(c)]);

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
                sig_lic_u,
                sig_lic_r,

                com_0,
                com_1,
                com_2,

                tx_hash,
                sig_tx,
                merkle_proof,
            },
            SessionCookie {
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
