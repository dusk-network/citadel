// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::JubJubAffine;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::SecretKey;
use dusk_poseidon::sponge;
use dusk_schnorr::Signature;
use rand_core::{CryptoRng, RngCore};

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

pub struct SessionCookie {
    pub pk_sp: JubJubAffine,
    pub s_0: BlsScalar,

    pub attr: JubJubScalar,
    pub s_1: JubJubScalar,

    pub c: JubJubScalar,
    pub s_2: JubJubScalar,
}

impl SessionCookie {
    pub fn new(
        pk_sp: JubJubAffine,
        s_0: BlsScalar,
        attr: JubJubScalar,
        s_1: JubJubScalar,
        c: JubJubScalar,
        s_2: JubJubScalar,
    ) -> Self {
        Self {
            pk_sp,
            s_0,
            attr,
            s_1,
            c,
            s_2,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct License {
    pub npk_user: JubJubAffine,   // note public key
    pub npk_user_p: JubJubAffine, // note public key prime

    pub pk_sp: JubJubAffine, // static public key of the service provider SP
    pub attr: JubJubScalar,  // set of attributes describing our license
    pub sig_lic: Signature,  // signature of the license

    pub note_type: BlsScalar, // 2: transparent, 3: obfuscated
    pub enc: BlsScalar,       // encryption of the commitment opening
    pub nonce: BlsScalar,     // IV for the encryption
    pub r_user: JubJubAffine, // R value of the user
    pub pos: BlsScalar,       // position of the note in the Merkle tree

    pub s_0: BlsScalar,    // randomness for the hash
    pub s_1: JubJubScalar, // randomness for the Pedersen Commitment
    pub s_2: JubJubScalar, // randomness for the Pedersen Commitment

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2

    pub c: JubJubScalar,             // challenge for the nullifier
    pub tx_hash: BlsScalar,          // hash of the transaction nullifying the license
    pub sig_tx: dusk_schnorr::Proof, // signature of the tx_hash
    pub nullifier_lic: BlsScalar,    // License nullifier

    pub merkle_proof: PoseidonBranch<DEPTH>, // Merkle proof for the Proof of Validity
}

impl License {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // First, the user computes these values and requests a License
        let nsk_user = SecretKey::random(rng);
        let npk_user = JubJubAffine::from(GENERATOR_EXTENDED * nsk_user.as_ref());
        let npk_user_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * nsk_user.as_ref());

        // Second, the SP computes these values and grants the License
        let sk_sp = SecretKey::random(rng);
        let pk_sp = JubJubAffine::from(GENERATOR_EXTENDED * sk_sp.as_ref());

        let attr = JubJubScalar::from(112233445566778899u64);
        let message = sponge::hash(&[npk_user.get_x(), npk_user.get_y(), BlsScalar::from(attr)]);

        let sig_lic = Signature::new(&sk_sp, rng, message);

        let note_type = BlsScalar::from(3u64);
        let enc = BlsScalar::random(rng);
        let nonce = BlsScalar::random(rng);
        let r_user = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(rng));
        let pos = BlsScalar::from(1u64);

        // Third, the user computes these values to generate the ZKP later on
        let s_0 = BlsScalar::random(rng);
        let s_1 = JubJubScalar::random(rng);
        let s_2 = JubJubScalar::random(rng);

        let c = JubJubScalar::from(20221126u64);
        let tx_hash = BlsScalar::from(112233445566778899u64);
        let sig_tx = dusk_schnorr::Proof::new(&nsk_user, rng, tx_hash);

        let com_0 = sponge::hash(&[pk_sp.get_x(), pk_sp.get_y(), s_0]);

        let com_1 = (GENERATOR_EXTENDED * attr) + (GENERATOR_NUMS_EXTENDED * s_1);
        let com_2 = (GENERATOR_EXTENDED * c) + (GENERATOR_NUMS_EXTENDED * s_2);

        let nullifier_lic =
            sponge::hash(&[npk_user_p.get_x(), npk_user_p.get_y(), BlsScalar::from(c)]);

        let note_hash = sponge::hash(&[
            note_type,
            enc,
            nonce,
            r_user.get_x(),
            r_user.get_y(),
            npk_user.get_x(),
            npk_user.get_y(),
            pos,
        ]);

        let mut tree = Tree::default();
        let pos_tree = tree.push(DataLeaf::new(note_hash, 0));

        for i in 1..1024 {
            let l = DataLeaf::from(i as u64);
            tree.push(l);
        }

        let merkle_proof = tree.branch(pos_tree).expect("Tree was read successfully");

        Self {
            npk_user,
            npk_user_p,

            pk_sp,
            attr,
            sig_lic,

            note_type,
            enc,
            nonce,
            r_user,
            pos,

            s_0,
            s_1,
            s_2,

            com_0,
            com_1,
            com_2,

            c,
            tx_hash,
            sig_tx,
            nullifier_lic,

            merkle_proof,
        }
    }

    pub fn verify(sc: SessionCookie, public_inputs: Vec<BlsScalar>, pk_sp: JubJubAffine) {
        assert_eq!(pk_sp.get_x(), sc.pk_sp.get_x());
        assert_eq!(pk_sp.get_y(), sc.pk_sp.get_y());

        // public inputs are in negated form, we negate them again to assert correctly
        let com_0 = sponge::hash(&[sc.pk_sp.get_x(), sc.pk_sp.get_y(), sc.s_0]);
        assert_eq!(com_0, -public_inputs[2]);

        let com_1 = (GENERATOR_EXTENDED * sc.attr) + (GENERATOR_NUMS_EXTENDED * sc.s_1);
        assert_eq!(JubJubAffine::from(com_1).get_x(), -public_inputs[3]);
        assert_eq!(JubJubAffine::from(com_1).get_y(), -public_inputs[4]);

        let com_2 = (GENERATOR_EXTENDED * sc.c) + (GENERATOR_NUMS_EXTENDED * sc.s_2);
        assert_eq!(JubJubAffine::from(com_2).get_x(), -public_inputs[5]);
        assert_eq!(JubJubAffine::from(com_2).get_y(), -public_inputs[6]);
    }
}
