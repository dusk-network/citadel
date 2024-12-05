// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{dhke, GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::Hash;
use dusk_poseidon::{Domain, HashGadget};
use ff::Field;
use jubjub_schnorr::gadgets;
use jubjub_schnorr::{Signature, SignatureDouble};
use phoenix_core::{aes::decrypt, PublicKey, SecretKey};
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::{license::LIC_PLAINTEXT_SIZE, License, SessionCookie};

use poseidon_merkle::zk::opening_gadget;

// out of this circuit, the generated public inputs vector collects
// these values in that particular order:
//
// public_inputs[0]: session_id
// public_inputs[1]: session_hash
// public_inputs[2]: com_0
// public_inputs[3]: com_1.x
// public_inputs[4]: com_1.y
// public_inputs[5]: com_2.x
// public_inputs[6]: com_2.y
// public_inputs[7]: root

pub fn use_license<const DEPTH: usize>(
    composer: &mut Composer,
    gp: &GadgetParameters<DEPTH>,
    sc: &SessionCookie,
) -> Result<(), Error> {
    // APPEND THE LICENSE PUBLIC KEYS OF THE USER
    let lpk = composer.append_point(gp.lpk);
    let lpk_p = composer.append_point(gp.lpk_p);

    // COMPUTE THE SESSION ID
    let c = composer.append_witness(sc.c);
    let session_id_pi = composer.append_public(sc.session_id);
    let session_id = HashGadget::digest(composer, Domain::Other, &[*lpk_p.x(), *lpk_p.y(), c]);

    composer.assert_equal(session_id[0], session_id_pi);

    // VERIFY THE LICENSE SIGNATURE
    let sig_lic_u = composer.append_witness(*gp.sig_lic.u());
    let sig_lic_r = composer.append_point(gp.sig_lic.R());
    let pk_lp = composer.append_point(sc.pk_lp);
    let attr_data = composer.append_witness(sc.attr_data);

    let message = HashGadget::digest(composer, Domain::Other, &[*lpk.x(), *lpk.y(), attr_data]);
    gadgets::verify_signature(composer, sig_lic_u, sig_lic_r, pk_lp, message[0])?;

    // VERIFY THE SESSION HASH SIGNATURE
    let sig_session_hash_u = composer.append_witness(*gp.sig_session_hash.u());
    let sig_session_hash_r = composer.append_point(gp.sig_session_hash.R());
    let sig_session_hash_r_p = composer.append_point(gp.sig_session_hash.R_prime());
    let session_hash = composer.append_public(gp.session_hash);

    gadgets::verify_signature_double(
        composer,
        sig_session_hash_u,
        sig_session_hash_r,
        sig_session_hash_r_p,
        lpk,
        lpk_p,
        session_hash,
    )?;

    // COMMIT TO THE PK_LP USING A HASH FUNCTION
    let s_0 = composer.append_witness(sc.s_0);
    let com_0_pi = composer.append_public(gp.com_0);
    let com_0 = HashGadget::digest(composer, Domain::Other, &[*pk_lp.x(), *pk_lp.y(), s_0]);

    composer.assert_equal(com_0[0], com_0_pi);

    // COMMIT TO THE ATTRIBUTE DATA
    let s_1 = composer.append_witness(sc.s_1);
    let pc_1_1 = composer.component_mul_generator(attr_data, GENERATOR);
    let pc_1_2 = composer.component_mul_generator(s_1, GENERATOR_NUMS);
    let com_1 = composer.component_add_point(pc_1_1.unwrap(), pc_1_2.unwrap());

    composer.assert_equal_public_point(com_1, gp.com_1);

    // COMMIT TO THE CHALLENGE
    let s_2 = composer.append_witness(sc.s_2);
    let pc_2_1 = composer.component_mul_generator(c, GENERATOR);
    let pc_2_2 = composer.component_mul_generator(s_2, GENERATOR_NUMS);
    let com_2 = composer.component_add_point(pc_2_1.unwrap(), pc_2_2.unwrap());

    composer.assert_equal_public_point(com_2, gp.com_2);

    // COMPUTE THE HASH OF THE LICENSE
    let license_hash = HashGadget::digest(composer, Domain::Other, &[*lpk.x(), *lpk.y()]);

    // VERIFY THE MERKLE PROOF
    let root_pi = composer.append_public(gp.merkle_proof.root().hash);
    let root = opening_gadget(composer, &gp.merkle_proof, license_hash[0]);
    composer.assert_equal(root, root_pi);

    Ok(())
}

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy)]
pub struct GadgetParameters<const DEPTH: usize> {
    pub lpk: JubJubAffine,   // license public key
    pub lpk_p: JubJubAffine, // license public key prime
    pub sig_lic: Signature,  // signature of the license

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2

    pub session_hash: BlsScalar,           // hash of the session
    pub sig_session_hash: SignatureDouble, // signature of the session_hash
    pub merkle_proof: Opening<(), DEPTH>,  // Merkle proof for the Proof of Validity
}

impl<const DEPTH: usize> Default for GadgetParameters<DEPTH> {
    fn default() -> Self {
        let mut tree = Tree::new();
        let item = Item {
            hash: BlsScalar::zero(),
            data: (),
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
            sig_session_hash: SignatureDouble::default(),
            merkle_proof,
        }
    }
}

impl<const DEPTH: usize> GadgetParameters<DEPTH> {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_parameters<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        lic: &License,
        pk_lp: &PublicKey,
        pk_sp: &PublicKey,
        c: &JubJubScalar,
        mut rng: &mut R,
        merkle_proof: Opening<(), DEPTH>,
    ) -> Result<(Self, SessionCookie), phoenix_core::Error> {
        let lsk = sk.gen_note_sk(&lic.lsa);
        let k_lic = dhke(sk.a(), lic.lsa.R());

        let dec: [u8; LIC_PLAINTEXT_SIZE] = match decrypt(&k_lic, &lic.enc) {
            Ok(dec) => dec,
            Err(_err) => {
                let k_lic = JubJubAffine::from(
                    GENERATOR_EXTENDED
                        * Hash::digest_truncated(Domain::Other, &[(*lsk.as_ref()).into()])[0],
                );

                decrypt(&k_lic, &lic.enc)?
            }
        };

        let mut sig_lic_bytes = [0u8; Signature::SIZE];
        sig_lic_bytes.copy_from_slice(&dec[..Signature::SIZE]);
        let sig_lic = Signature::from_bytes(&sig_lic_bytes).expect("Deserialization was correct.");

        let mut attr_data_bytes = [0u8; JubJubScalar::SIZE];
        attr_data_bytes.copy_from_slice(&dec[Signature::SIZE..]);
        let attr_data =
            JubJubScalar::from_bytes(&attr_data_bytes).expect("Deserialization was correct.");

        let lpk = JubJubAffine::from(*lic.lsa.note_pk().as_ref());
        let lpk_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * lsk.as_ref());

        let s_0 = BlsScalar::random(&mut rng);
        let s_1 = JubJubScalar::random(&mut rng);
        let s_2 = JubJubScalar::random(&mut rng);

        let pk_sp = JubJubAffine::from(*pk_sp.A());
        let r = BlsScalar::random(&mut rng);

        let session_hash = Hash::digest(Domain::Other, &[pk_sp.get_u(), pk_sp.get_v(), r])[0];
        let sig_session_hash = lsk.sign_double(rng, session_hash);

        let mut session_id = Hash::new(Domain::Other);
        let binding = &[lpk_p.get_u(), lpk_p.get_v(), BlsScalar::from(*c)];
        session_id.update(binding);
        let session_id = session_id.finalize()[0];

        let pk_lp = JubJubAffine::from(*pk_lp.A());

        let com_0 = Hash::digest(Domain::Other, &[pk_lp.get_u(), pk_lp.get_v(), s_0])[0];
        let com_1 = (GENERATOR_EXTENDED * attr_data) + (GENERATOR_NUMS_EXTENDED * s_1);
        let com_2 = (GENERATOR_EXTENDED * c) + (GENERATOR_NUMS_EXTENDED * s_2);

        Ok((
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
                pk_sp,
                r,
                session_id,
                pk_lp,
                attr_data,
                c: *c,
                s_0,
                s_1,
                s_2,
            },
        ))
    }
}
