// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::JubJubAffine;
use dusk_jubjub::{dhke, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{PublicKey, PublicSpendKey, SecretKey, SecretSpendKey, StealthAddress};
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge;
use dusk_schnorr::Signature;
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug)]
pub struct Request {
    pub rsa: StealthAddress,   // request stealth address
    pub enc_1: PoseidonCipher, // encryption of the license stealth address and k_lic
    pub nonce_1: BlsScalar,    // IV for the encryption
    pub enc_2: PoseidonCipher, // encryption of the license stealth address and k_lic
    pub nonce_2: BlsScalar,    // IV for the encryption
    pub enc_3: PoseidonCipher, // encryption of the license stealth address and k_lic
    pub nonce_3: BlsScalar,    // IV for the encryption
}

impl Request {
    pub fn new<R: RngCore + CryptoRng>(
        psk_lp: &PublicSpendKey,
        lsa: &StealthAddress,
        k_lic: &JubJubAffine,
        rng: &mut R,
    ) -> Self {
        let nonce_1 = BlsScalar::random(rng);
        let nonce_2 = BlsScalar::random(rng);
        let nonce_3 = BlsScalar::random(rng);

        let lpk = JubJubAffine::from(*lsa.pk_r().as_ref());
        let r = JubJubAffine::from(*lsa.R());

        let r_dh = JubJubScalar::random(rng);
        let rsa = psk_lp.gen_stealth_address(&r_dh);
        let k_dh = dhke(&r_dh, psk_lp.A());

        let enc_1 = PoseidonCipher::encrypt(&[lpk.get_x(), lpk.get_y()], &k_dh, &nonce_1);

        let enc_2 = PoseidonCipher::encrypt(&[r.get_x(), r.get_y()], &k_dh, &nonce_2);

        let enc_3 = PoseidonCipher::encrypt(&[k_lic.get_x(), k_lic.get_y()], &k_dh, &nonce_3);

        Self {
            rsa,
            enc_1,
            nonce_1,
            enc_2,
            nonce_2,
            enc_3,
            nonce_3,
        }
    }
}

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug)]
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
        let session_id = public_inputs[0];
        let session_hash = public_inputs[1];

        let com_0 = public_inputs[2];
        let com_1 = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            public_inputs[3],
            public_inputs[4],
        ));
        let com_2 = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            public_inputs[5],
            public_inputs[6],
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

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
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

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Default, Debug, Clone)]
pub struct License {
    pub lsa: StealthAddress,   // license stealth address
    pub enc_1: PoseidonCipher, // encryption of the license signature and attributes
    pub nonce_1: BlsScalar,    // IV for the encryption
    pub enc_2: PoseidonCipher, // encryption of the license signature and attributes
    pub nonce_2: BlsScalar,    // IV for the encryption
}

impl License {
    pub fn new<R: RngCore + CryptoRng>(
        attr: &JubJubScalar,
        ssk_lp: &SecretSpendKey,
        req: &Request,
        rng: &mut R,
    ) -> Self {
        let k_dh = dhke(ssk_lp.a(), req.rsa.R());

        let dec_1 = req
            .enc_1
            .decrypt(&k_dh, &req.nonce_1)
            .expect("decryption should succeed");

        let dec_2 = req
            .enc_2
            .decrypt(&k_dh, &req.nonce_2)
            .expect("decryption should succeed");

        let dec_3 = req
            .enc_3
            .decrypt(&k_dh, &req.nonce_3)
            .expect("decryption should succeed");

        let lpk = JubJubAffine::from_raw_unchecked(dec_1[0], dec_1[1]);
        let r = JubJubAffine::from_raw_unchecked(dec_2[0], dec_2[1]);
        let k_lic = JubJubAffine::from_raw_unchecked(dec_3[0], dec_3[1]);

        let message = sponge::hash(&[lpk.get_x(), lpk.get_y(), BlsScalar::from(*attr)]);

        let sig_lic = Signature::new(&SecretKey::from(ssk_lp.a()), rng, message);
        let sig_lic_r = JubJubAffine::from(sig_lic.R());

        let nonce_1 = BlsScalar::random(rng);
        let nonce_2 = BlsScalar::random(rng);

        let enc_1 = PoseidonCipher::encrypt(
            &[BlsScalar::from(*sig_lic.u()), BlsScalar::from(*attr)],
            &k_lic,
            &nonce_1,
        );

        let enc_2 =
            PoseidonCipher::encrypt(&[sig_lic_r.get_x(), sig_lic_r.get_y()], &k_lic, &nonce_2);

        Self {
            lsa: StealthAddress::from_raw_unchecked(
                JubJubExtended::from(r),
                PublicKey::from_raw_unchecked(JubJubExtended::from(lpk)),
            ),
            enc_1,
            nonce_1,
            enc_2,
            nonce_2,
        }
    }
}

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy)]
pub struct CitadelProverParameters<const DEPTH: usize, const ARITY: usize> {
    pub lpk: JubJubAffine,   // license public key
    pub lpk_p: JubJubAffine, // license public key prime
    pub sig_lic: Signature,  // signature of the license

    pub com_0: BlsScalar,      // Hash commitment 0
    pub com_1: JubJubExtended, // Pedersen Commitment 1
    pub com_2: JubJubExtended, // Pedersen Commitment 2

    pub session_hash: BlsScalar,                 // hash of the session
    pub sig_session_hash: dusk_schnorr::Proof,   // signature of the session_hash
    pub merkle_proof: Opening<(), DEPTH, ARITY>, // Merkle proof for the Proof of Validity
}

impl<const DEPTH: usize, const ARITY: usize> Default for CitadelProverParameters<DEPTH, ARITY> {
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
            sig_session_hash: dusk_schnorr::Proof::default(),
            merkle_proof,
        }
    }
}

impl<const DEPTH: usize, const ARITY: usize> CitadelProverParameters<DEPTH, ARITY> {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_parameters<R: RngCore + CryptoRng>(
        ssk: &SecretSpendKey,
        lic: &License,
        psk_lp: &PublicSpendKey,
        psk_sp: &PublicSpendKey,
        c: &JubJubScalar,
        rng: &mut R,
        merkle_proof: Opening<(), DEPTH, ARITY>,
    ) -> (Self, SessionCookie) {
        let lsk = ssk.sk_r(&lic.lsa);
        let k_lic = JubJubAffine::from(
            GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]),
        );

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

        let lpk = JubJubAffine::from(*lic.lsa.pk_r().as_ref());

        let lsk = ssk.sk_r(&lic.lsa);
        let lpk_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * lsk.as_ref());

        let s_0 = BlsScalar::random(rng);
        let s_1 = JubJubScalar::random(rng);
        let s_2 = JubJubScalar::random(rng);

        let pk_sp = JubJubAffine::from(*psk_sp.A());
        let r = BlsScalar::random(rng);

        let session_hash = sponge::hash(&[pk_sp.get_x(), pk_sp.get_y(), r]);

        let sig_session_hash = dusk_schnorr::Proof::new(&lsk, rng, session_hash);

        let session_id = sponge::hash(&[lpk_p.get_x(), lpk_p.get_y(), BlsScalar::from(*c)]);

        let pk_lp = JubJubAffine::from(*psk_lp.A());

        let com_0 = sponge::hash(&[pk_lp.get_x(), pk_lp.get_y(), s_0]);
        let com_1 = (GENERATOR_EXTENDED * attr) + (GENERATOR_NUMS_EXTENDED * s_1);
        let com_2 = (GENERATOR_EXTENDED * c) + (GENERATOR_NUMS_EXTENDED * s_2);

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
                pk_sp,
                r,
                session_id,
                pk_lp,
                attr,
                c: *c,
                s_0,
                s_1,
                s_2,
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ShelterProverParameters<const DEPTH: usize, const ARITY: usize> {
    pub lsk: JubJubScalar, // license secret key

    pub sig_lic: Signature,  // signature of the licensee
    pub pk_lp: JubJubAffine, // public key of the LP
    pub attr: JubJubScalar,  // attributes of the license

    pub c: JubJubScalar, // challenge value
    pub session_id: BlsScalar,

    pub merkle_proof: Opening<(), DEPTH, ARITY>, // Merkle proof for the Proof of Validity
}

impl<const DEPTH: usize, const ARITY: usize> Default for ShelterProverParameters<DEPTH, ARITY> {
    fn default() -> Self {
        let mut tree = Tree::new();
        let item = Item {
            hash: BlsScalar::zero(),
            data: (),
        };
        tree.insert(0, item);
        let merkle_proof = tree.opening(0).expect("There is a leaf at position 0");
        Self {
            lsk: JubJubScalar::default(),

            sig_lic: Signature::default(),
            pk_lp: JubJubAffine::default(),
            attr: JubJubScalar::default(),

            c: JubJubScalar::default(),
            session_id: BlsScalar::default(),

            merkle_proof,
        }
    }
}

impl<const DEPTH: usize, const ARITY: usize> ShelterProverParameters<DEPTH, ARITY> {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_parameters(
        ssk: &SecretSpendKey,
        lic: &License,
        psk_lp: &PublicSpendKey,
        c: &JubJubScalar,
        merkle_proof: Opening<(), DEPTH, ARITY>,
    ) -> Self {
        let lsk = ssk.sk_r(&lic.lsa);
        let k_lic = JubJubAffine::from(
            GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]),
        );

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

        let lsk_binding = ssk.sk_r(&lic.lsa);
        let lsk = lsk_binding.as_ref();

        let session_id = sponge::hash(&[BlsScalar::from(*lsk), BlsScalar::from(*c)]);
        let pk_lp = JubJubAffine::from(*psk_lp.A());

        Self {
            lsk: *lsk,

            sig_lic,
            pk_lp,
            attr,

            c: *c,
            session_id,

            merkle_proof,
        }
    }
}
