// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{dhke, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_schnorr::{SecretKey as NoteSecretKey, Signature, SignatureDouble};
use phoenix_core::{
    aes::{decrypt, encrypt, ENCRYPTION_EXTRA_SIZE},
    Error, PublicKey, SecretKey, StealthAddress,
};
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_plonk::prelude::*;

const REQ_PLAINTEXT_SIZE: usize = StealthAddress::SIZE + JubJubAffine::SIZE;
const REQ_ENCRYPTION_SIZE: usize = REQ_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

const LIC_PLAINTEXT_SIZE: usize = Signature::SIZE + JubJubScalar::SIZE;
const LIC_ENCRYPTION_SIZE: usize = LIC_PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug)]
pub struct Request {
    pub rsa: StealthAddress,            // request stealth address
    pub enc: [u8; REQ_ENCRYPTION_SIZE], // encryption of the license stealth address and k_lic
}

impl Request {
    pub fn new<R: RngCore + CryptoRng>(
        pk_lp: &PublicKey,
        lsa: &StealthAddress,
        k_lic: &JubJubAffine,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let r_dh = JubJubScalar::random(&mut *rng);
        let rsa = pk_lp.gen_stealth_address(&r_dh);
        let k_dh = dhke(&r_dh, pk_lp.A());

        let mut plaintext = lsa.to_bytes().to_vec();
        plaintext.append(&mut k_lic.to_bytes().to_vec());

        let enc = encrypt(&k_dh, &plaintext, rng)?;

        Ok(Self { rsa, enc })
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

    pub fn verify(&self, sc: SessionCookie, pk_lp: JubJubAffine, pk_sp: JubJubAffine) {
        assert!(self.verifies_ok(sc, pk_lp, pk_sp));
    }

    pub fn verifies_ok(&self, sc: SessionCookie, pk_lp: JubJubAffine, pk_sp: JubJubAffine) -> bool {
        if pk_lp != sc.pk_lp {
            return false;
        }

        if pk_sp != sc.pk_sp {
            return false;
        }

        let session_hash =
            Hash::digest(Domain::Other, &[sc.pk_sp.get_u(), sc.pk_sp.get_v(), sc.r])[0];
        if session_hash != self.session_hash {
            return false;
        }

        let com_0 = Hash::digest(Domain::Other, &[pk_lp.get_u(), pk_lp.get_v(), sc.s_0])[0];
        if com_0 != self.com_0 {
            return false;
        }

        let com_1 = (GENERATOR_EXTENDED * sc.attr_data) + (GENERATOR_NUMS_EXTENDED * sc.s_1);
        if com_1 != self.com_1 {
            return false;
        }

        let com_2 = (GENERATOR_EXTENDED * sc.c) + (GENERATOR_NUMS_EXTENDED * sc.s_2);
        if com_2 != self.com_2 {
            return false;
        }
        true
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

    pub pk_lp: JubJubAffine,     // public key of the LP
    pub attr_data: JubJubScalar, // attribute data of the license
    pub c: JubJubScalar,         // challenge value

    pub s_0: BlsScalar,    // randomness for com_0
    pub s_1: JubJubScalar, // randomness for com_1
    pub s_2: JubJubScalar, // randomness for com_2
}

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone)]
pub struct License {
    pub lsa: StealthAddress,            // license stealth address
    pub enc: [u8; LIC_ENCRYPTION_SIZE], // encryption of the license signature and attribute data
}

impl License {
    pub fn new<R: RngCore + CryptoRng>(
        attr_data: &JubJubScalar,
        sk_lp: &SecretKey,
        req: &Request,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let k_dh = dhke(sk_lp.a(), req.rsa.R());
        let dec: [u8; REQ_PLAINTEXT_SIZE] = decrypt(&k_dh, &req.enc)?;

        let mut lsa_bytes = [0u8; StealthAddress::SIZE];
        lsa_bytes.copy_from_slice(&dec[..StealthAddress::SIZE]);
        let lsa = StealthAddress::from_bytes(&lsa_bytes).expect("Deserialization was correct.");

        let mut k_lic_bytes = [0u8; JubJubAffine::SIZE];
        k_lic_bytes.copy_from_slice(&dec[StealthAddress::SIZE..]);
        let k_lic = JubJubAffine::from_bytes(k_lic_bytes).expect("Deserialization was correct.");

        let message = Hash::digest(
            Domain::Other,
            &[
                lsa.note_pk().as_ref().get_u(),
                lsa.note_pk().as_ref().get_v(),
                BlsScalar::from(*attr_data),
            ],
        )[0];
        let sig_lic = NoteSecretKey::from(sk_lp.a()).sign(rng, message);

        let mut plaintext = sig_lic.to_bytes().to_vec();
        plaintext.append(&mut attr_data.to_bytes().to_vec());

        let enc = encrypt(&k_lic, &plaintext, rng)?;

        Ok(Self { lsa, enc })
    }
}

#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy)]
pub struct CitadelProverParameters<const DEPTH: usize> {
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

impl<const DEPTH: usize> Default for CitadelProverParameters<DEPTH> {
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

impl<const DEPTH: usize> CitadelProverParameters<DEPTH> {
    #[allow(clippy::too_many_arguments)]
    pub fn compute_parameters<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        lic: &License,
        pk_lp: &PublicKey,
        pk_sp: &PublicKey,
        c: &JubJubScalar,
        mut rng: &mut R,
        merkle_proof: Opening<(), DEPTH>,
    ) -> Result<(Self, SessionCookie), Error> {
        let lsk = sk.gen_note_sk(lic.lsa);
        let k_lic = JubJubAffine::from(
            GENERATOR_EXTENDED
                * Hash::digest_truncated(Domain::Other, &[(*lsk.as_ref()).into()])[0],
        );

        let dec: [u8; LIC_PLAINTEXT_SIZE] = decrypt(&k_lic, &lic.enc)?;

        let mut sig_lic_bytes = [0u8; Signature::SIZE];
        sig_lic_bytes.copy_from_slice(&dec[..Signature::SIZE]);
        let sig_lic = Signature::from_bytes(&sig_lic_bytes).expect("Deserialization was correct.");

        let mut attr_data_bytes = [0u8; JubJubScalar::SIZE];
        attr_data_bytes.copy_from_slice(&dec[Signature::SIZE..]);
        let attr_data =
            JubJubScalar::from_bytes(&attr_data_bytes).expect("Deserialization was correct.");

        let lpk = JubJubAffine::from(*lic.lsa.note_pk().as_ref());

        let lsk = sk.gen_note_sk(lic.lsa);
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
