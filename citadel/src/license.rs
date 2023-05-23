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
use rand_core::{CryptoRng, RngCore};

use dusk_plonk::prelude::*;

use crate::state::State;

use zk_citadel_shared::{License, LicenseProverParameters, Request, SessionCookie};

pub fn new_request<R: RngCore + CryptoRng>(
    psk_lp: &PublicSpendKey,
    lsa: &StealthAddress,
    k_lic: &JubJubAffine,
    rng: &mut R,
) -> Request {
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

    Request {
        rsa,
        enc_1,
        nonce_1,
        enc_2,
        nonce_2,
        enc_3,
        nonce_3,
    }
}

pub fn new_license<R: RngCore + CryptoRng>(
    attr: &JubJubScalar,
    ssk_lp: &SecretSpendKey,
    req: &Request,
    rng: &mut R,
) -> License {
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

    let enc_2 = PoseidonCipher::encrypt(&[sig_lic_r.get_x(), sig_lic_r.get_y()], &k_lic, &nonce_2);

    let pos = 0u64;

    License {
        lsa: StealthAddress::from_raw_unchecked(
            JubJubExtended::from(r),
            PublicKey::from_raw_unchecked(JubJubExtended::from(lpk)),
        ),
        enc_1,
        nonce_1,
        enc_2,
        nonce_2,
        pos,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn compute_parameters<R: RngCore + CryptoRng, const DEPTH: usize, const ARITY: usize>(
    ssk: &SecretSpendKey,
    lic: &License,
    psk_lp: &PublicSpendKey,
    psk_sp: &PublicSpendKey,
    k_lic: &JubJubAffine,
    c: &JubJubScalar,
    rng: &mut R,
    state: &State<DEPTH, ARITY>,
) -> (LicenseProverParameters<DEPTH, ARITY>, SessionCookie) {
    let dec_1 = lic
        .enc_1
        .decrypt(k_lic, &lic.nonce_1)
        .expect("decryption should succeed");

    let dec_2 = lic
        .enc_2
        .decrypt(k_lic, &lic.nonce_2)
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

    let merkle_proof = state.get_merkle_proof(lic);

    (
        LicenseProverParameters {
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
