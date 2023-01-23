// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR, GENERATOR_NUMS};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use dusk_poseidon::tree::{self};
use dusk_schnorr::gadgets;

use crate::license::License;

const DEPTH: usize = 17; // depth of the 4-ary Merkle tree

// out of this circuit, the generated public inputs vector collects
// these values in that particular order:
//
// public_inputs[0]: nullifier_lic
// public_inputs[1]: tx_hash
// public_inputs[2]: com_0
// public_inputs[3]: com_1.x
// public_inputs[4]: com_1.y
// public_inputs[5]: com_2.x
// public_inputs[6]: com_2.y
// public_inputs[7]: root

pub fn nullify_license<C: Composer>(composer: &mut C, license: &License) -> Result<(), Error> {
    // APPEND THE NOTE PUBLIC KEYS OF THE USER
    let npk_user = composer.append_point(license.npk_user);
    let npk_user_p = composer.append_point(license.npk_user_p);

    // COMPUTE THE LICENSE NULLIFIER
    let c = composer.append_witness(license.c);
    let nullifier_lic_pi = composer.append_public(license.nullifier_lic);
    let nullifier_lic = sponge::gadget(composer, &[*npk_user_p.x(), *npk_user_p.y(), c]);

    composer.assert_equal(nullifier_lic, nullifier_lic_pi);

    // VERIFY THE SIGNATURES
    let (sig_lic_u, sig_lic_r) = license.sig_lic.to_witness(composer);
    let pk_sp = composer.append_point(license.pk_sp);
    let attr = composer.append_witness(license.attr);

    let message = sponge::gadget(composer, &[*npk_user.x(), *npk_user.y(), attr]);
    gadgets::single_key_verify(composer, sig_lic_u, sig_lic_r, pk_sp, message)?;

    let (sig_tx_u, sig_tx_r, sig_tx_r_p) = license.sig_tx.to_witness(composer);
    let tx_hash = composer.append_public(license.tx_hash);
    gadgets::double_key_verify(
        composer, sig_tx_u, sig_tx_r, sig_tx_r_p, npk_user, npk_user_p, tx_hash,
    )?;

    // COMMIT TO THE PK_SP USING A HASH FUNCTION
    let s_0 = composer.append_witness(license.s_0);
    let com_0_pi = composer.append_public(license.com_0);
    let com_0 = sponge::gadget(composer, &[*pk_sp.x(), *pk_sp.y(), s_0]);

    composer.assert_equal(com_0, com_0_pi);

    // COMMIT TO THE ATTRIBUTE
    let s_1 = composer.append_witness(license.s_1);
    let pc_1_1 = composer.component_mul_generator(attr, GENERATOR);
    let pc_1_2 = composer.component_mul_generator(s_1, GENERATOR_NUMS);
    let com_1 = composer.component_add_point(pc_1_1.unwrap(), pc_1_2.unwrap());

    composer.assert_equal_public_point(com_1, license.com_1);

    // COMMIT TO THE CHALLENGE
    let s_2 = composer.append_witness(license.s_2);
    let pc_2_1 = composer.component_mul_generator(c, GENERATOR);
    let pc_2_2 = composer.component_mul_generator(s_2, GENERATOR_NUMS);
    let com_2 = composer.component_add_point(pc_2_1.unwrap(), pc_2_2.unwrap());

    composer.assert_equal_public_point(com_2, license.com_2);

    // COMPUTE THE HASH OF THE NOTE
    let note_type = composer.append_witness(license.note_type);
    let enc = composer.append_witness(license.enc);
    let nonce = composer.append_witness(license.nonce);
    let r_user = composer.append_point(license.r_user);
    let pos = composer.append_witness(license.pos);

    let note_hash = sponge::gadget(
        composer,
        &[
            note_type,
            enc,
            nonce,
            *r_user.x(),
            *r_user.y(),
            *npk_user.x(),
            *npk_user.y(),
            pos,
        ],
    );

    // VERIFY THE MERKLE PROOF
    let root_pi = composer.append_public(*license.merkle_proof.root());
    let root = tree::merkle_opening::<C, DEPTH>(composer, &license.merkle_proof, note_hash);

    composer.assert_equal(root, root_pi);

    Ok(())
}
