// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR, GENERATOR_NUMS};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, HashGadget};
use jubjub_schnorr::gadgets;

use poseidon_merkle::zk::opening_gadget;

use crate::license::{CitadelProverParameters, SessionCookie};

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

pub fn use_license_citadel<const DEPTH: usize>(
    composer: &mut Composer,
    cpp: &CitadelProverParameters<DEPTH>,
    sc: &SessionCookie,
) -> Result<(), Error> {
    // APPEND THE LICENSE PUBLIC KEYS OF THE USER
    let lpk = composer.append_point(cpp.lpk);
    let lpk_p = composer.append_point(cpp.lpk_p);

    // COMPUTE THE SESSION ID
    let c = composer.append_witness(sc.c);
    let session_id_pi = composer.append_public(sc.session_id);
    let session_id = HashGadget::digest(composer, Domain::Other, &[*lpk_p.x(), *lpk_p.y(), c]);

    composer.assert_equal(session_id[0], session_id_pi);

    // VERIFY THE LICENSE SIGNATURE
    let sig_lic_u = composer.append_witness(*cpp.sig_lic.u());
    let sig_lic_r = composer.append_point(cpp.sig_lic.R());
    let pk_lp = composer.append_point(sc.pk_lp);
    let attr_data = composer.append_witness(sc.attr_data);

    let message = HashGadget::digest(composer, Domain::Other, &[*lpk.x(), *lpk.y(), attr_data]);
    gadgets::verify_signature(composer, sig_lic_u, sig_lic_r, pk_lp, message[0])?;

    // VERIFY THE SESSION HASH SIGNATURE
    let sig_session_hash_u = composer.append_witness(*cpp.sig_session_hash.u());
    let sig_session_hash_r = composer.append_point(cpp.sig_session_hash.R());
    let sig_session_hash_r_p = composer.append_point(cpp.sig_session_hash.R_prime());
    let session_hash = composer.append_public(cpp.session_hash);

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
    let com_0_pi = composer.append_public(cpp.com_0);
    let com_0 = HashGadget::digest(composer, Domain::Other, &[*pk_lp.x(), *pk_lp.y(), s_0]);

    composer.assert_equal(com_0[0], com_0_pi);

    // COMMIT TO THE ATTRIBUTE DATA
    let s_1 = composer.append_witness(sc.s_1);
    let pc_1_1 = composer.component_mul_generator(attr_data, GENERATOR);
    let pc_1_2 = composer.component_mul_generator(s_1, GENERATOR_NUMS);
    let com_1 = composer.component_add_point(pc_1_1.unwrap(), pc_1_2.unwrap());

    composer.assert_equal_public_point(com_1, cpp.com_1);

    // COMMIT TO THE CHALLENGE
    let s_2 = composer.append_witness(sc.s_2);
    let pc_2_1 = composer.component_mul_generator(c, GENERATOR);
    let pc_2_2 = composer.component_mul_generator(s_2, GENERATOR_NUMS);
    let com_2 = composer.component_add_point(pc_2_1.unwrap(), pc_2_2.unwrap());

    composer.assert_equal_public_point(com_2, cpp.com_2);

    // COMPUTE THE HASH OF THE LICENSE
    let license_hash = HashGadget::digest(composer, Domain::Other, &[*lpk.x(), *lpk.y()]);

    // VERIFY THE MERKLE PROOF
    let root_pi = composer.append_public(cpp.merkle_proof.root().hash);
    let root = opening_gadget(composer, &cpp.merkle_proof, license_hash[0]);
    composer.assert_equal(root, root_pi);

    Ok(())
}
