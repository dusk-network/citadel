// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use phoenix_core::{PublicKey, SecretKey};
use poseidon_merkle::{Item, Tree};
use rand_core::OsRng;

use zk_citadel::{circuit, gadgets, License, Request, Session, SessionCookie};

static LABEL: &[u8; 12] = b"dusk-network";

// Example values
const ATTRIBUTE_DATA: u64 = 112233445566778899u64;
const CHALLENGE: u64 = 20221126u64;

#[test]
fn test_full_citadel() {
    // These are the keys of the user
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    // These are the keys of the LP
    let sk_lp = SecretKey::random(&mut OsRng);
    let pk_lp = PublicKey::from(&sk_lp);

    // Now we generate the ProverKey and VerifierKey for the license circuit
    let pp = PublicParameters::setup(1 << circuit::CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) = Compiler::compile::<circuit::LicenseCircuit>(&pp, LABEL)
        .expect("failed to compile circuit");

    // To use Citadel, the user first computes these values and requests a License
    let lsa = pk.gen_stealth_address(&JubJubScalar::random(&mut OsRng));
    let lsk = sk.gen_note_sk(&lsa);
    let k_lic = JubJubAffine::from(
        GENERATOR_EXTENDED * Hash::digest_truncated(Domain::Other, &[(*lsk.as_ref()).into()])[0],
    );
    let req = Request::new(&pk_lp, &lsa, &k_lic, &mut OsRng).expect("Request correctly computed.");

    // Second, the LP computes these values and grants the License on-chain
    let attr_data = JubJubScalar::from(ATTRIBUTE_DATA);
    let lic =
        License::new(&attr_data, &sk_lp, &req, &mut OsRng).expect("License correctly computed.");

    let mut tree = Tree::<(), { circuit::DEPTH }>::new();
    let lpk = JubJubAffine::from(lic.lsa.note_pk().as_ref());

    let item = Item {
        hash: Hash::digest(Domain::Other, &[lpk.get_u(), lpk.get_v()])[0],
        data: (),
    };

    let pos = 0;
    tree.insert(pos, item);

    // Now, the user can use the license
    let pk_sp = pk_lp; // in this case, LP = SP
    let merkle_proof = tree.opening(pos).expect("Tree was read successfully");

    let c = JubJubScalar::from(CHALLENGE);
    let (gp, sc) = gadgets::GadgetParameters::compute_parameters(
        &sk,
        &lic,
        &pk_lp,
        &pk_sp,
        &c,
        &mut OsRng,
        merkle_proof,
    )
    .expect("Parameters computed correctly.");

    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &circuit::LicenseCircuit::new(&gp, &sc))
        .expect("failed to prove");

    // The network verifies the proof received from the user
    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    // We also test verifying the proof with a false public input
    let mut false_public_inputs = public_inputs.clone();
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    // So, this should fail
    assert!(verifier.verify(&proof, &false_public_inputs).is_err());

    // Now, the SP can verify a received session cookie
    assert_eq!(JubJubAffine::from(pk_lp.A()), sc.pk_lp);
    assert_eq!(JubJubAffine::from(pk_sp.A()), sc.pk_sp);
    assert_eq!(c, sc.c);
    assert_eq!(attr_data, sc.attr_data);

    // Finally, the SP can verify a session, related by the session_id
    let session = Session::from(&public_inputs);
    assert_eq!(session.session_id, sc.session_id);
    session.verify(sc).expect("Session verified correctly.");

    // We also test setting a false session cookie
    let sc_false = SessionCookie {
        pk_sp: sc.pk_sp,
        r: sc.r,
        session_id: sc.session_id,
        pk_lp: sc.pk_lp,
        attr_data: JubJubScalar::from(1234u64),
        c: sc.c,
        s_0: sc.s_0,
        s_1: sc.s_1,
        s_2: sc.s_2,
    };

    // So, this should be an error
    assert!(session.verify(sc_false).is_err());
}
