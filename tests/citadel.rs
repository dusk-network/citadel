// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use ff::Field;
use phoenix_core::{PublicKey as PublicSpendKey, SecretKey as SecretSpendKey};

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH: usize = 9; // depth of the n-ary Merkle tree
const ARITY: usize = 4; // arity of the Merkle tree

use zk_citadel::gadgets;
use zk_citadel::license::{CitadelProverParameters, Session, SessionCookie};

use rand_core::OsRng;
use zk_citadel::utils::CitadelUtils;

#[macro_use]
extern crate lazy_static;

pub struct Keys {
    ssk: SecretSpendKey,
    psk: PublicSpendKey,

    ssk_lp: SecretSpendKey,
    psk_lp: PublicSpendKey,

    citadel_prover: Prover,
    citadel_verifier: Verifier,
}

lazy_static! {
    static ref KEYS: Keys = {
        // These are the keys of the user
        let ssk = SecretSpendKey::random(&mut OsRng);
        let psk = PublicSpendKey::from(ssk);

        // These are the keys of the LP
        let ssk_lp = SecretSpendKey::random(&mut OsRng);
        let psk_lp = PublicSpendKey::from(ssk_lp);

        // Now we generate the ProverKey and VerifierKey for Citadel
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let (citadel_prover, citadel_verifier) =
            Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

        Keys { ssk, psk, ssk_lp, psk_lp, citadel_prover, citadel_verifier }
    };
}

#[derive(Default, Debug)]
pub struct Citadel {
    cpp: CitadelProverParameters<DEPTH, ARITY>,
    sc: SessionCookie,
}

impl Citadel {
    pub fn new(cpp: &CitadelProverParameters<DEPTH, ARITY>, sc: &SessionCookie) -> Self {
        Self { cpp: *cpp, sc: *sc }
    }
}

impl Circuit for Citadel {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        gadgets::use_license_citadel(composer, &self.cpp, &self.sc)?;
        Ok(())
    }
}

#[test]
fn test_full_citadel() {
    let (lic, merkle_proof) = CitadelUtils::compute_random_license::<OsRng, DEPTH, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk,
        KEYS.ssk_lp,
        KEYS.psk_lp,
    );

    let (cpp, sc) = CitadelUtils::compute_citadel_parameters::<OsRng, DEPTH, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk_lp,
        &lic,
        merkle_proof,
    );

    // Then, the user generates the proof
    let (proof, public_inputs) = KEYS
        .citadel_prover
        .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
        .expect("failed to prove");

    // After receiving the proof, the network verifies it
    KEYS.citadel_verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    // Finally, the SP can verify a session
    let pk_lp = sc.pk_lp;
    let pk_sp = sc.pk_sp;
    let session = Session::from(&public_inputs);
    session.verify(sc, pk_lp, pk_sp);
}

#[test]
#[should_panic]
fn test_citadel_false_public_input() {
    let (lic, merkle_proof) = CitadelUtils::compute_random_license::<OsRng, DEPTH, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk,
        KEYS.ssk_lp,
        KEYS.psk_lp,
    );

    let (cpp, sc) = CitadelUtils::compute_citadel_parameters::<OsRng, DEPTH, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk_lp,
        &lic,
        merkle_proof,
    );

    let (proof, public_inputs) = KEYS
        .citadel_prover
        .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
        .expect("failed to prove");

    // set a false public input
    let mut false_public_inputs = public_inputs;
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    KEYS.citadel_verifier
        .verify(&proof, &false_public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_citadel_false_session_cookie() {
    let (lic, merkle_proof) = CitadelUtils::compute_random_license::<OsRng, DEPTH, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk,
        KEYS.ssk_lp,
        KEYS.psk_lp,
    );

    let (cpp, sc) = CitadelUtils::compute_citadel_parameters::<OsRng, DEPTH, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk_lp,
        &lic,
        merkle_proof,
    );

    let (_proof, public_inputs) = KEYS
        .citadel_prover
        .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
        .expect("failed to prove");

    // set a false session cookie
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

    let pk_lp = sc.pk_lp;
    let pk_sp = sc.pk_sp;
    let session = Session::from(&public_inputs);
    session.verify(sc_false, pk_lp, pk_sp);
}
