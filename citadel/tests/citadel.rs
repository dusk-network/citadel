// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_pki::SecretSpendKey;
use dusk_plonk::prelude::*;

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 16; // capacity required for the setup
const DEPTH: usize = 17; // depth of the n-ary Merkle tree
pub const ARITY: usize = 4; // arity of the Merkle tree

use zk_citadel_shared::{gadget, License, LicenseProverParameters, Request, Session, SessionCookie};
use zk_citadel::license::{compute_parameters, new_license, new_request};
use zk_citadel::state::State;

use rand_core::{CryptoRng, OsRng, RngCore};

#[derive(Default, Debug)]
pub struct Citadel {
    lpp: LicenseProverParameters<DEPTH, ARITY>,
    sc: SessionCookie,
}

impl Citadel {
    pub fn new(lpp: &LicenseProverParameters<DEPTH, ARITY>, sc: &SessionCookie) -> Self {
        Self { lpp: *lpp, sc: *sc }
    }
}

impl Circuit for Citadel {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadget::use_license(composer, &self.lpp, &self.sc)?;
        Ok(())
    }
}

fn compute_random_license<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (
    License,
    LicenseProverParameters<DEPTH, ARITY>,
    SessionCookie,
) {
    // Example values
    const USER_ATTRIBUTES: u64 = 112233445566778899u64;
    const CHALLENGE: u64 = 20221126u64;

    // These are the keys of the user
    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_spend_key();

    // These are the keys of the LP
    let ssk_lp = SecretSpendKey::random(rng);
    let psk_lp = ssk_lp.public_spend_key();

    // First, the user computes these values and requests a License
    let lsa = psk.gen_stealth_address(&JubJubScalar::random(rng));
    let k_lic = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(rng)); // TODO: address issue #35 and modify this
    let req = new_request(&psk_lp, &lsa, &k_lic, rng);

    // Second, the LP computes these values and grants the License
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let mut lic = new_license(&attr, &ssk_lp, &req, rng);
    let mut state = State::new(); // the compiler takes DEPTH from expected 'lpp' to return
    state.append_license(&mut lic);

    // Third, the user computes these values to generate the ZKP later on
    let vk = ssk.view_key();
    let lics = state.get_licenses(&vk);
    let c = JubJubScalar::from(CHALLENGE);
    let (lpp, sc) = compute_parameters(
        &ssk, &lics[0], &psk_lp, &psk_lp, &k_lic, &c, rng, &state,
    );

    (lic, lpp, sc)
}

#[test]
fn test_full_citadel() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let pk_lp = sc.pk_lp;
    let session = Session::from(&public_inputs);
    session.verify(sc, pk_lp);
}

#[test]
#[should_panic]
fn test_use_license_circuit_false_public_input() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    // set a false public input
    let mut false_public_inputs = public_inputs;
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    verifier
        .verify(&proof, &false_public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_verify_license_false_session_cookie() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, _verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (_proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    // set a false session cookie
    let sc_false = SessionCookie {
        pk_sp: sc.pk_sp,
        r: sc.r,
        session_id: sc.session_id,
        pk_lp: sc.pk_lp,
        attr: JubJubScalar::from(1234u64),
        c: sc.c,
        s_0: sc.s_0,
        s_1: sc.s_1,
        s_2: sc.s_2,
    };

    let pk_lp = sc.pk_lp;
    let session = Session::from(&public_inputs);
    session.verify(sc_false, pk_lp);
}
