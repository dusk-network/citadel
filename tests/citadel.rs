// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_merkle::poseidon::{Item, Tree};
use dusk_pki::SecretSpendKey;
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH: usize = 9; // depth of the n-ary Merkle tree
const ARITY: usize = 4; // arity of the Merkle tree

use zk_citadel::gadget;
use zk_citadel::license::{License, LicenseProverParameters, Request, Session, SessionCookie};

use rand_core::{CryptoRng, OsRng, RngCore};

#[macro_use]
extern crate lazy_static;

pub struct Keys {
    prover: Prover<Citadel>,
    verifier: Verifier<Citadel>,
}

lazy_static! {
    static ref KEYS: Keys = {
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
        let (prover, verifier) =
            Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

        Keys { prover, verifier }
    };
}

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
    let lsk = ssk.sk_r(&lsa);
    let k_lic =
        JubJubAffine::from(GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]));
    let req = Request::new(&psk_lp, &lsa, &k_lic, rng);

    // Second, the LP computes these values and grants the License
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let mut lic = License::new(&attr, &ssk_lp, &req, rng);

    let mut tree = Tree::<(), DEPTH, ARITY>::new();
    let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

    let item = Item {
        hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
        data: (),
    };

    lic.pos = 0;
    tree.insert(lic.pos, item);

    let merkle_proof = tree.opening(lic.pos).expect("Tree was read successfully");

    // Third, the user computes these values to generate the ZKP later on
    let c = JubJubScalar::from(CHALLENGE);
    let (lpp, sc) = LicenseProverParameters::compute_parameters(
        &ssk,
        &lic,
        &psk_lp,
        &psk_lp,
        &k_lic,
        &c,
        rng,
        merkle_proof,
    );

    (lic, lpp, sc)
}

#[test]
fn test_full_citadel() {
    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = KEYS
        .prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    KEYS.verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let pk_lp = sc.pk_lp;
    let session = Session::from(&public_inputs);
    session.verify(sc, pk_lp);
}

#[test]
#[should_panic]
fn test_use_license_circuit_false_public_input() {
    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = KEYS
        .prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    // set a false public input
    let mut false_public_inputs = public_inputs;
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    KEYS.verifier
        .verify(&proof, &false_public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_verify_license_false_session_cookie() {
    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (_proof, public_inputs) = KEYS
        .prover
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
