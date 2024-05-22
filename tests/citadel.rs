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
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::OsRng;

use zk_citadel::gadgets;
use zk_citadel::license::{CitadelProverParameters, License, Request, Session, SessionCookie};

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH: usize = 9; // depth of the n-ary Merkle tree

// Example values
const ATTRIBUTE_DATA: u64 = 112233445566778899u64;
const CHALLENGE: u64 = 20221126u64;

#[macro_use]
extern crate lazy_static;

fn compute_random_license(
    rng: &mut OsRng,
    sk: &SecretKey,
    sk_lp: &SecretKey,
    pk_lp: &PublicKey,
) -> (License, Opening<(), DEPTH>) {
    let pk = PublicKey::from(sk);

    // First, the user computes these values and requests a License
    let lsa = pk.gen_stealth_address(&JubJubScalar::random(&mut *rng));
    let lsk = sk.gen_note_sk(&lsa);
    let k_lic = JubJubAffine::from(
        GENERATOR_EXTENDED * Hash::digest_truncated(Domain::Other, &[(*lsk.as_ref()).into()])[0],
    );
    let req = Request::new(pk_lp, &lsa, &k_lic, rng).expect("Request correctly computed.");

    // Second, the LP computes these values and grants the License
    let attr_data = JubJubScalar::from(ATTRIBUTE_DATA);
    let lic = License::new(&attr_data, sk_lp, &req, rng).expect("License correctly computed.");

    let mut tree = Tree::<(), DEPTH>::new();
    let lpk = JubJubAffine::from(lic.lsa.note_pk().as_ref());

    let item = Item {
        hash: Hash::digest(Domain::Other, &[lpk.get_u(), lpk.get_v()])[0],
        data: (),
    };

    let pos = 0;
    tree.insert(pos, item);

    let merkle_proof = tree.opening(pos).expect("Tree was read successfully");

    (lic, merkle_proof)
}

fn compute_citadel_parameters(
    rng: &mut OsRng,
    sk: &SecretKey,
    pk_lp: &PublicKey,
    lic: &License,
    merkle_proof: Opening<(), DEPTH>,
) -> (CitadelProverParameters<DEPTH>, SessionCookie) {
    let c = JubJubScalar::from(CHALLENGE);
    let (cpp, sc) =
        CitadelProverParameters::compute_parameters(sk, lic, pk_lp, pk_lp, &c, rng, merkle_proof)
            .expect("Parameters computed correctly.");
    (cpp, sc)
}

struct Keys {
    sk: SecretKey,

    sk_lp: SecretKey,
    pk_lp: PublicKey,

    citadel_prover: Prover,
    citadel_verifier: Verifier,
}

lazy_static! {
    static ref TEST_KEYS: Keys = {
        // These are the keys of the user
        let sk = SecretKey::random(&mut OsRng);

        // These are the keys of the LP
        let sk_lp = SecretKey::random(&mut OsRng);
        let pk_lp = PublicKey::from(&sk_lp);

        // Now we generate the ProverKey and VerifierKey for Citadel
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let (citadel_prover, citadel_verifier) =
            Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

        Keys { sk, sk_lp, pk_lp, citadel_prover, citadel_verifier }
    };
}

#[derive(Default, Debug)]
pub struct Citadel {
    cpp: CitadelProverParameters<DEPTH>,
    sc: SessionCookie,
}

impl Citadel {
    pub fn new(cpp: &CitadelProverParameters<DEPTH>, sc: &SessionCookie) -> Self {
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
    let (lic, merkle_proof) = compute_random_license(
        &mut OsRng,
        &TEST_KEYS.sk,
        &TEST_KEYS.sk_lp,
        &TEST_KEYS.pk_lp,
    );

    let (cpp, sc) = compute_citadel_parameters(
        &mut OsRng,
        &TEST_KEYS.sk,
        &TEST_KEYS.pk_lp,
        &lic,
        merkle_proof,
    );

    // Then, the user generates the proof
    let (proof, public_inputs) = TEST_KEYS
        .citadel_prover
        .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
        .expect("failed to prove");

    // After receiving the proof, the network verifies it
    TEST_KEYS
        .citadel_verifier
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
    let (lic, merkle_proof) = compute_random_license(
        &mut OsRng,
        &TEST_KEYS.sk,
        &TEST_KEYS.sk_lp,
        &TEST_KEYS.pk_lp,
    );

    let (cpp, sc) = compute_citadel_parameters(
        &mut OsRng,
        &TEST_KEYS.sk,
        &TEST_KEYS.pk_lp,
        &lic,
        merkle_proof,
    );

    let (proof, public_inputs) = TEST_KEYS
        .citadel_prover
        .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
        .expect("failed to prove");

    // set a false public input
    let mut false_public_inputs = public_inputs;
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    TEST_KEYS
        .citadel_verifier
        .verify(&proof, &false_public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_citadel_false_session_cookie() {
    let (lic, merkle_proof) = compute_random_license(
        &mut OsRng,
        &TEST_KEYS.sk,
        &TEST_KEYS.sk_lp,
        &TEST_KEYS.pk_lp,
    );

    let (cpp, sc) = compute_citadel_parameters(
        &mut OsRng,
        &TEST_KEYS.sk,
        &TEST_KEYS.pk_lp,
        &lic,
        merkle_proof,
    );

    let (_proof, public_inputs) = TEST_KEYS
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
