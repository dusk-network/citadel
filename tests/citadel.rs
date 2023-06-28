// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;

use poseidon_merkle::{Item, Opening, Tree};

use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH: usize = 9; // depth of the n-ary Merkle tree
const ARITY: usize = 4; // arity of the Merkle tree

use zk_citadel::gadgets;
use zk_citadel::license::{
    CitadelProverParameters, License, Request, Session, SessionCookie, ShelterProverParameters,
};

use rand_core::{CryptoRng, OsRng, RngCore};

#[macro_use]
extern crate lazy_static;

// Example values
const USER_ATTRIBUTES: u64 = 112233445566778899u64;
const CHALLENGE: u64 = 20221126u64;

pub struct Keys {
    ssk: SecretSpendKey,
    psk: PublicSpendKey,

    ssk_lp: SecretSpendKey,
    psk_lp: PublicSpendKey,

    citadel_prover: Prover,
    citadel_verifier: Verifier,

    shelter_prover: Prover,
    shelter_verifier: Verifier,
}

lazy_static! {
    static ref KEYS: Keys = {
        // These are the keys of the user
        let ssk = SecretSpendKey::random(&mut OsRng);
        let psk = ssk.public_spend_key();

        // These are the keys of the LP
        let ssk_lp = SecretSpendKey::random(&mut OsRng);
        let psk_lp = ssk_lp.public_spend_key();

        // Now we generate the ProverKey and VerifierKey for both Citadel and Shelter
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let (citadel_prover, citadel_verifier) =
            Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

        let (shelter_prover, shelter_verifier) =
            Compiler::compile::<Shelter>(&pp, LABEL).expect("failed to compile circuit");

        Keys { ssk, psk, ssk_lp, psk_lp, citadel_prover, citadel_verifier, shelter_prover, shelter_verifier }
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
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadgets::use_license_citadel(composer, &self.cpp, &self.sc)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct Shelter {
    spp: ShelterProverParameters<DEPTH, ARITY>,
}

impl Shelter {
    pub fn new(spp: &ShelterProverParameters<DEPTH, ARITY>) -> Self {
        Self { spp: *spp }
    }
}

impl Circuit for Shelter {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadgets::use_license_shelter(composer, &self.spp)?;
        Ok(())
    }
}

fn compute_random_license<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (License, Opening<(), DEPTH, ARITY>) {
    // First, the user computes these values and requests a License
    let lsa = KEYS.psk.gen_stealth_address(&JubJubScalar::random(rng));
    let lsk = KEYS.ssk.sk_r(&lsa);
    let k_lic =
        JubJubAffine::from(GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]));
    let req = Request::new(&KEYS.psk_lp, &lsa, &k_lic, rng);

    // Second, the LP computes these values and grants the License
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let mut lic = License::new(&attr, &KEYS.ssk_lp, &req, rng);

    let mut tree = Tree::<(), DEPTH, ARITY>::new();
    let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

    let item = Item {
        hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
        data: (),
    };

    lic.pos = 0;
    tree.insert(lic.pos, item);

    let merkle_proof = tree.opening(lic.pos).expect("Tree was read successfully");

    (lic, merkle_proof)
}

#[test]
fn test_full_citadel() {
    // We generate a random license and merkle proof for testing
    let (lic, merkle_proof) = compute_random_license(&mut OsRng);

    // The user computes these values to use a license
    let c = JubJubScalar::from(CHALLENGE);
    let (cpp, sc) = CitadelProverParameters::compute_parameters(
        &KEYS.ssk,
        &lic,
        &KEYS.psk_lp,
        &KEYS.psk_lp,
        &c,
        &mut OsRng,
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
    let session = Session::from(&public_inputs);
    session.verify(sc, pk_lp);
}

#[test]
fn test_full_shelter() {
    // We generate a random license and merkle proof for testing
    let (lic, merkle_proof) = compute_random_license(&mut OsRng);

    // The user computes these values to use a license
    let c = JubJubScalar::from(CHALLENGE);
    let spp = ShelterProverParameters::compute_parameters(
        &KEYS.ssk,
        &lic,
        &KEYS.psk_lp,
        &c,
        merkle_proof,
    );

    // Then, the user generates the proof
    let (proof, public_inputs) = KEYS
        .shelter_prover
        .prove(&mut OsRng, &Shelter::new(&spp))
        .expect("failed to prove");

    // After receiving the proof, the SP verifies it
    KEYS.shelter_verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_citadel_false_public_input() {
    let (lic, merkle_proof) = compute_random_license(&mut OsRng);

    let c = JubJubScalar::from(CHALLENGE);
    let (cpp, sc) = CitadelProverParameters::compute_parameters(
        &KEYS.ssk,
        &lic,
        &KEYS.psk_lp,
        &KEYS.psk_lp,
        &c,
        &mut OsRng,
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
fn test_shelter_false_public_input() {
    let (lic, merkle_proof) = compute_random_license(&mut OsRng);

    let c = JubJubScalar::from(CHALLENGE);
    let spp = ShelterProverParameters::compute_parameters(
        &KEYS.ssk,
        &lic,
        &KEYS.psk_lp,
        &c,
        merkle_proof,
    );

    let (proof, public_inputs) = KEYS
        .shelter_prover
        .prove(&mut OsRng, &Shelter::new(&spp))
        .expect("failed to prove");

    // set a false public input
    let mut false_public_inputs = public_inputs;
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    KEYS.shelter_verifier
        .verify(&proof, &false_public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_citadel_false_session_cookie() {
    let (lic, merkle_proof) = compute_random_license(&mut OsRng);

    let c = JubJubScalar::from(CHALLENGE);
    let (cpp, sc) = CitadelProverParameters::compute_parameters(
        &KEYS.ssk,
        &lic,
        &KEYS.psk_lp,
        &KEYS.psk_lp,
        &c,
        &mut OsRng,
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
