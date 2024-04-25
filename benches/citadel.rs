// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use ff::Field;
use phoenix_core::{PublicKey, SecretKey};
use poseidon_merkle::{Item, Opening, Tree};

use zk_citadel::gadgets;
use zk_citadel::license::{CitadelProverParameters, License, Request, SessionCookie};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

static mut CONSTRAINTS_CITADEL: usize = 0;

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH: usize = 17; // depth of the n-ary Merkle tree
const ARITY: usize = 4; // arity of the Merkle tree

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
) -> (License, Opening<(), DEPTH, ARITY>) {
    let pk = PublicKey::from(sk);

    // First, the user computes these values and requests a License
    let lsa = pk.gen_stealth_address(&JubJubScalar::random(&mut *rng));
    let lsk = sk.gen_note_sk(&lsa);
    let k_lic =
        JubJubAffine::from(GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]));
    let req = Request::new(pk_lp, &lsa, &k_lic, rng);

    // Second, the LP computes these values and grants the License
    let attr_data = JubJubScalar::from(ATTRIBUTE_DATA);
    let lic = License::new(&attr_data, sk_lp, &req, rng);

    let mut tree = Tree::<(), DEPTH, ARITY>::new();
    let lpk = JubJubAffine::from(lic.lsa.note_pk().as_ref());

    let item = Item {
        hash: sponge::hash(&[lpk.get_u(), lpk.get_v()]),
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
    merkle_proof: Opening<(), DEPTH, ARITY>,
) -> (CitadelProverParameters<DEPTH, ARITY>, SessionCookie) {
    let c = JubJubScalar::from(CHALLENGE);
    let (cpp, sc) =
        CitadelProverParameters::compute_parameters(sk, lic, pk_lp, pk_lp, &c, rng, merkle_proof);
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
        unsafe {
            CONSTRAINTS_CITADEL = composer.constraints();
        }
        Ok(())
    }
}

fn citadel_benchmark(crit: &mut Criterion) {
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

    unsafe {
        let log = &format!("Citadel Prover ({} constraints)", CONSTRAINTS_CITADEL);
        crit.bench_function(log, |b| {
            b.iter(|| {
                TEST_KEYS
                    .citadel_prover
                    .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
                    .expect("failed to prove")
            })
        });

        // Benchmark the verifier
        let (proof, public_inputs) = TEST_KEYS
            .citadel_prover
            .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
            .expect("failed to prove");
        let log = &format!("Citadel Verifier ({} constraints)", CONSTRAINTS_CITADEL);
        crit.bench_function(log, |b| {
            b.iter(|| {
                TEST_KEYS
                    .citadel_verifier
                    .verify(&proof, &public_inputs)
                    .expect("failed to verify proof")
            })
        });
    }
}

criterion_group! {
    name = citadel;
    config = Criterion::default().sample_size(10);
    targets = citadel_benchmark
}
criterion_main!(citadel);
