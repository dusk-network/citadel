// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_merkle::poseidon::{Item, Tree};
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;

use zk_citadel::gadgets;
use zk_citadel::license::{
    CitadelProverParameters, License, Request, SessionCookie, ShelterProverParameters,
};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::{CryptoRng, OsRng, RngCore};

static mut CONSTRAINTS_CITADEL: usize = 0;
static mut CONSTRAINTS_SHELTER: usize = 0;

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH_CITADEL: usize = 17; // depth of the n-ary Merkle tree
const DEPTH_SHELTER: usize = 9; // depth of the n-ary Merkle tree
const ARITY: usize = 4; // arity of the Merkle tree

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

    citadel_prover: Prover<Citadel>,
    citadel_verifier: Verifier<Citadel>,

    shelter_prover: Prover<Shelter>,
    shelter_verifier: Verifier<Shelter>,
}

lazy_static! {
    static ref KEYS: Keys = {
        // These are the keys of the user
        let ssk = SecretSpendKey::random(&mut OsRng);
        let psk = ssk.public_spend_key();

        // These are the keys of the LP
        let ssk_lp = SecretSpendKey::random(&mut OsRng);
        let psk_lp = ssk_lp.public_spend_key();

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
    cpp: CitadelProverParameters<DEPTH_CITADEL, ARITY>,
    sc: SessionCookie,
}

impl Citadel {
    pub fn new(cpp: &CitadelProverParameters<DEPTH_CITADEL, ARITY>, sc: &SessionCookie) -> Self {
        Self { cpp: *cpp, sc: *sc }
    }
}

impl Circuit for Citadel {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadgets::use_license_citadel(composer, &self.cpp, &self.sc)?;
        unsafe {
            CONSTRAINTS_CITADEL = composer.constraints();
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct Shelter {
    spp: ShelterProverParameters<DEPTH_SHELTER, ARITY>,
}

impl Shelter {
    pub fn new(spp: &ShelterProverParameters<DEPTH_SHELTER, ARITY>) -> Self {
        Self { spp: *spp }
    }
}

impl Circuit for Shelter {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadgets::use_license_shelter(composer, &self.spp)?;
        unsafe {
            CONSTRAINTS_SHELTER = composer.constraints();
        }
        Ok(())
    }
}

fn compute_random_license<R: RngCore + CryptoRng>(rng: &mut R) -> License {
    // First, the user computes these values and requests a License
    let lsa = KEYS.psk.gen_stealth_address(&JubJubScalar::random(rng));
    let lsk = KEYS.ssk.sk_r(&lsa);
    let k_lic =
        JubJubAffine::from(GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]));
    let req = Request::new(&KEYS.psk_lp, &lsa, &k_lic, rng);

    // Second, the LP computes these values and grants the License
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let mut lic = License::new(&attr, &KEYS.ssk_lp, &req, rng);
    lic.pos = 0;

    lic
}

fn shelter_benchmark(crit: &mut Criterion) {
    let lic = compute_random_license(&mut OsRng);

    let mut tree = Tree::<(), DEPTH_SHELTER, ARITY>::new();
    let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

    let item = Item {
        hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
        data: (),
    };

    tree.insert(lic.pos, item);

    let merkle_proof = tree.opening(lic.pos).expect("Tree was read successfully");

    let c = JubJubScalar::from(CHALLENGE);
    let spp = ShelterProverParameters::compute_parameters(
        &KEYS.ssk,
        &lic,
        &KEYS.psk_lp,
        &c,
        merkle_proof,
    );

    unsafe {
        let log = &format!("Shelter Prover ({} constraints)", CONSTRAINTS_SHELTER);
        crit.bench_function(log, |b| {
            b.iter(|| {
                KEYS.shelter_prover
                    .prove(&mut OsRng, &Shelter::new(&spp))
                    .expect("failed to prove")
            })
        });

        // Benchmark the verifier
        let (proof, public_inputs) = KEYS
            .shelter_prover
            .prove(&mut OsRng, &Shelter::new(&spp))
            .expect("failed to prove");
        let log = &format!("Shelter Verifier ({} constraints)", CONSTRAINTS_SHELTER);
        crit.bench_function(log, |b| {
            b.iter(|| {
                KEYS.shelter_verifier
                    .verify(&proof, &public_inputs)
                    .expect("failed to verify proof")
            })
        });
    }
}

fn citadel_benchmark(crit: &mut Criterion) {
    let lic = compute_random_license(&mut OsRng);

    let mut tree = Tree::<(), DEPTH_CITADEL, ARITY>::new();
    let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

    let item = Item {
        hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
        data: (),
    };

    tree.insert(lic.pos, item);

    let merkle_proof = tree.opening(lic.pos).expect("Tree was read successfully");

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

    unsafe {
        let log = &format!("Citadel Prover ({} constraints)", CONSTRAINTS_CITADEL);
        crit.bench_function(log, |b| {
            b.iter(|| {
                KEYS.citadel_prover
                    .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
                    .expect("failed to prove")
            })
        });

        // Benchmark the verifier
        let (proof, public_inputs) = KEYS
            .citadel_prover
            .prove(&mut OsRng, &Citadel::new(&cpp, &sc))
            .expect("failed to prove");
        let log = &format!("Citadel Verifier ({} constraints)", CONSTRAINTS_CITADEL);
        crit.bench_function(log, |b| {
            b.iter(|| {
                KEYS.citadel_verifier
                    .verify(&proof, &public_inputs)
                    .expect("failed to verify proof")
            })
        });
    }
}

criterion_group! {
    name = citadel;
    config = Criterion::default().sample_size(10);
    targets = shelter_benchmark, citadel_benchmark
}
criterion_main!(citadel);
