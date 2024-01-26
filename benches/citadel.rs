// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use phoenix_core::{PublicKey as PublicSpendKey, SecretKey as SecretSpendKey};

use zk_citadel::gadgets;
use zk_citadel::license::{CitadelProverParameters, SessionCookie};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use zk_citadel::utils::CitadelUtils;

static mut CONSTRAINTS_CITADEL: usize = 0;

static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 15; // capacity required for the setup
const DEPTH_CITADEL: usize = 17; // depth of the n-ary Merkle tree
const ARITY: usize = 4; // arity of the Merkle tree

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

        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let (citadel_prover, citadel_verifier) =
            Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

        Keys { ssk, psk, ssk_lp, psk_lp, citadel_prover, citadel_verifier  }
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
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        gadgets::use_license_citadel(composer, &self.cpp, &self.sc)?;
        unsafe {
            CONSTRAINTS_CITADEL = composer.constraints();
        }
        Ok(())
    }
}

fn citadel_benchmark(crit: &mut Criterion) {
    let (lic, merkle_proof) = CitadelUtils::compute_random_license::<OsRng, DEPTH_CITADEL, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk,
        KEYS.ssk_lp,
        KEYS.psk_lp,
    );

    let (cpp, sc) = CitadelUtils::compute_citadel_parameters::<OsRng, DEPTH_CITADEL, ARITY>(
        &mut OsRng,
        KEYS.ssk,
        KEYS.psk_lp,
        &lic,
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
    targets = citadel_benchmark
}
criterion_main!(citadel);
