// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use zk_citadel::gadget;
use zk_citadel::license::{License, LicenseProverParameters, SessionCookie};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 15; // capacity required for the setup

#[derive(Default, Debug)]
pub struct Citadel {
    lpp: LicenseProverParameters,
    sc: SessionCookie,
}

impl Citadel {
    pub fn new(lpp: LicenseProverParameters, sc: SessionCookie) -> Self {
        Self { lpp, sc }
    }
}

impl Circuit for Citadel {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadget::nullify_license(composer, &self.lpp, &self.sc)?;

        unsafe {
            CONSTRAINTS = composer.constraints();
        }

        Ok(())
    }
}

fn citadel_benchmark(c: &mut Criterion) {
    // Compute the setup
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    // Benchmark the prover
    let (_license, lpp, sc) = License::random(&mut OsRng);

    unsafe {
        let log = &format!("Citadel Prover ({} constraints)", CONSTRAINTS);
        c.bench_function(log, |b| {
            b.iter(|| {
                prover
                    .prove(&mut OsRng, &Citadel::new(lpp.clone(), sc.clone()))
                    .expect("failed to prove")
            })
        });

        // Benchmark the verifier
        let (proof, public_inputs) = prover
            .prove(&mut OsRng, &Citadel::new(lpp, sc))
            .expect("failed to prove");
        let log = &format!("Citadel Verifier ({} constraints)", CONSTRAINTS);
        c.bench_function(log, |b| {
            b.iter(|| {
                verifier
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
