// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_pki::SecretSpendKey;
use dusk_plonk::prelude::*;

use zk_citadel::gadget;
use zk_citadel::license::{License, LicenseProverParameters, SessionCookie};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::{CryptoRng, OsRng, RngCore};

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

fn compute_random_license<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (License, LicenseProverParameters, SessionCookie) {
    let ssk = SecretSpendKey::random(&mut OsRng);
    let psk = ssk.public_spend_key();
    let lsa = psk.gen_stealth_address(&JubJubScalar::random(&mut OsRng));

    let ssk_sp = SecretSpendKey::random(&mut OsRng);
    let psk_sp = ssk_sp.public_spend_key();

    let attr = JubJubScalar::from(112233445566778899u64);
    let k_lic = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(123456u64));
    let lic = License::new(attr, ssk_sp, lsa, k_lic, &mut OsRng);

    let (lpp, sc) = LicenseProverParameters::new(lsa, ssk, lic.clone(), psk_sp, psk_sp, k_lic, rng);

    (lic, lpp, sc)
}

fn citadel_benchmark(c: &mut Criterion) {
    // Compute the setup
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    // Benchmark the prover
    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);

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
