// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_pki::SecretSpendKey;
use dusk_plonk::prelude::*;

use zk_citadel::gadget;
use zk_citadel::license::{License, LicenseProverParameters, Request, SessionCookie};
use zk_citadel::state::State;

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::{CryptoRng, OsRng, RngCore};

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 16; // capacity required for the setup
const DEPTH: usize = 17; // depth of the n-ary Merkle tree
pub const ARITY: usize = 4; // arity of the Merkle tree

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
        unsafe {
            CONSTRAINTS = composer.constraints();
        }
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
    let req = Request::new(&psk_lp, &lsa, &k_lic, rng);

    // Second, the LP computes these values and grants the License
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let mut lic = License::new(&attr, &ssk_lp, &req, rng);
    let mut state = State::new(); // the compiler takes DEPTH from expected 'lpp' to return
    state.append_license(&mut lic);

    // Third, the user computes these values to generate the ZKP later on
    let vk = ssk.view_key();
    let lics = state.get_licenses(&vk);
    let c = JubJubScalar::from(CHALLENGE);
    let (lpp, sc) = LicenseProverParameters::compute_parameters(
        &ssk, &lics[0], &psk_lp, &psk_lp, &k_lic, &c, rng, &state,
    );

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
                    .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
                    .expect("failed to prove")
            })
        });

        // Benchmark the verifier
        let (proof, public_inputs) = prover
            .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
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