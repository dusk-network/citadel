// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, Hash};
use phoenix_core::{PublicKey, SecretKey};
use poseidon_merkle::{Item, Tree};

use zk_citadel::{circuit, gadgets, License, LicenseOrigin, SessionCookie};

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";

// Example values
const ATTRIBUTE_DATA: u64 = 112233445566778899u64;
const CHALLENGE: u64 = 20221126u64;

#[derive(Default, Debug)]
pub struct LicenseCircuit {
    gp: gadgets::GadgetParameters<{ circuit::DEPTH }>,
    sc: SessionCookie,
}

impl LicenseCircuit {
    pub fn new(gp: &gadgets::GadgetParameters<{ circuit::DEPTH }>, sc: &SessionCookie) -> Self {
        Self { gp: *gp, sc: *sc }
    }
}

impl Circuit for LicenseCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        gadgets::use_license(composer, &self.gp, &self.sc)?;
        unsafe {
            CONSTRAINTS = composer.constraints();
        }
        Ok(())
    }
}

fn license_circuit_benchmark(crit: &mut Criterion) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);
    let sk_lp = SecretKey::random(&mut OsRng);
    let pk_lp = PublicKey::from(&sk_lp);

    let pp = PublicParameters::setup(1 << circuit::CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<LicenseCircuit>(&pp, LABEL).expect("failed to compile circuit");

    let attr_data = JubJubScalar::from(ATTRIBUTE_DATA);
    let lic = License::new(
        &attr_data,
        &sk_lp,
        &LicenseOrigin::FromPublicKey(pk),
        &mut OsRng,
    )
    .expect("License correctly computed.");

    let mut tree = Tree::<(), { circuit::DEPTH }>::new();
    let lpk = JubJubAffine::from(lic.lsa.note_pk().as_ref());

    let item = Item {
        hash: Hash::digest(Domain::Other, &[lpk.get_u(), lpk.get_v()])[0],
        data: (),
    };

    let pos = 0;
    tree.insert(pos, item);

    let merkle_proof = tree.opening(pos).expect("Tree was read successfully");

    let c = JubJubScalar::from(CHALLENGE);
    let pk_sp = pk_lp; // LP = SP
    let (gp, sc) = gadgets::GadgetParameters::compute_parameters(
        &sk,
        &lic,
        &pk_lp,
        &pk_sp,
        &c,
        &mut OsRng,
        merkle_proof,
    )
    .expect("Parameters correctly computed.");

    // Perform the actual benchmarks
    unsafe {
        // Benchmark the prover
        let log = &format!("License Circuit Prover ({} constraints)", CONSTRAINTS);
        crit.bench_function(log, |b| {
            b.iter(|| {
                prover
                    .prove(&mut OsRng, &LicenseCircuit::new(&gp, &sc))
                    .expect("failed to prove")
            })
        });

        // Benchmark the verifier
        let (proof, public_inputs) = prover
            .prove(&mut OsRng, &LicenseCircuit::new(&gp, &sc))
            .expect("failed to prove");
        let log = &format!("License Circuit Verifier ({} constraints)", CONSTRAINTS);
        crit.bench_function(log, |b| {
            b.iter(|| {
                verifier
                    .verify(&proof, &public_inputs)
                    .expect("failed to verify proof")
            })
        });
    }
}

criterion_group! {
    name = license_circuit;
    config = Criterion::default().sample_size(10);
    targets = license_circuit_benchmark
}
criterion_main!(license_circuit);
