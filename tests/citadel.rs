// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::GENERATOR_EXTENDED;
use dusk_pki::SecretSpendKey;
use dusk_plonk::prelude::*;

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 15; // capacity required for the setup

use zk_citadel::gadget;
use zk_citadel::license::{License, LicenseProverParameters, SessionCookie};

use rand_core::{CryptoRng, OsRng, RngCore};

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
        Ok(())
    }
}

fn compute_random_license<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (License, LicenseProverParameters, SessionCookie) {
    // First, the user computes these values and requests a License
    let ssk = SecretSpendKey::random(&mut OsRng);
    let psk = ssk.public_spend_key();
    let lsa = psk.gen_stealth_address(&JubJubScalar::random(&mut OsRng));

    // Second, the SP computes these values and grants the License
    let ssk_sp = SecretSpendKey::random(&mut OsRng);
    let psk_sp = ssk_sp.public_spend_key();

    let attr = JubJubScalar::from(112233445566778899u64);
    let k_lic = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(123456u64));
    let lic = License::new(attr, ssk_sp, lsa, k_lic, &mut OsRng);

    // Third, the user computes these values to generate the ZKP later on
    let pk_sp = JubJubAffine::from(*psk_sp.A());
    let (lpp, sc) = LicenseProverParameters::new(lsa, ssk, lic.clone(), pk_sp, k_lic, rng);

    (lic, lpp, sc)
}

#[test]
fn test_full_citadel() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(lpp.clone(), sc.clone()))
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let pk_sp = sc.pk_sp;
    sc.verify(public_inputs, pk_sp);
}

#[test]
#[should_panic]
fn test_nullify_license_circuit_false_public_input() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(lpp.clone(), sc.clone()))
        .expect("failed to prove");

    // set a false public input
    let mut false_public_inputs = public_inputs;
    false_public_inputs[0] = BlsScalar::random(&mut OsRng);

    verifier
        .verify(&proof, &false_public_inputs)
        .expect("failed to verify proof");
}

#[test]
#[should_panic]
fn test_verify_license_false_session_cookie() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, _verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (_proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(lpp.clone(), sc.clone()))
        .expect("failed to prove");

    // set a false session cookie
    let sc_false = SessionCookie::new(
        sc.nullifier_lic,
        sc.pk_sp,
        JubJubScalar::from(1234u64),
        sc.c,
        sc.s_0,
        sc.s_1,
        sc.s_2,
    );
    sc_false.verify(public_inputs, sc.pk_sp);
}
