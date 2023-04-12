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
use zk_citadel::license::{License, LicenseProverParameters, Request, Session, SessionCookie};

use rand_core::{CryptoRng, OsRng, RngCore};

#[derive(Default, Debug)]
pub struct Citadel {
    lpp: LicenseProverParameters,
    sc: SessionCookie,
}

impl Citadel {
    pub fn new(lpp: &LicenseProverParameters, sc: &SessionCookie) -> Self {
        Self { lpp: *lpp, sc: *sc }
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
    // These are the keys of the user
    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_spend_key();

    // These are the keys of the SP
    let ssk_sp = SecretSpendKey::random(rng);
    let psk_sp = ssk_sp.public_spend_key();

    // First, the user computes these values and requests a License
    let lsa = psk.gen_stealth_address(&JubJubScalar::random(rng));
    let k_lic = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(123456u64));
    let req = Request::new(&psk_sp, &lsa, &k_lic, rng);

    // Second, the SP computes these values and grants the License
    let attr = JubJubScalar::from(112233445566778899u64);
    let lic = License::new(&attr, &ssk_sp, &req, rng);

    // Third, the user computes these values to generate the ZKP later on
    let c = JubJubScalar::from(20221126u64);
    let (lpp, sc) = LicenseProverParameters::compute_parameters(
        &lsa, &ssk, &lic, &psk_sp, &psk_sp, &k_lic, &c, rng,
    );

    (lic, lpp, sc)
}

#[test]
fn test_full_citadel() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let pk_sp = sc.pk_sp;
    let session = Session::from(&public_inputs);
    session.verify(sc, pk_sp);
}

#[test]
#[should_panic]
fn test_nullify_license_circuit_false_public_input() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let (_lic, lpp, sc) = compute_random_license(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
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
        .prove(&mut OsRng, &Citadel::new(&lpp, &sc))
        .expect("failed to prove");

    // set a false session cookie
    let sc_false = SessionCookie {
        pk_ssp: sc.pk_ssp,
        r: sc.r,
        nullifier_lic: sc.nullifier_lic,
        pk_sp: sc.pk_sp,
        attr: JubJubScalar::from(1234u64),
        c: sc.c,
        s_0: sc.s_0,
        s_1: sc.s_1,
        s_2: sc.s_2,
    };

    let pk_sp = sc.pk_sp;
    let session = Session::from(&public_inputs);
    session.verify(sc_false, pk_sp);
}
