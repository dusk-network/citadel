use dusk_plonk::prelude::*;
use rand_core::OsRng;

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 17; // capacity required for the setup

use citadel::gadget;
use citadel::license::{License, SessionCookie};

#[derive(Default, Debug)]
pub struct Citadel {
    license: License,
}

impl Citadel {
    pub fn new(license: License) -> Self {
        Self { license }
    }
}

impl Circuit for Citadel {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadget::nullify_license(composer, &self.license)?;
        Ok(())
    }
}

#[test]
fn test_full_citadel() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let license = License::random(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(license.clone()))
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");

    let sc = SessionCookie::new(
        license.pk_sp,
        license.s_0,
        license.attr,
        license.s_1,
        license.c,
        license.s_2,
    );
    License::verify(sc, public_inputs, license.pk_sp);
}

#[test]
#[should_panic]
fn test_nullify_license_circuit_false_public_input() {
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (prover, verifier) =
        Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

    let license = License::random(&mut OsRng);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(license))
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

    let license = License::random(&mut OsRng);
    let (_proof, public_inputs) = prover
        .prove(&mut OsRng, &Citadel::new(license.clone()))
        .expect("failed to prove");

    // set a false session cookie
    let sc = SessionCookie::new(
        license.pk_sp,
        BlsScalar::from(1234u64),
        license.attr,
        license.s_1,
        license.c,
        license.s_2,
    );
    License::verify(sc, public_inputs, license.pk_sp);
}
