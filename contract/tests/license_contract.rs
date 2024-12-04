// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use std::ops::Range;
use std::sync::mpsc;

use dusk_bytes::Serializable;
use dusk_poseidon::{Domain, Hash};
use execution_core::plonk::{Prover, Verifier};
use ff::Field;
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use rkyv::{check_archived_root, Deserialize, Infallible};
use zk_citadel::{circuit, gadgets, License, LicenseCreator, Request, SessionCookie};

const PROVER_BYTES: &[u8] = include_bytes!("../../target/prover");

const VERIFIER_BYTES: &[u8] = include_bytes!("../../target/verifier");

const LICENSE_CONTRACT_BYTECODE: &[u8] =
    include_bytes!("../../target/wasm32-unknown-unknown/release/license_contract.wasm");

pub type LicenseOpening = poseidon_merkle::Opening<(), { circuit::DEPTH }>;

use execution_core::{
    transfer::phoenix::{PublicKey, SecretKey, StealthAddress, ViewKey},
    BlsScalar, ContractId, JubJubAffine, JubJubScalar, GENERATOR_EXTENDED,
};
use rusk_abi::{ContractData, Session};

#[path = "../src/license_types.rs"]
mod license_types;
use license_types::*;

const LICENSE_CONTRACT_ID: ContractId = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xf8;
    ContractId::from_bytes(bytes)
};

const POINT_LIMIT: u64 = 0x10000000;
const TEST_OWNER: [u8; 32] = [0; 32];
const CHAIN_ID: u8 = 0xFA;
const USER_ATTRIBUTES: u64 = 545072475273;

fn create_test_license<R: RngCore + CryptoRng>(
    attr: &JubJubScalar,
    sk_lp: &SecretKey,
    pk_lp: &PublicKey,
    sa_user: &StealthAddress,
    k_lic: &JubJubAffine,
    rng: &mut R,
) -> License {
    let request = Request::new(pk_lp, sa_user, k_lic, rng).unwrap();
    License::new(attr, sk_lp, &LicenseCreator::FromRequest(request), rng).unwrap()
}

fn initialize() -> Session {
    let vm = rusk_abi::new_ephemeral_vm().expect("Creating a VM should succeed");
    let mut session = rusk_abi::new_genesis_session(&vm, CHAIN_ID);

    session
        .deploy(
            LICENSE_CONTRACT_BYTECODE,
            ContractData::builder()
                .owner(TEST_OWNER)
                .contract_id(LICENSE_CONTRACT_ID),
            POINT_LIMIT,
        )
        .expect("Deploying the license contract should succeed");

    session
}

/// Deserializes license, panics if deserialization fails.
fn deserialise_license(v: &Vec<u8>) -> License {
    let response_data =
        check_archived_root::<License>(v.as_slice()).expect("License should deserialize correctly");
    let license: License = response_data
        .deserialize(&mut Infallible)
        .expect("Infallible");
    license
}

/// Finds owned license in a collection of licenses.
/// It searches in a reverse order to return a newest license.
fn find_owned_license(
    sk_user: &SecretKey,
    licenses: &Vec<(u64, Vec<u8>)>,
) -> Option<(u64, License)> {
    for (pos, license) in licenses.iter().rev() {
        let license = deserialise_license(&license);
        if ViewKey::from(sk_user).owns(&license.lsa) {
            return Some((pos.clone(), license));
        }
    }
    None
}

/// Creates the Citadel request object
fn create_request<R: RngCore + CryptoRng>(
    sk_user: &SecretKey,
    pk_lp: &PublicKey,
    rng: &mut R,
) -> Request {
    let pk = PublicKey::from(sk_user);
    let lsa = pk.gen_stealth_address(&JubJubScalar::random(&mut *rng));
    let lsk = sk_user.gen_note_sk(&lsa);
    let k_lic = JubJubAffine::from(
        GENERATOR_EXTENDED * Hash::digest_truncated(Domain::Other, &[(*lsk.as_ref()).into()])[0],
    );
    Request::new(pk_lp, &lsa, &k_lic, rng).unwrap()
}

fn compute_citadel_parameters(
    rng: &mut StdRng,
    sk: &SecretKey,
    pk_lp: &PublicKey,
    lic: &License,
    merkle_proof: LicenseOpening,
) -> (gadgets::GadgetParameters<{ circuit::DEPTH }>, SessionCookie) {
    const CHALLENGE: u64 = 20221126u64;
    let c = JubJubScalar::from(CHALLENGE);
    let (gp, sc) =
        gadgets::GadgetParameters::compute_parameters(sk, lic, pk_lp, pk_lp, &c, rng, merkle_proof)
            .expect("Parameters computed correctly.");
    (gp, sc)
}

#[test]
fn license_issue_get_merkle() {
    let rng = &mut StdRng::seed_from_u64(0xcafe);
    let mut session = initialize();

    // user
    let sk_user = SecretKey::random(rng);
    let pk_user = PublicKey::from(&sk_user);
    let sa_user = pk_user.gen_stealth_address(&JubJubScalar::random(&mut *rng));

    // license provider
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);
    let k_lic = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng));

    let attr = JubJubScalar::from(USER_ATTRIBUTES);

    let license = create_test_license(&attr, &sk_lp, &pk_lp, &sa_user, &k_lic, rng);
    let license_blob = rkyv::to_bytes::<_, 4096>(&license)
        .expect("Request should serialize correctly")
        .to_vec();

    let lpk = JubJubAffine::from(license.lsa.note_pk().as_ref());
    let license_hash = Hash::digest(Domain::Other, &[lpk.get_u(), lpk.get_v()])[0];

    session
        .call::<(Vec<u8>, BlsScalar), ()>(
            LICENSE_CONTRACT_ID,
            "issue_license",
            &(license_blob, license_hash),
            POINT_LIMIT,
        )
        .expect("Issuing license should succeed");

    let bh_range = 0..10000u64;
    let (feeder, receiver) = mpsc::channel();
    session
        .feeder_call::<Range<u64>, ()>(
            LICENSE_CONTRACT_ID,
            "get_licenses",
            &bh_range,
            u64::MAX,
            feeder,
        )
        .expect("Querying of the licenses should succeed")
        .data;

    let pos_license_pairs: Vec<(u64, Vec<u8>)> = receiver
        .iter()
        .map(|bytes| rkyv::from_bytes(&bytes).expect("Should return licenses"))
        .collect();

    assert!(
        !pos_license_pairs.is_empty(),
        "Call to getting a license request should return some licenses"
    );

    let owned_license = find_owned_license(&sk_user, &pos_license_pairs);
    assert!(
        owned_license.is_some(),
        "Some license should be owned by the user"
    );
    let (pos, _) = owned_license.unwrap();

    let _merkle_opening = session
        .call::<u64, LicenseOpening>(LICENSE_CONTRACT_ID, "get_merkle_opening", &pos, POINT_LIMIT)
        .expect("Querying the merkle opening should succeed")
        .data;
}

#[test]
fn multiple_licenses_issue_get_merkle() {
    let rng = &mut StdRng::seed_from_u64(0xcafe);
    let mut session = initialize();

    // user
    let sk_user = SecretKey::random(rng);
    let pk_user = PublicKey::from(&sk_user);
    let sa_user = pk_user.gen_stealth_address(&JubJubScalar::random(&mut *rng));

    // license provider
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);

    let attr = JubJubScalar::from(USER_ATTRIBUTES);

    const NUM_LICENSES: usize = 4 + 1;
    for _ in 0..NUM_LICENSES {
        let k_lic = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(&mut *rng));
        let license = create_test_license(&attr, &sk_lp, &pk_lp, &sa_user, &k_lic, rng);
        let license_blob = rkyv::to_bytes::<_, 4096>(&license)
            .expect("Request should serialize correctly")
            .to_vec();

        let lpk = JubJubAffine::from(license.lsa.note_pk().as_ref());
        let license_hash = Hash::digest(Domain::Other, &[lpk.get_u(), lpk.get_v()])[0];
        session
            .call::<(Vec<u8>, BlsScalar), ()>(
                LICENSE_CONTRACT_ID,
                "issue_license",
                &(license_blob, license_hash),
                POINT_LIMIT,
            )
            .expect("Issuing license should succeed");
    }

    let (feeder, receiver) = mpsc::channel();
    let bh_range = 0..NUM_LICENSES as u64;
    session
        .feeder_call::<Range<u64>, ()>(
            LICENSE_CONTRACT_ID,
            "get_licenses",
            &bh_range,
            u64::MAX,
            feeder,
        )
        .expect("Querying of the licenses should succeed")
        .data;

    let pos_license_pairs: Vec<(u64, Vec<u8>)> = receiver
        .iter()
        .map(|bytes| rkyv::from_bytes(&bytes).expect("Should return licenses"))
        .collect();

    assert_eq!(
        pos_license_pairs.len(),
        NUM_LICENSES,
        "Call to getting license requests should return licenses"
    );

    let owned_license = find_owned_license(&sk_user, &pos_license_pairs);
    assert!(
        owned_license.is_some(),
        "Some license should be owned by the user"
    );
    let (pos, _) = owned_license.unwrap();

    let _merkle_opening = session
        .call::<u64, LicenseOpening>(LICENSE_CONTRACT_ID, "get_merkle_opening", &pos, POINT_LIMIT)
        .expect("Querying the merkle opening should succeed")
        .data;
}

#[test]
fn session_not_found() {
    const SESSION_ID: u64 = 7u64;
    let mut session = initialize();
    let session_id = LicenseSessionId {
        id: BlsScalar::from(SESSION_ID),
    };

    let license_session = session
        .call::<LicenseSessionId, Option<LicenseSession>>(
            LICENSE_CONTRACT_ID,
            "get_session",
            &session_id,
            POINT_LIMIT,
        )
        .expect("Querying the session should succeed")
        .data;

    assert_eq!(None::<LicenseSession>, license_session);
}

#[test]
fn use_license_get_session() {
    let mut session = initialize();

    // NOTE: it is important that the seed is the same as in the recovery
    // PUB_PARAMS initialization code
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let prover =
        Prover::try_from_bytes(PROVER_BYTES).expect("Prover failed to be created from slice.");

    let verifier = Verifier::try_from_bytes(VERIFIER_BYTES)
        .expect("Verifier failed to be created from slice.");

    // user
    let sk_user = SecretKey::random(rng);

    // license provider
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);

    let request = create_request(&sk_user, &pk_lp, rng);
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let license = License::new(&attr, &sk_lp, &LicenseCreator::FromRequest(request), rng).unwrap();

    let license_blob = rkyv::to_bytes::<_, 4096>(&license)
        .expect("Request should serialize correctly")
        .to_vec();

    let lpk = JubJubAffine::from(license.lsa.note_pk().as_ref());
    let license_hash = Hash::digest(Domain::Other, &[lpk.get_u(), lpk.get_v()])[0];

    session
        .call::<(Vec<u8>, BlsScalar), ()>(
            LICENSE_CONTRACT_ID,
            "issue_license",
            &(license_blob, license_hash),
            POINT_LIMIT,
        )
        .expect("Issuing license should succeed");

    let (feeder, receiver) = mpsc::channel();
    let bh_range = 0..10000u64;
    session
        .feeder_call::<Range<u64>, ()>(
            LICENSE_CONTRACT_ID,
            "get_licenses",
            &bh_range,
            u64::MAX,
            feeder,
        )
        .expect("Querying the license should succeed")
        .data;

    let pos_license_pairs: Vec<(u64, Vec<u8>)> = receiver
        .iter()
        .map(|bytes| rkyv::from_bytes(&bytes).expect("Should return licenses"))
        .collect();

    assert!(
        !pos_license_pairs.is_empty(),
        "Call to getting license requests should return licenses"
    );

    let owned_license = find_owned_license(&sk_user, &pos_license_pairs);
    assert!(
        owned_license.is_some(),
        "Some license should be owned by the user"
    );
    let (pos, owned_license) = owned_license.unwrap();

    let merkle_opening = session
        .call::<u64, LicenseOpening>(LICENSE_CONTRACT_ID, "get_merkle_opening", &pos, POINT_LIMIT)
        .expect("Querying the merkle opening should succeed")
        .data;

    let (gp, sc) =
        compute_citadel_parameters(rng, &sk_user, &pk_lp, &owned_license, merkle_opening);
    let circuit = circuit::LicenseCircuit::new(&gp, &sc);

    let (proof, public_inputs) = prover.prove(rng, &circuit).expect("Proving should succeed");

    let session_id = LicenseSessionId {
        id: public_inputs[0],
    };

    verifier
        .verify(&proof, &public_inputs)
        .expect("Verifying the circuit should succeed");

    let use_license_arg = UseLicenseArg {
        proof: proof.to_bytes().to_vec(),
        public_inputs,
    };

    session
        .call::<UseLicenseArg, ()>(
            LICENSE_CONTRACT_ID,
            "use_license",
            &use_license_arg,
            POINT_LIMIT,
        )
        .expect("Use license should succeed");

    assert!(
        session
            .call::<LicenseSessionId, Option<LicenseSession>>(
                LICENSE_CONTRACT_ID,
                "get_session",
                &session_id,
                POINT_LIMIT
            )
            .expect("Get session should succeed")
            .data
            .is_some(),
        "Call to get session should return a session"
    );
}

#[test]
fn test_request_license() {
    let mut session = initialize();
    session
        .call::<(), ()>(LICENSE_CONTRACT_ID, "request_license", &(), POINT_LIMIT)
        .expect("Request license should succeed");
}
