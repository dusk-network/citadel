// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

extern crate alloc;

use std::ops::Range;
use std::sync::mpsc;

use dusk_bytes::Serializable;
use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};
use rkyv::{Deserialize, Infallible, check_archived_root};
use zk_citadel::{License, LicenseOrigin, Request, SessionCookie, circuit, gadgets};

const PROVER_BYTES: &[u8] = include_bytes!("../../target/prover");

const VERIFIER_BYTES: &[u8] = include_bytes!("../../target/verifier");

const LICENSE_CONTRACT_BYTECODE: &[u8] =
    include_bytes!("../../target/wasm32-unknown-unknown/release/license_contract.wasm");

pub type LicenseOpening = poseidon_merkle::Opening<(), { circuit::DEPTH }>;

use dusk_core::{
    BlsScalar, JubJubAffine, JubJubScalar,
    abi::ContractId,
    plonk::{Prover, Verifier},
    transfer::phoenix::{PublicKey, SecretKey, ViewKey},
};
use dusk_vm::{ContractData, Session, VM};

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
    sk_user: &SecretKey,
    pk_user: &PublicKey,
    rng: &mut R,
) -> License {
    let request = Request::new(sk_user, pk_user, pk_lp, rng).unwrap();
    License::new(
        attr,
        sk_lp,
        &LicenseOrigin::FromRequest(Box::new(request)),
        rng,
    )
    .unwrap()
}

fn issue_arg(license: &License, license_blob: Vec<u8>) -> IssueLicenseArg {
    let lpk = JubJubAffine::from(license.lsa.note_pk().as_ref());
    IssueLicenseArg {
        license: license_blob,
        lpk_u: lpk.get_u(),
        lpk_v: lpk.get_v(),
    }
}

fn initialize() -> Session {
    let vm = &mut VM::ephemeral().expect("Creating ephemeral VM should work");
    let mut session = vm.genesis_session(CHAIN_ID);

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

    // license provider
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);

    let attr = JubJubScalar::from(USER_ATTRIBUTES);

    let license = create_test_license(&attr, &sk_lp, &pk_lp, &sk_user, &pk_user, rng);
    let license_blob = rkyv::to_bytes::<_, 4096>(&license)
        .expect("Request should serialize correctly")
        .to_vec();

    let issue_arg = issue_arg(&license, license_blob);

    session
        .call::<IssueLicenseArg, ()>(
            LICENSE_CONTRACT_ID,
            "issue_license",
            &issue_arg,
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

    // license provider
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);

    let attr = JubJubScalar::from(USER_ATTRIBUTES);

    const NUM_LICENSES: usize = 4 + 1;
    for _ in 0..NUM_LICENSES {
        let license = create_test_license(&attr, &sk_lp, &pk_lp, &sk_user, &pk_user, rng);
        let license_blob = rkyv::to_bytes::<_, 4096>(&license)
            .expect("Request should serialize correctly")
            .to_vec();

        let issue_arg = issue_arg(&license, license_blob);
        session
            .call::<IssueLicenseArg, ()>(
                LICENSE_CONTRACT_ID,
                "issue_license",
                &issue_arg,
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
fn metadata_and_info_track_state() {
    let rng = &mut StdRng::seed_from_u64(0xcafe);
    let mut session = initialize();

    let metadata = session
        .call::<(), DeploymentMetadata>(LICENSE_CONTRACT_ID, "get_metadata", &(), POINT_LIMIT)
        .expect("Get metadata should succeed")
        .data;

    assert_eq!(metadata.deployment_id, BlsScalar::zero());
    assert_eq!(metadata.protocol_version, BlsScalar::one());
    assert_eq!(metadata.chain_id, BlsScalar::zero());
    assert_eq!(metadata.contract_id, BlsScalar::zero());
    assert_eq!(metadata.merkle_depth, circuit::DEPTH as u32);
    assert_eq!(metadata.root_history_size, 8);
    assert_eq!(metadata.public_inputs_len, PUBLIC_INPUTS_LEN as u32);

    let initial_info = session
        .call::<(), (u32, u32, u32)>(LICENSE_CONTRACT_ID, "get_info", &(), POINT_LIMIT)
        .expect("Get info should succeed")
        .data;
    assert_eq!(initial_info, (0, 0, 0));

    let empty_opening = session
        .call::<u64, Option<LicenseOpening>>(
            LICENSE_CONTRACT_ID,
            "get_merkle_opening",
            &0,
            POINT_LIMIT,
        )
        .expect("Querying an empty opening should succeed")
        .data;
    assert!(empty_opening.is_none());

    let sk_user = SecretKey::random(rng);
    let pk_user = PublicKey::from(&sk_user);
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let license = create_test_license(&attr, &sk_lp, &pk_lp, &sk_user, &pk_user, rng);
    let license_blob = rkyv::to_bytes::<_, 4096>(&license)
        .expect("License should serialize correctly")
        .to_vec();
    let issue_arg = issue_arg(&license, license_blob);

    session
        .call::<IssueLicenseArg, ()>(
            LICENSE_CONTRACT_ID,
            "issue_license",
            &issue_arg,
            POINT_LIMIT,
        )
        .expect("Issuing license should succeed");

    let issued_info = session
        .call::<(), (u32, u32, u32)>(LICENSE_CONTRACT_ID, "get_info", &(), POINT_LIMIT)
        .expect("Get info should succeed")
        .data;
    assert_eq!(issued_info, (1, 1, 0));

    let opening = session
        .call::<u64, Option<LicenseOpening>>(
            LICENSE_CONTRACT_ID,
            "get_merkle_opening",
            &0,
            POINT_LIMIT,
        )
        .expect("Querying an issued opening should succeed")
        .data;
    assert!(opening.is_some());
}

#[test]
fn issue_license_rejects_invalid_and_duplicate_public_keys() {
    let rng = &mut StdRng::seed_from_u64(0xcafe);
    let mut session = initialize();

    let invalid_issue_arg = IssueLicenseArg {
        license: vec![1, 2, 3],
        lpk_u: BlsScalar::zero(),
        lpk_v: BlsScalar::zero(),
    };
    assert!(
        session
            .call::<IssueLicenseArg, ()>(
                LICENSE_CONTRACT_ID,
                "issue_license",
                &invalid_issue_arg,
                POINT_LIMIT,
            )
            .is_err(),
        "Invalid license public key should be rejected"
    );

    let sk_user = SecretKey::random(rng);
    let pk_user = PublicKey::from(&sk_user);
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let license = create_test_license(&attr, &sk_lp, &pk_lp, &sk_user, &pk_user, rng);
    let license_blob = rkyv::to_bytes::<_, 4096>(&license)
        .expect("License should serialize correctly")
        .to_vec();
    let issue_arg = issue_arg(&license, license_blob);

    session
        .call::<IssueLicenseArg, ()>(
            LICENSE_CONTRACT_ID,
            "issue_license",
            &issue_arg,
            POINT_LIMIT,
        )
        .expect("Issuing license should succeed");

    assert!(
        session
            .call::<IssueLicenseArg, ()>(
                LICENSE_CONTRACT_ID,
                "issue_license",
                &issue_arg,
                POINT_LIMIT,
            )
            .is_err(),
        "Duplicate license public key should be rejected"
    );

    let info = session
        .call::<(), (u32, u32, u32)>(LICENSE_CONTRACT_ID, "get_info", &(), POINT_LIMIT)
        .expect("Get info should succeed")
        .data;
    assert_eq!(info, (1, 1, 0));
}

#[test]
fn use_license_rejects_bad_public_inputs_before_proof_verification() {
    let mut session = initialize();

    let short_arg = UseLicenseArg {
        proof: vec![],
        public_inputs: vec![BlsScalar::zero(); PUBLIC_INPUTS_LEN - 1],
    };
    let short_result = session.call::<UseLicenseArg, ()>(
        LICENSE_CONTRACT_ID,
        "use_license",
        &short_arg,
        POINT_LIMIT,
    );
    assert!(
        short_result.is_err(),
        "Wrong public input length should be rejected"
    );

    let unknown_root_arg = UseLicenseArg {
        proof: vec![],
        public_inputs: vec![BlsScalar::zero(); PUBLIC_INPUTS_LEN],
    };
    assert!(
        session
            .call::<UseLicenseArg, ()>(
                LICENSE_CONTRACT_ID,
                "use_license",
                &unknown_root_arg,
                POINT_LIMIT,
            )
            .is_err(),
        "Unknown root should be rejected before proof verification"
    );
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
    // TODO: Keep contract proof verification on PLONK V3. The VM host query
    // still defaults to V2, while dusk-plonk currently generates V3 proofs.
    let _plonk_version_guard =
        dusk_vm::host_queries::set_plonk_version(dusk_core::plonk::PlonkVersion::current());

    // NOTE: it is important that the seed is the same as in the recovery
    // PUB_PARAMS initialization code
    let rng = &mut StdRng::seed_from_u64(0xbeef);

    let prover =
        Prover::try_from_bytes(PROVER_BYTES).expect("Prover failed to be created from slice.");

    let verifier = Verifier::try_from_bytes(VERIFIER_BYTES)
        .expect("Verifier failed to be created from slice.");

    // user
    let sk_user = SecretKey::random(rng);
    let pk_user = PublicKey::from(&sk_user);

    // license provider
    let sk_lp = SecretKey::random(rng);
    let pk_lp = PublicKey::from(&sk_lp);

    let request =
        Request::new(&sk_user, &pk_user, &pk_lp, rng).expect("Request correctly created.");
    let attr = JubJubScalar::from(USER_ATTRIBUTES);
    let license = License::new(
        &attr,
        &sk_lp,
        &LicenseOrigin::FromRequest(Box::new(request)),
        rng,
    )
    .unwrap();

    let license_blob = rkyv::to_bytes::<_, 4096>(&license)
        .expect("Request should serialize correctly")
        .to_vec();

    let issue_arg = issue_arg(&license, license_blob);

    session
        .call::<IssueLicenseArg, ()>(
            LICENSE_CONTRACT_ID,
            "issue_license",
            &issue_arg,
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
    let duplicate_use_license_arg = use_license_arg.clone();

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

    assert!(
        session
            .call::<UseLicenseArg, ()>(
                LICENSE_CONTRACT_ID,
                "use_license",
                &duplicate_use_license_arg,
                POINT_LIMIT,
            )
            .is_err(),
        "A duplicate session_id should be rejected"
    );
}

#[test]
fn test_request_license() {
    let mut session = initialize();
    session
        .call::<(), ()>(LICENSE_CONTRACT_ID, "request_license", &(), POINT_LIMIT)
        .expect("Request license should succeed");
}
