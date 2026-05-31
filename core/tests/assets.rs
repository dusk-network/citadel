// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED, JubJubAffine};
use dusk_plonk::prelude::*;
use phoenix_core::{PublicKey, SecretKey};
use rand_core::OsRng;

use zk_citadel::{
    AttributeOpening, Error as CitadelError, License, LicenseOptions, LicenseOrigin, Request,
    Session, SessionCookie, SessionPolicy,
    helpers::{
        COOKIE_MODE_BASE, DEFAULT_DEPLOYMENT, Deployment, OBJECT_VERSION_V1, PI_COM_1_X,
        PI_COM_1_Y, attr_data as compute_attr_data, lp_commitment, request_id, session_hash,
    },
};

fn test_deployment(id: u64) -> Deployment {
    Deployment::new(
        BlsScalar::from(id),
        BlsScalar::one(),
        BlsScalar::from(10_000 + id),
        BlsScalar::from(20_000 + id),
    )
}

fn cookie() -> SessionCookie {
    let sk_sp = SecretKey::random(&mut OsRng);
    let sk_lp = SecretKey::random(&mut OsRng);

    SessionCookie {
        version: OBJECT_VERSION_V1,
        deployment_id: DEFAULT_DEPLOYMENT.id,
        cookie_mode: COOKIE_MODE_BASE,
        policy_id: BlsScalar::zero(),
        pk_sp: PublicKey::from(&sk_sp),
        r_session: BlsScalar::from(11u64),
        session_id: BlsScalar::from(12u64),
        pk_lp: PublicKey::from(&sk_lp),
        attr_data: JubJubScalar::from(13u64),
        attr_opening: None,
        c: JubJubScalar::from(14u64),
        s_0: BlsScalar::from(15u64),
        s_1: JubJubScalar::from(16u64),
        s_2: JubJubScalar::from(17u64),
        binding_data: [BlsScalar::zero(); 4],
    }
}

fn policy(sc: &SessionCookie) -> SessionPolicy {
    SessionPolicy::new(sc.policy_id, sc.pk_sp, sc.pk_lp, sc.c)
}

fn public_inputs(sc: &SessionCookie) -> Vec<BlsScalar> {
    let pk_sp_a = JubJubAffine::from(sc.pk_sp.A());
    let pk_lp_a = JubJubAffine::from(sc.pk_lp.A());
    let com_1 = JubJubAffine::from(
        (GENERATOR_EXTENDED * sc.attr_data) + (GENERATOR_NUMS_EXTENDED * sc.s_1),
    );
    let com_2 =
        JubJubAffine::from((GENERATOR_EXTENDED * sc.c) + (GENERATOR_NUMS_EXTENDED * sc.s_2));

    vec![
        sc.session_id,
        session_hash(DEFAULT_DEPLOYMENT, pk_sp_a, sc.r_session),
        lp_commitment(DEFAULT_DEPLOYMENT, pk_lp_a, sc.s_0),
        com_1.get_u(),
        com_1.get_v(),
        com_2.get_u(),
        com_2.get_v(),
        BlsScalar::from(18u64),
    ]
}

#[test]
fn request_bound_license_enforces_deployment_and_intended_lp() {
    let sk_user = SecretKey::random(&mut OsRng);
    let pk_user = PublicKey::from(&sk_user);
    let sk_lp = SecretKey::random(&mut OsRng);
    let pk_lp = PublicKey::from(&sk_lp);
    let sk_other_lp = SecretKey::random(&mut OsRng);
    let attr_data = JubJubScalar::from(123u64);
    let deployment = test_deployment(7);
    let other_deployment = test_deployment(8);

    let req = Request::new_with_deployment(&sk_user, &pk_user, &pk_lp, deployment, &mut OsRng)
        .expect("request should be created");
    assert_eq!(req.version, OBJECT_VERSION_V1);
    assert_eq!(req.deployment_id, deployment.id);
    assert_eq!(
        req.id(),
        request_id(deployment, req.version, &req.rsa, &req.enc)
    );

    let license = License::new(
        &attr_data,
        &sk_lp,
        &LicenseOrigin::FromRequest(Box::new(req)),
        LicenseOptions {
            deployment,
            ..LicenseOptions::default()
        },
        &mut OsRng,
    )
    .expect("matching LP and deployment should issue from request");
    assert_eq!(license.version, OBJECT_VERSION_V1);
    assert_eq!(license.deployment_id, deployment.id);

    let wrong_deployment_req =
        Request::new_with_deployment(&sk_user, &pk_user, &pk_lp, deployment, &mut OsRng)
            .expect("request should be created");
    assert!(
        License::new(
            &attr_data,
            &sk_lp,
            &LicenseOrigin::FromRequest(Box::new(wrong_deployment_req)),
            LicenseOptions {
                deployment: other_deployment,
                ..LicenseOptions::default()
            },
            &mut OsRng,
        )
        .is_err()
    );

    let wrong_lp_req =
        Request::new_with_deployment(&sk_user, &pk_user, &pk_lp, deployment, &mut OsRng)
            .expect("request should be created");
    assert!(
        License::new(
            &attr_data,
            &sk_other_lp,
            &LicenseOrigin::FromRequest(Box::new(wrong_lp_req)),
            LicenseOptions {
                deployment,
                ..LicenseOptions::default()
            },
            &mut OsRng,
        )
        .is_err()
    );
}

#[test]
fn direct_license_carries_selected_deployment() {
    let sk_user = SecretKey::random(&mut OsRng);
    let pk_user = PublicKey::from(&sk_user);
    let sk_lp = SecretKey::random(&mut OsRng);
    let attr_data = JubJubScalar::from(456u64);
    let deployment = test_deployment(9);

    let license = License::new(
        &attr_data,
        &sk_lp,
        &LicenseOrigin::FromPublicKey(Box::new(pk_user)),
        LicenseOptions {
            deployment,
            ..LicenseOptions::default()
        },
        &mut OsRng,
    )
    .expect("direct issuance should succeed");

    assert_eq!(license.deployment_id, deployment.id);
}

#[test]
fn session_rejects_malformed_public_inputs() {
    let sc = cookie();
    let mut inputs = public_inputs(&sc);

    let mut short_inputs = inputs.clone();
    short_inputs.pop();
    assert!(matches!(
        Session::from(&short_inputs),
        Err(CitadelError::InvalidPublicInputs)
    ));

    inputs[PI_COM_1_X] = BlsScalar::zero();
    inputs[PI_COM_1_Y] = BlsScalar::zero();
    assert!(matches!(
        Session::from(&inputs),
        Err(CitadelError::InvalidCommitment)
    ));

    let mut identity_inputs = public_inputs(&sc);
    let identity = JubJubAffine::identity();
    identity_inputs[PI_COM_1_X] = identity.get_u();
    identity_inputs[PI_COM_1_Y] = identity.get_v();
    assert!(matches!(
        Session::from(&identity_inputs),
        Err(CitadelError::InvalidCommitment)
    ));
}

#[test]
fn session_verify_reports_each_cookie_opening_failure() {
    let sc = cookie();
    let session = Session::from(&public_inputs(&sc)).expect("valid public inputs should parse");
    let policy = policy(&sc);

    session
        .verify(sc, &policy)
        .expect("matching cookie should open the session");

    let mut wrong_deployment = sc;
    wrong_deployment.deployment_id = BlsScalar::from(1u64);
    assert!(matches!(
        session.verify(wrong_deployment, &policy),
        Err(CitadelError::WrongDeployment)
    ));

    let mut wrong_policy_id = sc;
    wrong_policy_id.policy_id = BlsScalar::from(42u64);
    assert!(matches!(
        session.verify(wrong_policy_id, &policy),
        Err(CitadelError::WrongPolicyId)
    ));

    let mut wrong_cookie_mode = sc;
    wrong_cookie_mode.cookie_mode = BlsScalar::from(2u64);
    assert!(matches!(
        session.verify(wrong_cookie_mode, &policy),
        Err(CitadelError::WrongCookieMode)
    ));

    let mut wrong_session_id = sc;
    wrong_session_id.session_id = BlsScalar::from(2u64);
    assert!(matches!(
        session.verify(wrong_session_id, &policy),
        Err(CitadelError::WrongSessionId)
    ));

    let mut wrong_session_hash = sc;
    wrong_session_hash.r_session = BlsScalar::from(3u64);
    assert!(matches!(
        session.verify(wrong_session_hash, &policy),
        Err(CitadelError::WrongSessionHash)
    ));

    let other_sp = PublicKey::from(&SecretKey::random(&mut OsRng));
    let mut wrong_sp = sc;
    wrong_sp.pk_sp = other_sp;
    assert!(matches!(
        session.verify(wrong_sp, &policy),
        Err(CitadelError::WrongServiceProvider)
    ));

    let other_lp = PublicKey::from(&SecretKey::random(&mut OsRng));
    let mut wrong_lp = sc;
    wrong_lp.pk_lp = other_lp;
    assert!(matches!(
        session.verify(wrong_lp, &policy),
        Err(CitadelError::WrongLicenseProvider)
    ));

    let mut wrong_lp_commitment = sc;
    wrong_lp_commitment.s_0 = BlsScalar::from(4u64);
    assert!(matches!(
        session.verify(wrong_lp_commitment, &policy),
        Err(CitadelError::WrongLicenseProviderComm)
    ));

    let mut wrong_attr_commitment = sc;
    wrong_attr_commitment.attr_data = JubJubScalar::from(5u64);
    assert!(matches!(
        session.verify(wrong_attr_commitment, &policy),
        Err(CitadelError::WrongAttributeDataComm)
    ));

    let mut wrong_challenge_commitment = sc;
    wrong_challenge_commitment.c = JubJubScalar::from(6u64);
    assert!(matches!(
        session.verify(wrong_challenge_commitment, &policy),
        Err(CitadelError::WrongChallenge)
    ));

    let mut wrong_challenge_opening = sc;
    wrong_challenge_opening.s_2 = JubJubScalar::from(19u64);
    assert!(matches!(
        session.verify(wrong_challenge_opening, &policy),
        Err(CitadelError::WrongChallengeComm)
    ));
}

#[test]
fn session_policy_enforces_attribute_openings_and_root() {
    let mut sc = cookie();
    let opening = AttributeOpening {
        schema_id: BlsScalar::from(21u64),
        canonical_attributes_digest: BlsScalar::from(22u64),
        r_attr: JubJubScalar::from(23u64),
    };
    sc.attr_data = compute_attr_data(
        DEFAULT_DEPLOYMENT,
        opening.schema_id,
        opening.canonical_attributes_digest,
        opening.r_attr,
    );
    sc.attr_opening = Some(opening);

    let session = Session::from(&public_inputs(&sc)).expect("valid public inputs should parse");
    let policy = policy(&sc)
        .with_expected_attr_data(sc.attr_data)
        .with_expected_root(session.root)
        .require_attribute_opening();

    session
        .verify(sc, &policy)
        .expect("matching attribute opening and root should verify");

    let mut missing_opening = sc;
    missing_opening.attr_opening = None;
    assert!(matches!(
        session.verify(missing_opening, &policy),
        Err(CitadelError::MissingAttributeOpening)
    ));

    let mut wrong_opening = sc;
    let mut altered_opening = opening;
    altered_opening.canonical_attributes_digest = BlsScalar::from(24u64);
    wrong_opening.attr_opening = Some(altered_opening);
    assert!(matches!(
        session.verify(wrong_opening, &policy),
        Err(CitadelError::WrongAttributeOpening)
    ));

    let wrong_attr_policy = policy.with_expected_attr_data(JubJubScalar::from(25u64));
    assert!(matches!(
        session.verify(sc, &wrong_attr_policy),
        Err(CitadelError::WrongAttributeData)
    ));

    let wrong_root_policy = policy.with_expected_root(BlsScalar::from(26u64));
    assert!(matches!(
        session.verify(sc, &wrong_root_policy),
        Err(CitadelError::WrongRoot)
    ));
}
