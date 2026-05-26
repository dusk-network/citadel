// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::*;
use phoenix_core::{PublicKey, SecretKey};
use rand_core::OsRng;

use zk_citadel::{
    Error as CitadelError, License, LicenseOrigin, Request, Session, SessionCookie,
    helpers::{
        DEFAULT_DEPLOYMENT, Deployment, PI_COM_1_X, PI_COM_1_Y, lp_commitment, session_hash,
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
        deployment_id: DEFAULT_DEPLOYMENT.id,
        pk_sp: PublicKey::from(&sk_sp),
        r: BlsScalar::from(11u64),
        session_id: BlsScalar::from(12u64),
        pk_lp: PublicKey::from(&sk_lp),
        attr_data: JubJubScalar::from(13u64),
        c: JubJubScalar::from(14u64),
        s_0: BlsScalar::from(15u64),
        s_1: JubJubScalar::from(16u64),
        s_2: JubJubScalar::from(17u64),
    }
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
        session_hash(DEFAULT_DEPLOYMENT, pk_sp_a, sc.r),
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
    assert_eq!(req.deployment_id, deployment.id);

    let license = License::new_with_deployment(
        &attr_data,
        &sk_lp,
        &LicenseOrigin::FromRequest(Box::new(req)),
        deployment,
        &mut OsRng,
    )
    .expect("matching LP and deployment should issue from request");
    assert_eq!(license.deployment_id, deployment.id);

    let wrong_deployment_req =
        Request::new_with_deployment(&sk_user, &pk_user, &pk_lp, deployment, &mut OsRng)
            .expect("request should be created");
    assert!(
        License::new_with_deployment(
            &attr_data,
            &sk_lp,
            &LicenseOrigin::FromRequest(Box::new(wrong_deployment_req)),
            other_deployment,
            &mut OsRng,
        )
        .is_err()
    );

    let wrong_lp_req =
        Request::new_with_deployment(&sk_user, &pk_user, &pk_lp, deployment, &mut OsRng)
            .expect("request should be created");
    assert!(
        License::new_with_deployment(
            &attr_data,
            &sk_other_lp,
            &LicenseOrigin::FromRequest(Box::new(wrong_lp_req)),
            deployment,
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

    let license = License::new_with_deployment(
        &attr_data,
        &sk_lp,
        &LicenseOrigin::FromPublicKey(Box::new(pk_user)),
        deployment,
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
}

#[test]
fn session_verify_reports_each_cookie_opening_failure() {
    let sc = cookie();
    let session = Session::from(&public_inputs(&sc)).expect("valid public inputs should parse");

    session
        .verify(sc)
        .expect("matching cookie should open the session");

    let mut wrong_deployment = sc;
    wrong_deployment.deployment_id = BlsScalar::from(1u64);
    assert!(matches!(
        session.verify(wrong_deployment),
        Err(CitadelError::WrongDeployment)
    ));

    let mut wrong_session_id = sc;
    wrong_session_id.session_id = BlsScalar::from(2u64);
    assert!(matches!(
        session.verify(wrong_session_id),
        Err(CitadelError::WrongSessionId)
    ));

    let mut wrong_session_hash = sc;
    wrong_session_hash.r = BlsScalar::from(3u64);
    assert!(matches!(
        session.verify(wrong_session_hash),
        Err(CitadelError::WrongSessionHash)
    ));

    let mut wrong_lp_commitment = sc;
    wrong_lp_commitment.s_0 = BlsScalar::from(4u64);
    assert!(matches!(
        session.verify(wrong_lp_commitment),
        Err(CitadelError::WrongLicenseProviderComm)
    ));

    let mut wrong_attr_commitment = sc;
    wrong_attr_commitment.attr_data = JubJubScalar::from(5u64);
    assert!(matches!(
        session.verify(wrong_attr_commitment),
        Err(CitadelError::WrongAttributeDataComm)
    ));

    let mut wrong_challenge_commitment = sc;
    wrong_challenge_commitment.c = JubJubScalar::from(6u64);
    assert!(matches!(
        session.verify(wrong_challenge_commitment),
        Err(CitadelError::WrongChallengeComm)
    ));
}
