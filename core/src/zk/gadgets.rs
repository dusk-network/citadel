// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{
    EDWARDS_D, GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS, GENERATOR_NUMS_EXTENDED, dhke,
};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, HashGadget};
use ff::Field;
use phoenix_core::{PublicKey, SecretKey, aes::decrypt};
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    License, SessionCookie,
    assets::{LIC_PLAINTEXT_SIZE, decode_license_plaintext},
    helpers::{
        COOKIE_MODE_BASE, CitadelDomain, DEFAULT_DEPLOYMENT, OBJECT_VERSION_V1,
        license_encryption_salt, license_key, lp_commitment, session_auth, session_hash,
        session_id,
    },
    signatures::{LicenseSignature, SessionAuthSignature},
};

use poseidon_merkle::zk::opening_gadget;

/// The [`use_license`] gadget for the [`LicenseCircuit`](crate::zk::circuit::LicenseCircuit).
/// It is meant to use Citadel licenses on-chain. Out of this circuit,
/// the generated public inputs vector collects these values in that particular order:
///
/// session_id
/// session_hash
/// com_0
/// com_1.x
/// com_1.y
/// com_2.x
/// com_2.y
/// root
pub fn use_license<const DEPTH: usize>(
    composer: &mut Composer,
    gp: &GadgetParameters<DEPTH>,
    sc: &SessionCookie,
) -> Result<(), Error> {
    let deployment = DEFAULT_DEPLOYMENT;

    // APPEND THE LICENSE PUBLIC KEYS OF THE USER
    let lpk = composer.append_point(gp.lpk);
    let lpk_p = composer.append_point(gp.lpk_p);
    assert_valid_witness_point(composer, lpk);
    assert_valid_witness_point(composer, lpk_p);

    // APPEND PUBLIC INPUTS IN THE SPECIFIED ORDER
    let c = composer.append_witness(sc.c);
    let session_id_pi = composer.append_public(sc.session_id);
    let session_hash_pi = composer.append_public(gp.session_hash);
    let com_0_pi = composer.append_public(gp.com_0);
    let com_1_pi = composer.append_public_point(gp.com_1);
    let com_2_pi = composer.append_public_point(gp.com_2);
    let root_pi = composer.append_public(gp.merkle_proof.root().hash);

    // COMPUTE THE SESSION ID
    let session_id_ctx = composer.append_constant(deployment.context(CitadelDomain::SessionId));
    let session_id = HashGadget::digest(
        composer,
        Domain::Other,
        &[session_id_ctx, *lpk_p.x(), *lpk_p.y(), c],
    );

    composer.assert_equal(session_id[0], session_id_pi);

    // VERIFY THE LICENSE SIGNATURE
    let sig_lic_z = composer.append_witness(*gp.sig_lic.z());
    let sig_lic_r = composer.append_point(gp.sig_lic.R());
    assert_valid_witness_point(composer, sig_lic_r);
    let pk_lp_a = JubJubAffine::from(sc.pk_lp.A());
    let pk_lp = composer.append_point(pk_lp_a);
    assert_valid_witness_point(composer, pk_lp);
    let attr_data = composer.append_witness(sc.attr_data);

    let license_sig_ctx =
        composer.append_constant(deployment.context(CitadelDomain::LicenseSigMsg));
    let message = HashGadget::digest(
        composer,
        Domain::Other,
        &[license_sig_ctx, *lpk.x(), *lpk.y(), attr_data],
    );
    verify_license_signature(
        composer, deployment, sig_lic_z, sig_lic_r, pk_lp, message[0],
    )?;

    // COMMIT TO THE PK_LP USING A HASH FUNCTION
    let s_0 = composer.append_witness(sc.s_0);
    let lp_commitment_ctx =
        composer.append_constant(deployment.context(CitadelDomain::LpCommitment));
    let com_0 = HashGadget::digest(
        composer,
        Domain::Other,
        &[lp_commitment_ctx, *pk_lp.x(), *pk_lp.y(), s_0],
    );

    composer.assert_equal(com_0[0], com_0_pi);

    // COMMIT TO THE ATTRIBUTE DATA
    let s_1 = composer.append_witness(sc.s_1);
    let pc_1_1 = composer.component_mul_generator(attr_data, GENERATOR)?;
    let pc_1_2 = composer.component_mul_generator(s_1, GENERATOR_NUMS)?;
    let com_1 = composer.component_add_point(pc_1_1, pc_1_2);

    composer.assert_equal_point(com_1, com_1_pi);

    // COMMIT TO THE CHALLENGE
    let s_2 = composer.append_witness(sc.s_2);
    let pc_2_1 = composer.component_mul_generator(c, GENERATOR)?;
    let pc_2_2 = composer.component_mul_generator(s_2, GENERATOR_NUMS)?;
    let com_2 = composer.component_add_point(pc_2_1, pc_2_2);

    composer.assert_equal_point(com_2, com_2_pi);

    // VERIFY THE SESSION AUTHORIZATION SIGNATURE
    let session_auth_ctx = composer.append_constant(deployment.context(CitadelDomain::SessionAuth));
    let session_auth = HashGadget::digest(
        composer,
        Domain::Other,
        &[
            session_auth_ctx,
            session_id_pi,
            session_hash_pi,
            com_0_pi,
            *com_1_pi.x(),
            *com_1_pi.y(),
            *com_2_pi.x(),
            *com_2_pi.y(),
            root_pi,
        ],
    );

    let sig_session_auth_z = composer.append_witness(*gp.sig_session_auth.z());
    let sig_session_auth_r = composer.append_point(gp.sig_session_auth.R());
    let sig_session_auth_r_p = composer.append_point(gp.sig_session_auth.R_prime());
    assert_valid_witness_point(composer, sig_session_auth_r);
    assert_valid_witness_point(composer, sig_session_auth_r_p);

    verify_session_auth_signature(
        composer,
        deployment,
        sig_session_auth_z,
        sig_session_auth_r,
        sig_session_auth_r_p,
        lpk,
        lpk_p,
        session_auth[0],
    )?;

    // COMPUTE THE HASH OF THE LICENSE
    let license_hash_ctx = composer.append_constant(deployment.context(CitadelDomain::LicenseHash));
    let license_hash = HashGadget::digest(
        composer,
        Domain::Other,
        &[license_hash_ctx, *lpk.x(), *lpk.y()],
    );

    // VERIFY THE MERKLE PROOF
    let root = opening_gadget(composer, &gp.merkle_proof, license_hash[0]);
    composer.assert_equal(root, root_pi);

    Ok(())
}

fn verify_license_signature(
    composer: &mut Composer,
    deployment: crate::helpers::Deployment,
    z: Witness,
    r: WitnessPoint,
    pk: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    let ctx = composer.append_constant(deployment.context(CitadelDomain::LicenseSigChallenge));
    let challenge = HashGadget::digest_truncated(
        composer,
        Domain::Other,
        &[ctx, *pk.x(), *pk.y(), *r.x(), *r.y(), msg],
    )[0];

    let lhs = composer.component_mul_generator(z, GENERATOR)?;
    let challenge_pk = composer.component_mul_point(challenge, pk);
    let rhs = composer.component_add_point(r, challenge_pk);
    composer.assert_equal_point(lhs, rhs);

    Ok(())
}

fn verify_session_auth_signature(
    composer: &mut Composer,
    deployment: crate::helpers::Deployment,
    z: Witness,
    r: WitnessPoint,
    r_p: WitnessPoint,
    pk: WitnessPoint,
    pk_p: WitnessPoint,
    msg: Witness,
) -> Result<(), Error> {
    let ctx = composer.append_constant(deployment.context(CitadelDomain::SessionSigChallenge));
    let challenge = HashGadget::digest_truncated(
        composer,
        Domain::Other,
        &[
            ctx,
            *pk.x(),
            *pk.y(),
            *pk_p.x(),
            *pk_p.y(),
            *r.x(),
            *r.y(),
            *r_p.x(),
            *r_p.y(),
            msg,
        ],
    )[0];

    let lhs = composer.component_mul_generator(z, GENERATOR)?;
    let challenge_pk = composer.component_mul_point(challenge, pk);
    let rhs = composer.component_add_point(r, challenge_pk);
    composer.assert_equal_point(lhs, rhs);

    let lhs_prime = composer.component_mul_generator(z, GENERATOR_NUMS)?;
    let challenge_pk_prime = composer.component_mul_point(challenge, pk_p);
    let rhs_prime = composer.component_add_point(r_p, challenge_pk_prime);
    composer.assert_equal_point(lhs_prime, rhs_prime);

    Ok(())
}

fn assert_valid_witness_point(composer: &mut Composer, point: WitnessPoint) {
    assert_on_curve(composer, point);
    assert_not_identity(composer, point);

    // Jubjub has cofactor 8; multiplying by 8 must not collapse a valid
    // prime-order witness point to the identity.
    let two_p = composer.component_add_point(point, point);
    let four_p = composer.component_add_point(two_p, two_p);
    let eight_p = composer.component_add_point(four_p, four_p);
    assert_not_identity(composer, eight_p);
}

fn assert_on_curve(composer: &mut Composer, point: WitnessPoint) {
    let x = *point.x();
    let y = *point.y();
    let x2 = composer.gate_mul(Constraint::new().mult(1).a(x).b(x));
    let y2 = composer.gate_mul(Constraint::new().mult(1).a(y).b(y));
    let x2_y2 = composer.gate_mul(Constraint::new().mult(1).a(x2).b(y2));
    let curve = composer.gate_add(
        Constraint::new()
            .left(1)
            .right(-BlsScalar::one())
            .fourth(-EDWARDS_D)
            .constant(-BlsScalar::one())
            .a(y2)
            .b(x2)
            .d(x2_y2),
    );
    composer.assert_equal_constant(curve, BlsScalar::zero(), None);
}

fn assert_not_identity(composer: &mut Composer, point: WitnessPoint) {
    let x = *point.x();
    let y = *point.y();
    let x2 = composer.gate_mul(Constraint::new().mult(1).a(x).b(x));
    let y_minus_one = composer.gate_add(Constraint::new().left(1).constant(-BlsScalar::one()).a(y));
    let y_minus_one2 = composer.gate_mul(Constraint::new().mult(1).a(y_minus_one).b(y_minus_one));
    let distance = composer.gate_add(Constraint::new().left(1).right(1).a(x2).b(y_minus_one2));

    let inverse_value =
        Option::<BlsScalar>::from(composer[distance].invert()).unwrap_or(BlsScalar::zero());
    let inverse = composer.append_witness(inverse_value);
    let non_zero = composer.gate_mul(Constraint::new().mult(1).a(distance).b(inverse));
    composer.assert_equal_constant(non_zero, BlsScalar::one(), None);
}

/// The parameters required by the [`use_license`] gadget
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[derive(Debug, Clone, Copy)]
pub struct GadgetParameters<const DEPTH: usize> {
    lpk: JubJubAffine,         // license public key
    lpk_p: JubJubAffine,       // license public key prime
    sig_lic: LicenseSignature, // signature of the license

    com_0: BlsScalar,      // Hash commitment 0
    com_1: JubJubExtended, // Pedersen Commitment 1
    com_2: JubJubExtended, // Pedersen Commitment 2

    session_hash: BlsScalar,                // hash of the session
    sig_session_auth: SessionAuthSignature, // signature of the public session tuple
    merkle_proof: Opening<(), DEPTH>,       // Merkle proof for the Proof of Validity
}

impl<const DEPTH: usize> Default for GadgetParameters<DEPTH> {
    fn default() -> Self {
        let mut tree = Tree::new();
        let item = Item {
            hash: BlsScalar::zero(),
            data: (),
        };
        tree.insert(0, item);
        let merkle_proof = tree.opening(0).expect("There is a leaf at position 0");
        Self {
            lpk: JubJubAffine::default(),
            lpk_p: JubJubAffine::default(),
            sig_lic: LicenseSignature::default(),

            com_0: BlsScalar::default(),
            com_1: JubJubExtended::default(),
            com_2: JubJubExtended::default(),

            session_hash: BlsScalar::default(),
            sig_session_auth: SessionAuthSignature::default(),
            merkle_proof,
        }
    }
}

impl<const DEPTH: usize> GadgetParameters<DEPTH> {
    /// Method to generate the [`GadgetParameters`] struct
    #[allow(clippy::too_many_arguments)]
    pub fn compute_parameters<R: RngCore + CryptoRng>(
        sk: &SecretKey,
        lic: &License,
        pk_lp: &PublicKey,
        pk_sp: &PublicKey,
        c: &JubJubScalar,
        mut rng: &mut R,
        merkle_proof: Opening<(), DEPTH>,
    ) -> Result<(Self, SessionCookie), phoenix_core::Error> {
        if lic.version != OBJECT_VERSION_V1 || lic.deployment_id != DEFAULT_DEPLOYMENT.id {
            return Err(phoenix_core::Error::InvalidData);
        }

        let lsk = sk.gen_note_sk(&lic.lsa);
        let k_lic = dhke(sk.a(), lic.lsa.R());

        let salt = license_encryption_salt(DEFAULT_DEPLOYMENT, lic.version, &lic.lsa);
        let dec: [u8; LIC_PLAINTEXT_SIZE] = match decrypt(&k_lic, &salt, &lic.enc) {
            Ok(dec) => dec,
            Err(_err) => {
                let k_lic = license_key(
                    DEFAULT_DEPLOYMENT,
                    *lsk.as_ref(),
                    JubJubAffine::from(lic.lsa.note_pk().as_ref()),
                    JubJubAffine::from(lic.lsa.R()),
                );

                decrypt(&k_lic, &salt, &lic.enc)?
            }
        };

        let (sig_lic, attr_data, context) = decode_license_plaintext(&dec)?;
        if context.version != lic.version
            || context.deployment_id != lic.deployment_id
            || context.issuer != *pk_lp
        {
            return Err(phoenix_core::Error::InvalidData);
        }

        let lpk = JubJubAffine::from(*lic.lsa.note_pk().as_ref());
        let lpk_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * lsk.as_ref());
        let pk_lp_a = JubJubAffine::from(*pk_lp.A());
        let message = crate::helpers::license_sig_message(DEFAULT_DEPLOYMENT, lpk, attr_data);
        if !sig_lic.verify(DEFAULT_DEPLOYMENT, pk_lp_a, message) {
            return Err(phoenix_core::Error::InvalidData);
        }

        let s_0 = BlsScalar::random(&mut rng);
        let s_1 = JubJubScalar::random(&mut rng);
        let s_2 = JubJubScalar::random(&mut rng);

        let pk_sp_a = JubJubAffine::from(*pk_sp.A());
        let r_session = BlsScalar::random(&mut rng);

        let session_hash = session_hash(DEFAULT_DEPLOYMENT, pk_sp_a, r_session);
        let session_id = session_id(DEFAULT_DEPLOYMENT, lpk_p, *c);

        let com_0 = lp_commitment(DEFAULT_DEPLOYMENT, pk_lp_a, s_0);
        let com_1 = (GENERATOR_EXTENDED * attr_data) + (GENERATOR_NUMS_EXTENDED * s_1);
        let com_2 = (GENERATOR_EXTENDED * c) + (GENERATOR_NUMS_EXTENDED * s_2);
        let root = merkle_proof.root().hash;
        let auth = session_auth(
            DEFAULT_DEPLOYMENT,
            session_id,
            session_hash,
            com_0,
            JubJubAffine::from(com_1),
            JubJubAffine::from(com_2),
            root,
        );
        let sig_session_auth =
            SessionAuthSignature::sign(rng, DEFAULT_DEPLOYMENT, lsk.as_ref(), lpk, lpk_p, auth);

        Ok((
            Self {
                lpk,
                lpk_p,
                sig_lic,

                com_0,
                com_1,
                com_2,

                session_hash,
                sig_session_auth,
                merkle_proof,
            },
            SessionCookie {
                version: OBJECT_VERSION_V1,
                deployment_id: DEFAULT_DEPLOYMENT.id,
                cookie_mode: COOKIE_MODE_BASE,
                policy_id: BlsScalar::zero(),
                pk_sp: *pk_sp,
                r_session,
                session_id,
                pk_lp: *pk_lp,
                attr_data,
                attr_opening: None,
                c: *c,
                s_0,
                s_1,
                s_2,
                binding_data: [BlsScalar::zero(); 4],
            },
        ))
    }
}
