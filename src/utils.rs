// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::license::{CitadelProverParameters, License, Request, SessionCookie};
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_poseidon::sponge;
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::{CryptoRng, RngCore};

// Example values
const USER_ATTRIBUTES: u64 = 112233445566778899u64;
const CHALLENGE: u64 = 20221126u64;

pub struct CitadelUtils {}

impl CitadelUtils {
    pub fn compute_random_license<
        R: RngCore + CryptoRng,
        const DEPTH: usize,
        const ARITY: usize,
    >(
        rng: &mut R,
        ssk: SecretSpendKey,
        psk: PublicSpendKey,
        ssk_lp: SecretSpendKey,
        psk_lp: PublicSpendKey,
    ) -> (License, Opening<(), DEPTH, ARITY>) {
        // First, the user computes these values and requests a License
        let lsa = psk.gen_stealth_address(&JubJubScalar::random(rng));
        let lsk = ssk.sk_r(&lsa);
        let k_lic = JubJubAffine::from(
            GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]),
        );
        let req = Request::new(&psk_lp, &lsa, &k_lic, rng);

        // Second, the LP computes these values and grants the License
        let attr = JubJubScalar::from(USER_ATTRIBUTES);
        let mut lic = License::new(&attr, &ssk_lp, &req, rng);

        let mut tree = Tree::<(), DEPTH, ARITY>::new();
        let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

        let item = Item {
            hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
            data: (),
        };

        lic.pos = 0;
        tree.insert(lic.pos, item);

        let merkle_proof = tree.opening(lic.pos).expect("Tree was read successfully");

        (lic, merkle_proof)
    }

    pub fn compute_citadel_parameters<
        R: RngCore + CryptoRng,
        const DEPTH: usize,
        const ARITY: usize,
    >(
        rng: &mut R,
        ssk: SecretSpendKey,
        psk: PublicSpendKey,
        ssk_lp: SecretSpendKey,
        psk_lp: PublicSpendKey,
    ) -> (CitadelProverParameters<DEPTH, ARITY>, SessionCookie) {
        let (lic, merkle_proof) =
            Self::compute_random_license::<R, DEPTH, ARITY>(rng, ssk, psk, ssk_lp, psk_lp);

        let c = JubJubScalar::from(CHALLENGE);
        let (cpp, sc) = CitadelProverParameters::compute_parameters(
            &ssk,
            &lic,
            &psk_lp,
            &psk_lp,
            &c,
            rng,
            merkle_proof,
        );
        (cpp, sc)
    }
}
