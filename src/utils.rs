// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::license::{CitadelProverParameters, License, Request, SessionCookie};
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use dusk_poseidon::sponge;
use ff::Field;
use phoenix_core::{PublicKey as PublicSpendKey, SecretKey as SecretSpendKey};
use poseidon_merkle::{Item, Opening, Tree};
use rand_core::{CryptoRng, RngCore};

// Example values
const ATTRIBUTE_DATA: u64 = 112233445566778899u64;
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
        let lsa = psk.gen_stealth_address(&JubJubScalar::random(&mut *rng));
        let lsk = ssk.sk_r(&lsa);
        let k_lic = JubJubAffine::from(
            GENERATOR_EXTENDED * sponge::truncated::hash(&[(*lsk.as_ref()).into()]),
        );
        let req = Request::new(&psk_lp, &lsa, &k_lic, rng);

        // Second, the LP computes these values and grants the License
        let attr_data = JubJubScalar::from(ATTRIBUTE_DATA);
        let lic = License::new(&attr_data, &ssk_lp, &req, rng);

        let mut tree = Tree::<(), DEPTH, ARITY>::new();
        let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

        let item = Item {
            hash: sponge::hash(&[lpk.get_u(), lpk.get_v()]),
            data: (),
        };

        let pos = 0;
        tree.insert(pos, item);

        let merkle_proof = tree.opening(pos).expect("Tree was read successfully");

        (lic, merkle_proof)
    }

    pub fn compute_citadel_parameters<
        R: RngCore + CryptoRng,
        const DEPTH: usize,
        const ARITY: usize,
    >(
        rng: &mut R,
        ssk: SecretSpendKey,
        psk_lp: PublicSpendKey,
        lic: &License,
        merkle_proof: Opening<(), DEPTH, ARITY>,
    ) -> (CitadelProverParameters<DEPTH, ARITY>, SessionCookie) {
        let c = JubJubScalar::from(CHALLENGE);
        let (cpp, sc) = CitadelProverParameters::compute_parameters(
            &ssk,
            lic,
            &psk_lp,
            &psk_lp,
            &c,
            rng,
            merkle_proof,
        );
        (cpp, sc)
    }
}
