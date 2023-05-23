// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_merkle::poseidon::{Item, Opening, Tree};
use dusk_merkle::Aggregate;
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use std::collections::BTreeMap;

use zk_citadel_shared::License;
use zk_citadel_shared::unit::{PoseidonItem, Unit};

pub struct State<const DEPTH: usize, const ARITY: usize> {
    tree: Tree<Unit, DEPTH, ARITY>,
    licenses: BTreeMap<u64, License>,
}

impl<const DEPTH: usize, const ARITY: usize> Default for State<DEPTH, ARITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize, const ARITY: usize> State<DEPTH, ARITY> {
    pub fn new() -> State<DEPTH, ARITY> {
        State {
            tree: Tree::<Unit, DEPTH, ARITY>::new(),
            licenses: BTreeMap::new(),
        }
    }
    pub fn append_license(&mut self, lic: &mut License) {
        let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

        let item = PoseidonItem {
            hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
            data: Unit,
        };

        lic.pos = self.licenses.len() as u64;
        self.tree.insert(lic.pos, item);
        self.licenses.insert(lic.pos, lic.clone());
    }

    pub fn get_licenses(&self, vk: &ViewKey) -> Vec<License> {
        self.licenses
            .iter()
            .filter_map(|(_, lic)| vk.owns(&lic.lsa).then_some(lic))
            .cloned()
            .collect()
    }

    pub fn get_merkle_proof(&self, lic: &License) -> Opening<Unit, DEPTH, ARITY> {
        self.tree
            .opening(lic.pos)
            .expect("Tree was read successfully")
    }
}
