// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::collections::BTreeMap;
use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
// use dusk_poseidon::tree::{PoseidonBranch, PoseidonLeaf, PoseidonTree};
use dusk_merkle::poseidon::{Opening, Tree, Item};

// use nstack::annotation::Keyed;

use crate::license::{License, Unit, ARITY};

type PoseidonItem = Item<Unit>;

pub struct State<const DEPTH: usize> {
    tree: Tree<Unit, DEPTH, ARITY>,
    licenses: BTreeMap<u64, License>,
}

impl<const DEPTH: usize> Default for State<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> State<DEPTH> {
    pub fn new() -> State<DEPTH> {
        State {
            tree: Tree::<Unit, DEPTH, ARITY>::new(),
            licenses: BTreeMap::new(),
        }
    }
    pub fn append_license(&mut self, lic: &License) {
        let lpk = JubJubAffine::from(lic.lsa.pk_r().as_ref());

        let item = PoseidonItem {
                hash: sponge::hash(&[lpk.get_x(), lpk.get_y()]),
                data: Unit,
            };

        self.tree.insert(0, item);
        self.licenses.insert( lic.pos, lic.clone() );
    }

    pub fn get_licenses(&self, vk: &ViewKey) -> Vec<License> {
        self.licenses
            .iter()
            .filter_map(|(_, lic)| vk.owns(&lic.lsa).then_some(lic))
            .cloned()
            .collect()
    }

    pub fn get_merkle_proof(&self, lic: &License) -> Opening<Unit, DEPTH, ARITY> {
        self.tree.opening(lic.pos)
            .expect("Tree was read successfully")
    }
}

// #[derive(Default, Clone)]
// pub struct DataLeaf {
//     pub lic: License,
// }

// Keyed needs to be implemented for a leaf type and the tree key.
// impl Keyed<()> for DataLeaf {
//     fn key(&self) -> &() {
//         &()
//     }
// }

// impl PoseidonLeaf for DataLeaf {
//     fn poseidon_hash(&self) -> BlsScalar {
//         let lpk = JubJubAffine::from(self.lic.lsa.pk_r().as_ref());
//         sponge::hash(&[lpk.get_x(), lpk.get_y()])
//     }
//
//     fn pos(&self) -> &u64 {
//         &self.lic.pos
//     }
//
//     fn set_pos(&mut self, pos: u64) {
//         self.lic.pos = pos;
//     }
// }
