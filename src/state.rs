// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use dusk_poseidon::tree::{PoseidonBranch, PoseidonLeaf, PoseidonTree};
use nstack::annotation::Keyed;

use crate::license::License;

pub struct State<const DEPTH: usize> {
    pub tree: PoseidonTree<DataLeaf, (), DEPTH>,
}

impl<const DEPTH: usize> Default for State<DEPTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize> State<DEPTH> {
    pub fn new() -> State<DEPTH> {
        State {
            tree: PoseidonTree::<DataLeaf, (), DEPTH>::default(),
        }
    }
    pub fn append_license(&mut self, lic: &License) {
        let lpk = JubJubAffine::from(*lic.lsa.pk_r().as_ref());
        let license_hash = sponge::hash(&[lpk.get_x(), lpk.get_y()]);

        self.tree.push(DataLeaf::new(license_hash));
    }
    pub fn get_merkle_proof(&self, license_hash: &BlsScalar) -> PoseidonBranch<DEPTH> {
        let mut pos = 0;

        for i in 0..(4 ^ DEPTH) {
            let it = i.try_into().unwrap();
            let leaf = self.tree.get(it);

            match leaf {
                Some(leaf) if leaf.license_hash == *license_hash => {
                    pos = it;
                    break;
                }
                _ => (),
            }
        }

        self.tree.branch(pos).expect("Tree was read successfully")
    }
}

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct DataLeaf {
    pub license_hash: BlsScalar,
}

// Keyed needs to be implemented for a leaf type and the tree key.
impl Keyed<()> for DataLeaf {
    fn key(&self) -> &() {
        &()
    }
}

impl DataLeaf {
    pub fn new(hash: BlsScalar) -> DataLeaf {
        DataLeaf { license_hash: hash }
    }
}

impl PoseidonLeaf for DataLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        // the license hash (the leaf) is computed into the circuit
        self.license_hash
    }

    fn pos(&self) -> &u64 {
        &u64::MAX
    }

    #[allow(clippy::no_effect)]
    fn set_pos(&mut self, _pos: u64) {
        ();
    }
}
