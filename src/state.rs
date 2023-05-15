// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_pki::ViewKey;
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use dusk_poseidon::tree::{PoseidonBranch, PoseidonLeaf, PoseidonTree};
use nstack::annotation::Keyed;

use crate::license::License;

pub struct State<const DEPTH: usize> {
    tree: PoseidonTree<DataLeaf, (), DEPTH>,
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
        self.tree.push(DataLeaf { lic: lic.clone() });
    }

    // TODO: we should update this function when starting to use the new
    // implementation of the Merkle tree
    pub fn get_licenses(&self, vk: &ViewKey) -> Vec<License> {
        let mut lic_vec = Vec::new();
        for i in 0u64..(4u64.pow(DEPTH as u32)) {
            let leaf = self.tree.get(i);

            match leaf {
                Some(leaf) if vk.owns(&leaf.lic.lsa) => {
                    lic_vec.push(leaf.lic);
                }
                _ => break,
            }
        }

        lic_vec
    }
    pub fn get_merkle_proof(&self, lic: &License) -> PoseidonBranch<DEPTH> {
        self.tree
            .branch(lic.pos)
            .expect("Tree was read successfully")
    }
}

#[derive(Default, Clone)]
pub struct DataLeaf {
    pub lic: License,
}

// Keyed needs to be implemented for a leaf type and the tree key.
impl Keyed<()> for DataLeaf {
    fn key(&self) -> &() {
        &()
    }
}

impl PoseidonLeaf for DataLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        let lpk = JubJubAffine::from(self.lic.lsa.pk_r().as_ref());
        sponge::hash(&[lpk.get_x(), lpk.get_y()])
    }

    fn pos(&self) -> &u64 {
        &self.lic.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.lic.pos = pos;
    }
}
