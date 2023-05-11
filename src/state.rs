// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use rand_core::{CryptoRng, RngCore};

use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use dusk_poseidon::tree::{PoseidonLeaf, PoseidonTree};
use nstack::annotation::Keyed;

use crate::license::License;

pub struct State<const DEPTH: usize> {
    pub tree: PoseidonTree<DataLeaf, (), DEPTH>,
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

        self.tree.push(DataLeaf::new(license_hash, 0));
    }
}

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct DataLeaf {
    license_hash: BlsScalar,

    pos: u64,
}

// Keyed needs to be implemented for a leaf type and the tree key.
impl Keyed<()> for DataLeaf {
    fn key(&self) -> &() {
        &()
    }
}

impl DataLeaf {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let license_hash = BlsScalar::random(rng);
        let pos = 0;

        Self { license_hash, pos }
    }
    pub fn new(hash: BlsScalar, n: u64) -> DataLeaf {
        DataLeaf {
            license_hash: hash,
            pos: n,
        }
    }
}

impl From<u64> for DataLeaf {
    fn from(n: u64) -> DataLeaf {
        DataLeaf {
            license_hash: BlsScalar::from(n),
            pos: n,
        }
    }
}

impl PoseidonLeaf for DataLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        // the license hash (the leaf) is computed into the circuit
        self.license_hash
    }

    fn pos(&self) -> &u64 {
        &self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}
