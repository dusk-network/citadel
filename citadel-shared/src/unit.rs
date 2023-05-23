// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use dusk_merkle::poseidon::Item;
use dusk_merkle::Aggregate;

#[derive(Default, Debug, Clone, Copy, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct Unit;

impl<const H: usize, const A: usize> Aggregate<H, A> for Unit {
    const EMPTY_SUBTREES: [Self; H] = [Unit; H];

    fn aggregate<'a, I>(_items: I) -> Self
    where
        Self: 'a,
        I: Iterator<Item = &'a Self>,
    {
        Unit
    }
}

pub type PoseidonItem = Item<Unit>;
