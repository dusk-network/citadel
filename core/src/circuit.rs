// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{gadgets, SessionCookie};
use dusk_plonk::prelude::*;

#[allow(dead_code)]
pub const CAPACITY: usize = 15; // capacity required for the setup
pub const DEPTH: usize = 16; // depth of the n-ary Merkle tree

#[derive(Default, Debug)]
pub struct LicenseCircuit {
    gp: gadgets::GadgetParameters<DEPTH>,
    sc: SessionCookie,
}

impl LicenseCircuit {
    pub fn new(gp: &gadgets::GadgetParameters<DEPTH>, sc: &SessionCookie) -> Self {
        Self { gp: *gp, sc: *sc }
    }
}

impl Circuit for LicenseCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        gadgets::use_license(composer, &self.gp, &self.sc)?;
        Ok(())
    }
}