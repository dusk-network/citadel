// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(target_family = "wasm", no_std)]
#![cfg(target_family = "wasm")]
#![deny(unused_crate_dependencies)]
#![deny(unused_extern_crates)]

extern crate alloc;
extern crate self as license_contract;

pub(crate) mod collection;
pub(crate) mod error;
pub(crate) mod license_types;
#[cfg(target_family = "wasm")]
mod state;

pub use license_types::{LicenseSession, LicenseSessionId, UseLicenseArg};

const VD_LICENSE_CIRCUIT: &[u8] = include_bytes!("../../target/verifier");

/// Verifier data for the `License` circuit.
#[allow(dead_code)]
pub const fn verifier_data_license_circuit() -> &'static [u8] {
    VD_LICENSE_CIRCUIT
}
