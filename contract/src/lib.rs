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

pub(crate) mod collection;
mod error;
mod license_types;
#[cfg(target_family = "wasm")]
mod state;

pub use license_types::{LicenseSession, LicenseSessionId, UseLicenseArg};

const VD_LICENSE_CIRCUIT: &[u8] = include_bytes!("../../target/verifier");

/// Verifier data for the `License` circuit.
#[allow(dead_code)]
pub const fn verifier_data_license_circuit() -> &'static [u8] {
    VD_LICENSE_CIRCUIT
}

#[cfg(target_family = "wasm")]
#[path = ""]
mod wasm {
    use super::*;

    use core::cell::UnsafeCell;

    use state::LicenseContractState;

    struct ContractState(UnsafeCell<LicenseContractState>);

    unsafe impl Sync for ContractState {}

    impl ContractState {
        const fn new() -> Self {
            Self(UnsafeCell::new(LicenseContractState::new()))
        }

        unsafe fn with_mut<R>(&self, f: impl FnOnce(&mut LicenseContractState) -> R) -> R {
            f(unsafe { &mut *self.0.get() })
        }

        unsafe fn with_ref<R>(&self, f: impl FnOnce(&LicenseContractState) -> R) -> R {
            f(unsafe { &*self.0.get() })
        }
    }

    static STATE: ContractState = ContractState::new();

    #[unsafe(no_mangle)]
    unsafe fn issue_license(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |(license, hash)| unsafe {
            STATE.with_mut(|state| state.issue_license(license, hash))
        })
    }

    #[unsafe(no_mangle)]
    unsafe fn get_licenses(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |user_public_key| unsafe {
            STATE.with_mut(|state| state.get_licenses(user_public_key))
        })
    }

    #[unsafe(no_mangle)]
    unsafe fn get_merkle_opening(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |position| unsafe {
            STATE.with_mut(|state| state.get_merkle_opening(position))
        })
    }

    #[unsafe(no_mangle)]
    unsafe fn use_license(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |use_license_arg| unsafe {
            STATE.with_mut(|state| state.use_license(use_license_arg))
        })
    }

    #[unsafe(no_mangle)]
    unsafe fn get_session(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |nullifier| unsafe {
            STATE.with_ref(|state| state.get_session(nullifier))
        })
    }

    #[unsafe(no_mangle)]
    unsafe fn request_license(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |_: ()| unsafe {
            STATE.with_ref(|state| state.request_license())
        })
    }

    #[unsafe(no_mangle)]
    unsafe fn get_info(arg_len: u32) -> u32 {
        dusk_core::abi::wrap_call(arg_len, |_: ()| unsafe {
            STATE.with_ref(|state| state.get_info())
        })
    }
}
