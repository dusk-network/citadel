// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This package contains the core implementation of Citadel, a self-sovereign identity protocol for
//! decentralized networks, allowing users to receive licenses issued by license providers (LP), and
//! to use them to prove sensitive information in zero-knowledge to service providers (SP).
//!
//! Reference: <https://arxiv.org/pdf/2301.09378>
//!
//! **DISCLAIMER**: this package **has not gone through an exhaustive security analysis**,
//! so it is not intended to be used in a production environment, only for academic purposes.

#![deny(missing_docs)]

mod error;

/// Protocol assets exchanged by Citadel participants.
pub mod assets;

/// Protocol helper functions and constants shared by the off-chain API,
/// circuit gadgets, tests, and benchmarks.
///
/// This module contains the fixed public-input order, Merkle arity,
/// deployment-bound domain separation helpers, and the canonical hash/KDF
/// helpers used by Citadel.
pub mod helpers;

/// Citadel-specific Schnorr signature wrappers.
pub mod signatures;

/// Zero-knowledge circuits and reusable gadgets.
#[cfg(feature = "zk")]
pub mod zk;

pub use assets::{
    AttributeOpening, IssuerIdentifier, License, LicenseContext, LicenseOptions, LicenseOrigin,
    LicensePayload, Request, Session, SessionCookie, SessionPolicy,
};
pub use error::Error;
pub use signatures::{LicenseSignature, SessionAuthSignature};
#[cfg(feature = "zk")]
pub use zk::{circuit, gadgets};
