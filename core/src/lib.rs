// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This package contains the core implementation of Citadel, a self-sovereign identity protocol for
//! decentralized networks, allowing users to receive licenses issued by license providers (LP), and
//! to use them to prove sensitive information in zero-knowledge to service providers (SP).
//!
//! Reference: https://arxiv.org/pdf/2301.09378
//!
//! **DISCLAIMER**: this package **has not gone through an exhaustive security analysis**,
//! so it is not intended to be used in a production environment, only for academic purposes.

#![deny(missing_docs)]

mod error;
mod license;
mod request;
mod session;

/// The arithmetic circuit module to use licenses
pub mod circuit;

/// The gadget module required by the license circuit and / or
/// in third party circuits, to use licenses
pub mod gadgets;

pub use license::{License, LicenseOrigin};
pub use request::Request;
pub use session::{Session, SessionCookie};

pub use error::Error;
