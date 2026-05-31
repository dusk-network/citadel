// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Protocol assets exchanged by users, license providers, and service providers.

mod license;
mod request;
mod session;

pub use license::{License, LicenseContext, LicenseOptions, LicenseOrigin};
pub use request::Request;
pub use session::{AttributeOpening, Session, SessionCookie, SessionPolicy};

#[cfg(feature = "zk")]
pub(crate) use license::{LIC_PLAINTEXT_SIZE, decode_license_plaintext};
pub(crate) use request::REQ_PLAINTEXT_SIZE;
