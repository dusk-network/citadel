// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::fmt;

/// All possible errors for Citadel
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum Error {
    /// The commitment to the public key of the License Provider is incorrect
    WrongLicenseProviderComm,
    /// The commitment to the attribute data is incorrect
    WrongAttributeDataComm,
    /// The commitment to the challenge is incorrect
    WrongChallengeComm,
    /// The result of the session hash is incorrect
    WrongSessionHash,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Citadel Error: {:?}", &self)
    }
}
