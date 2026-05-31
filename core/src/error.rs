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
    /// The public input vector has the wrong length
    InvalidPublicInputs,
    /// A public commitment point is malformed or not allowed
    InvalidCommitment,
    /// The session ID in the cookie does not match the session
    WrongSessionId,
    /// The deployment metadata in the cookie does not match this verifier
    WrongDeployment,
    /// The cookie object version does not match the selected policy
    WrongCookieVersion,
    /// The cookie mode does not match the selected policy
    WrongCookieMode,
    /// The policy ID in the cookie does not match the selected policy
    WrongPolicyId,
    /// The cookie SP key does not match the selected policy
    WrongServiceProvider,
    /// The cookie LP key does not match the selected policy
    WrongLicenseProvider,
    /// The disclosed challenge does not match the selected policy
    WrongChallenge,
    /// The disclosed attribute data does not match the selected policy
    WrongAttributeData,
    /// The session root does not satisfy the selected policy
    WrongRoot,
    /// A required digest-style attribute opening is missing
    MissingAttributeOpening,
    /// A supplied attribute opening does not match `attr_data`
    WrongAttributeOpening,
    /// The commitment to the public key of the License Provider is incorrect
    WrongLicenseProviderComm,
    /// The commitment to the attribute data is incorrect
    WrongAttributeDataComm,
    /// The commitment to the challenge is incorrect
    WrongChallengeComm,
    /// The result of the session hash is incorrect
    WrongSessionHash,
    /// A public key in the cookie or selected policy is malformed
    InvalidPublicKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Citadel Error: {:?}", &self)
    }
}
