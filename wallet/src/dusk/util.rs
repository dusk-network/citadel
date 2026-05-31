// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use anyhow::{Context, Result, bail};

pub fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let input = input.trim();
    let input = input.strip_prefix("0x").unwrap_or(input);
    if input.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(input).context("invalid hex input")
}

pub fn normalize_contract_id(input: &str) -> Result<String> {
    let bytes = decode_hex(input)?;
    if bytes.len() != 32 {
        bail!("contract ID must be exactly 32 bytes");
    }
    Ok(hex::encode(bytes))
}
