// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Read-only contract queries over RUES.
//!
//! The wallet uses the Dusk wallet library for submitted transactions and this
//! module for direct read-only queries, keeping query decoding close to the
//! Citadel contract payload definitions.

use std::ops::Range;

use anyhow::{Context, Result, bail};

use crate::citadel;

use super::util::normalize_contract_id;

const REQUIRED_RUSK_VERSION: &str = "1.0.0-rc.0";

pub struct Dusk {
    state_url: String,
    http: reqwest::Client,
}

/// Validated high-level state returned by the active Citadel contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CitadelQuery {
    pub licenses: u32,
    pub tree_len: u32,
    pub sessions: u32,
    pub accepted_roots: u32,
    pub current_root: dusk_bls12_381::BlsScalar,
}

impl Dusk {
    pub fn new(state_url: impl Into<String>) -> Self {
        Self {
            state_url: state_url.into(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn citadel_info(&self, contract_id: &str) -> Result<CitadelQuery> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize_unit()?;
        let response = self
            .query_bytes(&contract_id, "get_state_info", request, false)
            .await?;
        let info = citadel::decode_state_info(&response)?;
        citadel::validate_contract_info(&info)?;

        Ok(CitadelQuery {
            licenses: info.licenses,
            tree_len: info.tree_len,
            sessions: info.sessions,
            accepted_roots: info.accepted_roots,
            current_root: info.current_root,
        })
    }

    pub async fn metadata(&self, contract_id: &str) -> Result<citadel::DeploymentMetadata> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize_unit()?;
        let response = self
            .query_bytes(&contract_id, "get_metadata", request, false)
            .await?;
        let metadata = citadel::decode_metadata(&response)?;
        citadel::validate_metadata(&metadata)?;
        Ok(metadata)
    }

    pub async fn current_root(&self, contract_id: &str) -> Result<dusk_bls12_381::BlsScalar> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize_unit()?;
        let response = self
            .query_bytes(&contract_id, "get_current_root", request, false)
            .await?;
        citadel::decode_current_root(&response)
    }

    pub async fn accepted_roots(
        &self,
        contract_id: &str,
    ) -> Result<Vec<dusk_bls12_381::BlsScalar>> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize_unit()?;
        let response = self
            .query_bytes(&contract_id, "get_accepted_roots", request, false)
            .await?;
        citadel::decode_accepted_roots(&response)
    }

    pub async fn licenses(
        &self,
        contract_id: &str,
        block_heights: Range<u64>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        self.positioned_blob_feed(contract_id, "get_licenses", block_heights)
            .await
    }

    pub async fn license(&self, contract_id: &str, position: u64) -> Result<Option<Vec<u8>>> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize::<u64, 1024>(&position)?;
        let response = self
            .query_bytes(&contract_id, "get_license", request, false)
            .await?;
        citadel::decode_blob_option(&response, "get_license")
    }

    pub async fn session(
        &self,
        contract_id: &str,
        session_id: dusk_bls12_381::BlsScalar,
    ) -> Result<Option<citadel::LicenseSession>> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request =
            citadel::serialize::<citadel::LicenseSessionId, 1024>(&citadel::LicenseSessionId {
                id: session_id,
            })?;
        let response = self
            .query_bytes(&contract_id, "get_session", request, false)
            .await?;
        citadel::decode_session(&response)
    }

    async fn positioned_blob_feed(
        &self,
        contract_id: &str,
        method: &str,
        block_heights: Range<u64>,
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize::<Range<u64>, 1024>(&block_heights)?;
        let mut response = self
            .query_response(&contract_id, method, request, true)
            .await?;
        let mut buffer = Vec::new();
        let mut items = Vec::new();

        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("failed to read {method} feed"))?
        {
            if chunk.is_empty() {
                continue;
            }
            buffer.extend_from_slice(&chunk);
            drain_positioned_blob_feed_items(&mut buffer, &mut items);
        }

        if !buffer.is_empty()
            && let Ok(hex_text) = std::str::from_utf8(&buffer)
            && let Ok(decoded) = hex::decode(hex_text.trim())
        {
            buffer = decoded;
            drain_positioned_blob_feed_items(&mut buffer, &mut items);
        }

        if !buffer.is_empty() {
            bail!("failed to decode {method} feed item");
        }

        Ok(items)
    }

    pub async fn merkle_opening(
        &self,
        contract_id: &str,
        position: u64,
    ) -> Result<crate::citadel::LicenseOpening> {
        let contract_id = normalize_contract_id(contract_id)?;
        let request = citadel::serialize::<u64, 1024>(&position)?;
        let response = self
            .query_bytes(&contract_id, "get_merkle_opening", request, false)
            .await?;
        citadel::decode_merkle_opening(&response)?
            .ok_or_else(|| anyhow::anyhow!("no merkle opening for license position {position}"))
    }

    async fn query_bytes(
        &self,
        contract_id: &str,
        method: &str,
        request: Vec<u8>,
        feed: bool,
    ) -> Result<Vec<u8>> {
        let response = self
            .query_response(contract_id, method, request, feed)
            .await?;
        Ok(response.bytes().await?.to_vec())
    }

    async fn query_response(
        &self,
        contract_id: &str,
        method: &str,
        request: Vec<u8>,
        feed: bool,
    ) -> Result<reqwest::Response> {
        let separator = if self.state_url.ends_with('/') {
            "on"
        } else {
            "/on"
        };
        let url = format!(
            "{}{separator}/contracts:{contract_id}/{method}",
            self.state_url
        );
        let mut request = self
            .http
            .post(url)
            .body(request)
            .header("Content-Type", "application/octet-stream")
            .header("rusk-version", REQUIRED_RUSK_VERSION);
        if feed {
            request = request.header("Rusk-Feeder", "1");
        }
        let response = request.send().await?;

        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            let bytes = response.bytes().await?;
            bail!(
                "contract query failed with {status}: {}",
                String::from_utf8_lossy(&bytes)
            );
        }

        Ok(response)
    }
}

fn drain_positioned_blob_feed_items(buffer: &mut Vec<u8>, items: &mut Vec<(u64, Vec<u8>)>) {
    while let Some((len, item)) = decode_positioned_blob_feed_prefix(buffer) {
        items.push(item);
        buffer.drain(..len);
    }
}

fn decode_positioned_blob_feed_prefix(buffer: &[u8]) -> Option<(usize, (u64, Vec<u8>))> {
    // RUES feed chunks may split archived items at arbitrary byte boundaries.
    // The payloads here are small, so incrementally probing the current prefix
    // keeps the decoder simple while still handling partial chunks.
    for len in 1..=buffer.len() {
        if let Ok(item) = rkyv::from_bytes::<(u64, Vec<u8>)>(&buffer[..len]) {
            return Some((len, item));
        }
    }
    None
}
