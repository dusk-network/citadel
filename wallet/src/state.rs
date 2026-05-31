// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Encrypted local Citadel wallet state.
//!
//! The wallet keeps Citadel-specific data next to the `rusk-wallet` file, but
//! derives a separate storage key from the wallet encryption key and writes all
//! current files as AES-GCM envelopes.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::DateTime;
use dusk_bytes::Serializable;
use phoenix_core::PublicKey;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const STATE_FILE: &str = "citadel_wallet.dat";
const COOKIE_FILE: &str = "citadel_session_cookies.dat";
const ENCRYPTED_FILE_MAGIC: &str = "zk-citadel-wallet-encrypted-v1";
const LEGACY_ENCRYPTED_FILE_MAGIC: &str = "citadel-wallet-encrypted-v1";
const STATE_AAD: &[u8] = b"zk-citadel-wallet-state-v1";
const LEGACY_STATE_AAD: &[u8] = b"citadel-wallet-state-v1";
const COOKIE_AAD: &[u8] = b"zk-citadel-session-cookies-v1";
const LEGACY_COOKIE_AAD: &[u8] = b"citadel-session-cookies-v1";
const NONCE_SIZE: usize = 12;

/// Persistent Citadel settings for the selected Rusk wallet directory.
#[derive(Debug, Clone, Default)]
pub struct CitadelWalletState {
    pub use_shielded: bool,
    pub active_contract: Option<String>,
}

impl CitadelWalletState {
    pub fn load(wallet_dir: &Path, storage_key: &[u8; 32]) -> Result<Self> {
        let path = state_path(wallet_dir);
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = read_private_file(&path, storage_key, STATE_AAD, LEGACY_STATE_AAD)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&content).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn save(&self, wallet_dir: &Path, storage_key: &[u8; 32]) -> Result<()> {
        fs::create_dir_all(wallet_dir)
            .with_context(|| format!("failed to create {}", wallet_dir.display()))?;
        let path = state_path(wallet_dir);
        write_private_file(&path, self.encode().as_bytes(), storage_key, STATE_AAD)
    }

    pub fn set_active_contract(&mut self, contract_id: String) -> Result<()> {
        self.active_contract = Some(normalize_contract_id(&contract_id)?);
        Ok(())
    }

    pub fn active_contract(&self) -> Result<&str> {
        self.active_contract
            .as_deref()
            .ok_or_else(|| anyhow!("no active contract is configured; run deploy or set-contract"))
    }

    pub fn account_label(&self) -> &'static str {
        if self.use_shielded {
            "shielded"
        } else {
            "public"
        }
    }

    pub fn path(wallet_dir: &Path) -> PathBuf {
        state_path(wallet_dir)
    }

    fn parse(content: &str) -> Result<Self> {
        let mut state = Self::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                bail!("invalid state line: {line}");
            };

            match key.trim() {
                "version" => {
                    if value.trim() != "1" {
                        bail!("unsupported state version: {}", value.trim());
                    }
                }
                "use_shielded" => {
                    state.use_shielded = value
                        .trim()
                        .parse()
                        .with_context(|| format!("invalid use_shielded value: {}", value.trim()))?;
                }
                "active_contract" => {
                    let value = value.trim();
                    if !value.is_empty() {
                        state.set_active_contract(value.to_string())?;
                    }
                }
                _ => {}
            }
        }

        Ok(state)
    }

    fn encode(&self) -> String {
        format!(
            "version=1\nuse_shielded={}\nactive_contract={}\n",
            self.use_shielded,
            self.active_contract.as_deref().unwrap_or_default()
        )
    }
}

/// A saved bearer session cookie and the context needed to inspect it later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCookieRecord {
    pub created_at: String,
    pub contract_id: String,
    pub position: u64,
    pub service_provider: String,
    pub session_id: String,
    pub tx_hash: String,
    pub session_cookie: String,
}

/// Encrypted append-only store for locally saved session cookies.
#[derive(Debug, Clone, Default)]
pub struct SessionCookieStore {
    pub records: Vec<SessionCookieRecord>,
}

impl SessionCookieStore {
    pub fn load(wallet_dir: &Path, storage_key: &[u8; 32]) -> Result<Self> {
        let path = cookie_path(wallet_dir);
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = read_private_file(&path, storage_key, COOKIE_AAD, LEGACY_COOKIE_AAD)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&content).with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn save(&self, wallet_dir: &Path, storage_key: &[u8; 32]) -> Result<()> {
        fs::create_dir_all(wallet_dir)
            .with_context(|| format!("failed to create {}", wallet_dir.display()))?;
        let path = cookie_path(wallet_dir);
        for record in &self.records {
            record.validate()?;
        }
        write_private_file(&path, self.encode().as_bytes(), storage_key, COOKIE_AAD)
    }

    pub fn append(
        wallet_dir: &Path,
        storage_key: &[u8; 32],
        record: SessionCookieRecord,
    ) -> Result<PathBuf> {
        record.validate()?;
        let mut store = Self::load(wallet_dir, storage_key)?;
        store.records.push(record);
        store.save(wallet_dir, storage_key)?;
        Ok(cookie_path(wallet_dir))
    }

    fn parse(content: &str) -> Result<Self> {
        let mut store = Self::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                bail!("invalid cookie store line: {line}");
            };

            match key.trim() {
                "version" => {
                    if value.trim() != "1" {
                        bail!("unsupported cookie store version: {}", value.trim());
                    }
                }
                "cookie" => store.records.push(parse_cookie_record(value.trim())?),
                _ => {}
            }
        }

        Ok(store)
    }

    fn encode(&self) -> String {
        let mut output = String::from("version=1\n");
        for record in &self.records {
            output.push_str("cookie=");
            output.push_str(&record.created_at);
            output.push('|');
            output.push_str(&record.contract_id);
            output.push('|');
            output.push_str(&record.position.to_string());
            output.push('|');
            output.push_str(&record.service_provider);
            output.push('|');
            output.push_str(&record.session_id);
            output.push('|');
            output.push_str(&record.tx_hash);
            output.push('|');
            output.push_str(&record.session_cookie);
            output.push('\n');
        }
        output
    }
}

fn state_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(STATE_FILE)
}

fn cookie_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(COOKIE_FILE)
}

fn parse_cookie_record(value: &str) -> Result<SessionCookieRecord> {
    let fields = value.split('|').collect::<Vec<_>>();
    if fields.len() != 7 {
        bail!("invalid session cookie record");
    }

    let record = SessionCookieRecord {
        created_at: fields[0].to_string(),
        contract_id: fields[1].to_string(),
        position: fields[2]
            .parse()
            .with_context(|| format!("invalid cookie position: {}", fields[2]))?,
        service_provider: fields[3].to_string(),
        session_id: fields[4].to_string(),
        tx_hash: fields[5].to_string(),
        session_cookie: fields[6].to_string(),
    };
    record.validate()?;
    Ok(record)
}

fn normalize_contract_id(contract_id: &str) -> Result<String> {
    normalize_hex(contract_id, 64, "contract ID")
}

fn normalize_hex(value: &str, len: usize, label: &str) -> Result<String> {
    let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());

    if value.len() != len {
        bail!("{label} must be {} bytes of hex", len / 2);
    }

    hex::decode(value).with_context(|| format!("{label} is not valid hex"))?;
    Ok(value.to_ascii_lowercase())
}

impl SessionCookieRecord {
    fn validate(&self) -> Result<()> {
        DateTime::parse_from_rfc3339(&self.created_at)
            .with_context(|| format!("invalid cookie created_at: {}", self.created_at))?;
        normalize_hex(&self.contract_id, 64, "cookie contract ID")?;
        normalize_hex(
            &self.service_provider,
            PublicKey::SIZE * 2,
            "cookie service provider public key",
        )?;
        normalize_hex(&self.session_id, 64, "cookie session ID")?;
        normalize_hex(&self.tx_hash, 64, "cookie transaction hash")?;
        validate_hex(&self.session_cookie, "cookie session cookie hex")?;
        Ok(())
    }
}

fn validate_hex(value: &str, label: &str) -> Result<()> {
    let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if value.is_empty() {
        bail!("{label} must not be empty");
    }
    if !value.len().is_multiple_of(2) {
        bail!("{label} must have an even number of hex characters");
    }
    hex::decode(value).with_context(|| format!("{label} is not valid hex"))?;
    Ok(())
}

fn read_private_file(
    path: &Path,
    storage_key: &[u8; 32],
    aad: &[u8],
    legacy_aad: &[u8],
) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    // Older development builds wrote plaintext files or used pre-publication
    // envelope labels. Reads accept those formats for migration, but every
    // write goes back through `write_private_file` and uses the current
    // encrypted envelope.
    let encrypted_aad = if bytes.starts_with(ENCRYPTED_FILE_MAGIC.as_bytes()) {
        Some(aad)
    } else if bytes.starts_with(LEGACY_ENCRYPTED_FILE_MAGIC.as_bytes()) {
        Some(legacy_aad)
    } else {
        None
    };

    if let Some(encrypted_aad) = encrypted_aad {
        let envelope = std::str::from_utf8(&bytes)
            .with_context(|| format!("{} is not valid UTF-8", path.display()))?;
        let plaintext = decrypt_envelope(envelope, storage_key, encrypted_aad)
            .with_context(|| format!("failed to decrypt {}", path.display()))?;
        return String::from_utf8(plaintext)
            .with_context(|| format!("decrypted {} is not valid UTF-8", path.display()));
    }

    String::from_utf8(bytes).with_context(|| format!("{} is not valid UTF-8", path.display()))
}

fn write_private_file(path: &Path, bytes: &[u8], storage_key: &[u8; 32], aad: &[u8]) -> Result<()> {
    let encrypted = encrypt_envelope(bytes, storage_key, aad)
        .with_context(|| format!("failed to encrypt {}", path.display()))?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(encrypted.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;

    #[cfg(unix)]
    {
        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to set permissions on {}", path.display()))?;
    }

    Ok(())
}

fn encrypt_envelope(plaintext: &[u8], storage_key: &[u8; 32], aad: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(storage_key)
        .map_err(|_| anyhow!("failed to initialize Citadel state cipher"))?;
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to encrypt Citadel state"))?;

    Ok(format!(
        "{ENCRYPTED_FILE_MAGIC}\nnonce={}\nciphertext={}\n",
        hex::encode(nonce),
        hex::encode(ciphertext)
    ))
}

fn decrypt_envelope(envelope: &str, storage_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = None;
    let mut ciphertext = None;

    for line in envelope.lines() {
        let line = line.trim();
        if line.is_empty() || line == ENCRYPTED_FILE_MAGIC || line == LEGACY_ENCRYPTED_FILE_MAGIC {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            bail!("invalid encrypted Citadel file line: {line}");
        };

        match key {
            "nonce" => {
                let decoded = hex::decode(value).context("Citadel state nonce is not hex")?;
                nonce = Some(
                    decoded
                        .try_into()
                        .map_err(|_| anyhow!("Citadel state nonce must be {NONCE_SIZE} bytes"))?,
                );
            }
            "ciphertext" => {
                ciphertext =
                    Some(hex::decode(value).context("Citadel state ciphertext is not hex")?);
            }
            _ => {}
        }
    }

    let nonce: [u8; NONCE_SIZE] =
        nonce.ok_or_else(|| anyhow!("encrypted Citadel file is missing its nonce"))?;
    let ciphertext =
        ciphertext.ok_or_else(|| anyhow!("encrypted Citadel file is missing its ciphertext"))?;
    let cipher = Aes256Gcm::new_from_slice(storage_key)
        .map_err(|_| anyhow!("failed to initialize Citadel state cipher"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt Citadel state"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_active_contract_id() {
        let mut state = CitadelWalletState::default();
        state
            .set_active_contract(
                "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            )
            .unwrap();

        assert_eq!(
            state.active_contract().unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn rejects_malformed_cookie_record() {
        let record = SessionCookieRecord {
            created_at: "not-a-date".to_string(),
            contract_id: "00".repeat(32),
            position: 0,
            service_provider: "00".repeat(PublicKey::SIZE),
            session_id: "00".repeat(32),
            tx_hash: "00".repeat(32),
            session_cookie: "00".to_string(),
        };

        assert!(record.validate().is_err());
    }

    #[test]
    fn encrypted_state_round_trip_does_not_write_plaintext() {
        let storage_key = [7u8; 32];
        let dir = std::env::temp_dir().join(format!(
            "zk-citadel-wallet-state-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();

        let mut state = CitadelWalletState {
            use_shielded: true,
            active_contract: None,
        };
        state
            .set_active_contract("11".repeat(32))
            .expect("contract ID should normalize");
        state.save(&dir, &storage_key).unwrap();

        let bytes = fs::read(state_path(&dir)).unwrap();
        let content = String::from_utf8(bytes).unwrap();
        assert!(content.starts_with(ENCRYPTED_FILE_MAGIC));
        assert!(!content.contains("active_contract=1111"));

        let loaded = CitadelWalletState::load(&dir, &storage_key).unwrap();
        assert_eq!(loaded.use_shielded, state.use_shielded);
        assert_eq!(loaded.active_contract, state.active_contract);

        let _ = fs::remove_file(state_path(&dir));
        let _ = fs::remove_dir(&dir);
    }
}
