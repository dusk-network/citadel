// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Thin integration layer around `rusk-wallet`.
//!
//! Write transactions, wallet decryption, account selection, and deployment
//! receipt waiting are delegated to Dusk wallet APIs so this crate does not
//! introduce a second key-management format.

use std::{
    fs,
    io::{self, IsTerminal},
    path::PathBuf,
    str::FromStr,
};

use aes::Aes256;
use aes_gcm::{Aes256Gcm, Key, KeyInit, aead::Aead};
use anyhow::{Context, Result, anyhow, bail};
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use dusk_core::{
    JubJubScalar,
    abi::ContractId,
    transfer::data::{ContractCall, TransactionData},
};
use rand::Rng;
use rusk_wallet::{
    Address, GraphQL, IV_SIZE, PBKDF2_ROUNDS, SALT_SIZE, SecureWalletFile, Wallet, WalletPath,
    currency::Dusk,
    dat::{self, FileVersion},
    gas::Gas,
};
use sha2::{Digest, Sha256};
use wallet_core::{Seed, keys::derive_phoenix_sk};
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::citadel::{self, IssueLicenseArg, OwnedLicense, UseLicenseArg};

use super::util::{decode_hex, normalize_contract_id};

/// Runtime configuration shared by wallet-backed commands.
#[derive(Debug, Clone)]
pub struct RuskWalletConfig {
    pub wallet_dir: PathBuf,
    pub password: Option<Zeroizing<String>>,
    pub state: String,
    pub prover: String,
    pub archiver: String,
}

/// Wallet-backed Dusk/Citadel command executor.
#[derive(Debug, Clone)]
pub struct RuskWallet {
    config: RuskWalletConfig,
}

/// Parameters for deploying a compiled Citadel contract WASM.
#[derive(Debug, Clone)]
pub struct ContractDeploy {
    pub code: PathBuf,
    pub init_args: String,
    pub deploy_nonce: u64,
    pub address: Option<String>,
    pub profile_idx: Option<u8>,
    pub shielded: bool,
    pub gas_limit: u64,
    pub gas_price: u64,
}

/// Result of a submitted contract deployment transaction.
#[derive(Debug, Clone)]
pub struct DeploymentReceipt {
    pub contract_id: String,
    pub tx_hash: String,
}

/// Parameters for issuing a license through an active contract.
#[derive(Debug, Clone)]
pub struct IssueLicense {
    pub contract_id: String,
    pub profile_idx: Option<u8>,
    pub shielded: bool,
    pub gas_limit: u64,
    pub gas_price: u64,
}

/// Parameters for proving and submitting a license-use transaction.
#[derive(Debug, Clone)]
pub struct UseLicense {
    pub contract_id: String,
    pub position: u64,
    pub service_provider: phoenix_core::PublicKey,
    pub challenge: JubJubScalar,
    pub profile_idx: Option<u8>,
    pub shielded: bool,
    pub gas_limit: u64,
    pub gas_price: u64,
}

/// Parameters for creating an encrypted license request.
#[derive(Debug, Clone)]
pub struct ReceiveLicense {
    pub profile_idx: Option<u8>,
}

/// Result of a submitted contract call transaction.
#[derive(Debug, Clone)]
pub struct TransactionReceipt {
    pub tx_hash: String,
}

/// Local request material to deliver to a License Provider.
#[derive(Debug, Clone)]
pub struct LicenseRequestReceipt {
    pub request_id: String,
    pub version: String,
    pub deployment_id: String,
    pub request_blob: String,
}

/// Result of a submitted license-use transaction and its local cookie.
#[derive(Debug, Clone)]
pub struct UseLicenseReceipt {
    pub tx_hash: String,
    pub session_id: String,
    pub session_cookie: String,
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
const DEFAULT_PROVER_PATH: &str = "target/prover";
const PROVER_PATH_ENV: &str = "CITADEL_PROVER_PATH";

#[derive(Debug, Clone)]
struct WalletFile {
    path: WalletPath,
    aes_key: Vec<u8>,
    salt: Option<[u8; SALT_SIZE]>,
    iv: Option<[u8; IV_SIZE]>,
}

impl SecureWalletFile for WalletFile {
    fn path(&self) -> &WalletPath {
        &self.path
    }

    fn aes_key(&self) -> &[u8] {
        &self.aes_key
    }

    fn zeroize_aes_key(&mut self) {
        self.aes_key.zeroize();
    }

    fn salt(&self) -> Option<&[u8; SALT_SIZE]> {
        self.salt.as_ref()
    }

    fn iv(&self) -> Option<&[u8; IV_SIZE]> {
        self.iv.as_ref()
    }
}

impl RuskWallet {
    pub fn new(config: RuskWalletConfig) -> Self {
        Self { config }
    }

    pub fn addresses(&self) -> Result<(String, String)> {
        let mut wallet = self.load()?;
        let public = wallet.public_address(0)?.to_string();
        let shielded = wallet.shielded_account(0)?.to_string();
        wallet.close();
        Ok((public, shielded))
    }

    pub fn citadel_secret_key(&self, profile_idx: u8) -> Result<phoenix_core::SecretKey> {
        self.phoenix_secret_key(profile_idx)
    }

    pub fn citadel_storage_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let path = WalletPath::new(&self.config.wallet_dir.join("wallet.dat"));
        let (file_version, salt_and_iv) = dat::read_file_version_and_salt_iv(&path)?;
        let password = self.password()?;
        let mut aes_key = derive_wallet_key(
            file_version,
            password.as_str(),
            salt_and_iv.as_ref().map(|si| &si.0),
        )?;
        let storage_key = derive_citadel_storage_key(&aes_key);
        aes_key.zeroize();
        Ok(Zeroizing::new(storage_key))
    }

    pub async fn deploy(&self, deploy: ContractDeploy) -> Result<DeploymentReceipt> {
        if deploy.code.extension().and_then(|ext| ext.to_str()) != Some("wasm") {
            bail!("contract code path must point to a .wasm file");
        }

        let code = std::fs::read(&deploy.code).with_context(|| {
            format!(
                "failed to read {}. Build the contract first with `make contract`, or pass --code / set CITADEL_CONTRACT_WASM",
                deploy.code.display()
            )
        })?;
        let init_args = decode_hex(&deploy.init_args).context("invalid --init-args")?;
        let gas = Gas::new(deploy.gas_limit).with_price(deploy.gas_price);

        let mut wallet = self.load()?;
        self.connect(&mut wallet).await?;

        let address = self.address_or_selected(
            &wallet,
            deploy.address.as_deref(),
            deploy.profile_idx,
            deploy.shielded,
        )?;
        let addr_idx = wallet.find_index(&address)?;
        let contract_id = wallet.get_contract_id(addr_idx, &code, deploy.deploy_nonce)?;

        let tx = match address {
            Address::Public(_) => {
                wallet
                    .moonlight_deploy(addr_idx, code, init_args, deploy.deploy_nonce, gas)
                    .await?
            }
            Address::Shielded(_) => {
                wallet.sync().await?;
                wallet
                    .phoenix_deploy(addr_idx, code, init_args, deploy.deploy_nonce, gas)
                    .await?
            }
        };

        let contract_id = hex::encode(contract_id);
        let tx_hash = hex::encode(tx.hash().to_bytes());
        wallet.close();

        let gql = GraphQL::new(
            self.config.state.clone(),
            self.config.archiver.clone(),
            headless,
        )?;
        gql.wait_for(&tx_hash).await?;

        Ok(DeploymentReceipt {
            contract_id,
            tx_hash,
        })
    }

    pub async fn issue_license(
        &self,
        issue: IssueLicense,
        issue_arg: IssueLicenseArg,
    ) -> Result<TransactionReceipt> {
        let contract_id = normalize_contract_id(&issue.contract_id)?;
        self.ensure_citadel_contract(&contract_id).await?;
        let contract_id = contract_id_bytes(&contract_id)?;
        let gas = Gas::new(issue.gas_limit).with_price(issue.gas_price);
        let call = ContractCall::new(ContractId::from_bytes(contract_id), "issue_license")
            .with_args(&issue_arg)
            .map_err(|error| anyhow!("{error:?}"))?;

        let mut wallet = self.load()?;
        self.connect(&mut wallet).await?;
        let address = self.address_or_selected(&wallet, None, issue.profile_idx, issue.shielded)?;
        let addr_idx = wallet.find_index(&address)?;

        let tx = match address {
            Address::Public(_) => {
                wallet
                    .moonlight_execute(addr_idx, Dusk::from(0), Dusk::from(0), gas, Some(call))
                    .await?
            }
            Address::Shielded(_) => {
                wallet.sync().await?;
                wallet
                    .phoenix_execute(addr_idx, Dusk::from(0), gas, TransactionData::Call(call))
                    .await?
            }
        };

        let tx_hash = hex::encode(tx.hash().to_bytes());
        wallet.close();

        let gql = GraphQL::new(
            self.config.state.clone(),
            self.config.archiver.clone(),
            headless,
        )?;
        gql.wait_for(&tx_hash).await?;

        Ok(TransactionReceipt { tx_hash })
    }

    pub fn receive_license(
        &self,
        receive: ReceiveLicense,
        issuer_public_key: phoenix_core::PublicKey,
    ) -> Result<LicenseRequestReceipt> {
        let sk = self.phoenix_secret_key(receive.profile_idx.unwrap_or_default())?;
        let request = citadel::license_request(&sk, &issuer_public_key)?;

        Ok(LicenseRequestReceipt {
            request_id: hex::encode(request.request_id.to_bytes()),
            version: hex::encode(request.version.to_bytes()),
            deployment_id: hex::encode(request.deployment_id.to_bytes()),
            request_blob: hex::encode(request.blob),
        })
    }

    pub async fn list_owned_licenses(&self, contract_id: &str) -> Result<Vec<OwnedLicense>> {
        let sk = self.phoenix_secret_key(0)?;
        let licenses = super::query::Dusk::new(self.config.state.clone())
            .licenses(contract_id, 0..u64::MAX)
            .await?;
        let mut owned = Vec::new();
        for (position, license) in licenses {
            if let Some(license) = citadel::owned_license(position, &license, &sk)? {
                owned.push(license);
            }
        }
        Ok(owned)
    }

    pub async fn use_license(&self, use_license: UseLicense) -> Result<UseLicenseReceipt> {
        self.ensure_citadel_contract(&use_license.contract_id)
            .await?;
        let sk = self.phoenix_secret_key(use_license.profile_idx.unwrap_or_default())?;
        let licenses = self.list_owned_licenses(&use_license.contract_id).await?;
        let owned = licenses
            .into_iter()
            .find(|license| license.position == use_license.position)
            .ok_or_else(|| anyhow!("no owned license at position {}", use_license.position))?;
        let merkle_opening = super::query::Dusk::new(self.config.state.clone())
            .merkle_opening(&use_license.contract_id, use_license.position)
            .await?;
        let prover_path = default_prover_path();
        let prepared = citadel::use_license_arg(
            &prover_path,
            &sk,
            &owned.issuer,
            &use_license.service_provider,
            use_license.challenge,
            &owned.license,
            merkle_opening,
        )?;
        let session_id = hex::encode(prepared.session_cookie.session_id.to_bytes());
        let session_cookie = citadel::session_cookie_hex(&prepared.session_cookie)?;

        let receipt = self.execute_use_license(use_license, prepared.arg).await?;
        Ok(UseLicenseReceipt {
            tx_hash: receipt.tx_hash,
            session_id,
            session_cookie,
        })
    }

    pub fn generated_deploy_nonce() -> u64 {
        rand::thread_rng().r#gen()
    }

    fn load(&self) -> Result<Wallet<WalletFile>> {
        let path = WalletPath::new(&self.config.wallet_dir.join("wallet.dat"));

        let (file_version, salt_and_iv) = dat::read_file_version_and_salt_iv(&path)?;
        let password = self.password()?;
        let aes_key = derive_wallet_key(
            file_version,
            password.as_str(),
            salt_and_iv.as_ref().map(|si| &si.0),
        )?;

        Ok(Wallet::from_file(WalletFile {
            path,
            aes_key,
            salt: salt_and_iv.map(|si| si.0),
            iv: salt_and_iv.map(|si| si.1),
        })?)
    }

    fn phoenix_secret_key(&self, index: u8) -> Result<phoenix_core::SecretKey> {
        let seed = self.seed()?;
        Ok(derive_phoenix_sk(&seed, index))
    }

    fn seed(&self) -> Result<Seed> {
        let path = self.config.wallet_dir.join("wallet.dat");
        let wallet_path = WalletPath::new(&path);
        let (file_version, salt_and_iv) = dat::read_file_version_and_salt_iv(&wallet_path)?;
        let password = self.password()?;
        let aes_key = derive_wallet_key(
            file_version,
            password.as_str(),
            salt_and_iv.as_ref().map(|si| &si.0),
        )?;
        let bytes =
            fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
        decrypt_seed(
            file_version,
            bytes,
            &aes_key,
            salt_and_iv.as_ref().map(|si| &si.1),
        )
    }

    async fn connect(&self, wallet: &mut Wallet<WalletFile>) -> Result<()> {
        wallet
            .connect_with_status(
                self.config.state.clone(),
                self.config.prover.clone(),
                self.config.archiver.clone(),
                status,
            )
            .await?;
        Ok(())
    }

    fn address_or_selected(
        &self,
        wallet: &Wallet<WalletFile>,
        address: Option<&str>,
        profile_idx: Option<u8>,
        shielded: bool,
    ) -> Result<Address> {
        match address {
            Some(address) => Ok(Address::from_str(address)?),
            None if shielded => Ok(wallet.shielded_account(profile_idx.unwrap_or_default())?),
            None => Ok(wallet.public_address(profile_idx.unwrap_or_default())?),
        }
    }

    fn password(&self) -> Result<Zeroizing<String>> {
        if let Some(password) = &self.config.password {
            return Ok(password.clone());
        }

        if !io::stdin().is_terminal() {
            bail!("wallet password is required; pass --password or set CITADEL_WALLET_PASSWORD");
        }

        prompt_wallet_password(None)
    }

    async fn execute_use_license(
        &self,
        use_license: UseLicense,
        arg: UseLicenseArg,
    ) -> Result<TransactionReceipt> {
        let contract_id = normalize_contract_id(&use_license.contract_id)?;
        let contract_id = contract_id_bytes(&contract_id)?;
        let gas = Gas::new(use_license.gas_limit).with_price(use_license.gas_price);
        let call = ContractCall::new(ContractId::from_bytes(contract_id), "use_license")
            .with_args(&arg)
            .map_err(|error| anyhow!("{error:?}"))?;

        let mut wallet = self.load()?;
        self.connect(&mut wallet).await?;
        let address =
            self.address_or_selected(&wallet, None, use_license.profile_idx, use_license.shielded)?;
        let addr_idx = wallet.find_index(&address)?;

        let tx = match address {
            Address::Public(_) => {
                wallet
                    .moonlight_execute(addr_idx, Dusk::from(0), Dusk::from(0), gas, Some(call))
                    .await?
            }
            Address::Shielded(_) => {
                wallet.sync().await?;
                wallet
                    .phoenix_execute(addr_idx, Dusk::from(0), gas, TransactionData::Call(call))
                    .await?
            }
        };

        let tx_hash = hex::encode(tx.hash().to_bytes());
        wallet.close();

        let gql = GraphQL::new(
            self.config.state.clone(),
            self.config.archiver.clone(),
            headless,
        )?;
        gql.wait_for(&tx_hash).await?;

        Ok(TransactionReceipt { tx_hash })
    }

    async fn ensure_citadel_contract(&self, contract_id: &str) -> Result<()> {
        super::query::Dusk::new(self.config.state.clone())
            .metadata(contract_id)
            .await
            .with_context(|| {
                format!("active contract {contract_id} did not pass Citadel metadata validation")
            })?;
        Ok(())
    }
}

fn headless(_status: &str) {}

fn status(_message: &str) {}

pub fn prompt_wallet_password(config_password: Option<&String>) -> Result<Zeroizing<String>> {
    if let Some(password) = config_password {
        return Ok(Zeroizing::new(password.clone()));
    }

    Ok(Zeroizing::new(
        rpassword::prompt_password("rusk-wallet password: ").context("failed to read password")?,
    ))
}

fn derive_wallet_key(
    file_version: FileVersion,
    password: &str,
    salt: Option<&[u8; SALT_SIZE]>,
) -> Result<Vec<u8>> {
    match file_version {
        FileVersion::RuskBinaryFileFormat(version)
            if dat::version_without_pre_higher(version) >= (0, 0, 2, 0) =>
        {
            let salt = salt.ok_or_else(|| anyhow!("wallet file is missing its password salt"))?;
            Ok(pbkdf2::pbkdf2_hmac_array::<Sha256, SALT_SIZE>(
                password.as_bytes(),
                salt,
                PBKDF2_ROUNDS,
            )
            .to_vec())
        }
        FileVersion::RuskBinaryFileFormat(_) => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            Ok(hasher.finalize().to_vec())
        }
        _ => Ok(blake3::hash(password.as_bytes()).as_bytes().to_vec()),
    }
}

fn derive_citadel_storage_key(wallet_key: &[u8]) -> [u8; 32] {
    // The Citadel state key is intentionally domain-separated from the raw
    // wallet file key. It protects local Citadel state and bearer cookies, not
    // Dusk wallet material itself.
    let mut hasher = Sha256::new();
    hasher.update(b"CITADEL_WALLET_STORAGE_KEY_V1");
    hasher.update((wallet_key.len() as u64).to_le_bytes());
    hasher.update(wallet_key);
    hasher.finalize().into()
}

fn contract_id_bytes(contract_id: &str) -> Result<[u8; 32]> {
    hex::decode(contract_id)?
        .try_into()
        .map_err(|_| anyhow!("contract ID must be exactly 32 bytes"))
}

fn default_prover_path() -> PathBuf {
    if let Some(path) = std::env::var_os(PROVER_PATH_ENV) {
        return PathBuf::from(path);
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(DEFAULT_PROVER_PATH)
}

fn decrypt_seed(
    file_version: FileVersion,
    mut bytes: Vec<u8>,
    aes_key: &[u8],
    iv: Option<&[u8; IV_SIZE]>,
) -> Result<Seed> {
    // `rusk-wallet` has used several encrypted file layouts. We only recover
    // the seed needed to derive the profile's Phoenix/Citadel key; normal Dusk
    // transaction signing still goes through the upstream Wallet type.
    let seed = match file_version {
        FileVersion::Legacy => {
            if bytes.get(1) == Some(&0) && bytes.get(2) == Some(&0) {
                bytes.drain(..3);
            }
            let content = decrypt_aes_cbc(&bytes, aes_key)?;
            content
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("wallet file is corrupted"))?
        }
        FileVersion::OldWalletCli((major, minor, _, _, _)) => {
            bytes.drain(..5);
            let content = decrypt_aes_cbc(&bytes, aes_key)?;
            match (major, minor) {
                (1, 0) => content
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("wallet file is corrupted"))?,
                (2, 0) => content
                    .get(..64)
                    .ok_or_else(|| anyhow!("wallet file is corrupted"))?
                    .try_into()
                    .map_err(|_| anyhow!("wallet file is corrupted"))?,
                _ => bail!("unsupported old wallet file version {major}.{minor}"),
            }
        }
        FileVersion::RuskBinaryFileFormat(version) => {
            const FILE_HEADER_SIZE: usize = 12;
            const OLD_PAYLOAD_SIZE: usize = 96;
            const PAYLOAD_SIZE: usize = 81;

            let (payload, use_aes_gcm) = if dat::version_without_pre_higher(version) < (0, 0, 2, 0)
            {
                let offset = FILE_HEADER_SIZE;
                (
                    bytes
                        .get(offset..offset + OLD_PAYLOAD_SIZE)
                        .ok_or_else(|| anyhow!("wallet file is corrupted"))?,
                    false,
                )
            } else {
                let offset = FILE_HEADER_SIZE + SALT_SIZE + IV_SIZE;
                (
                    bytes
                        .get(offset..offset + PAYLOAD_SIZE)
                        .ok_or_else(|| anyhow!("wallet file is corrupted"))?,
                    true,
                )
            };

            let content = if use_aes_gcm {
                decrypt_aes_gcm(
                    payload,
                    aes_key,
                    iv.ok_or_else(|| anyhow!("wallet file is missing its IV"))?,
                )?
            } else {
                decrypt_aes_cbc(payload, aes_key)?
            };

            content
                .get(..64)
                .ok_or_else(|| anyhow!("wallet file is corrupted"))?
                .try_into()
                .map_err(|_| anyhow!("wallet file is corrupted"))?
        }
    };

    bytes.zeroize();
    Ok(seed)
}

fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    const OLD_IV_SIZE: usize = 16;
    let iv = ciphertext
        .get(..OLD_IV_SIZE)
        .ok_or_else(|| anyhow!("wallet ciphertext is too short"))?;
    let enc = ciphertext
        .get(OLD_IV_SIZE..)
        .ok_or_else(|| anyhow!("wallet ciphertext is too short"))?;

    let cipher = Aes256Cbc::new_from_slices(key, iv)
        .map_err(|_| anyhow!("failed to initialize wallet AES-CBC decryptor"))?;
    cipher
        .decrypt_vec(enc)
        .map_err(|_| anyhow!("failed to decrypt wallet seed"))
}

fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8], iv: &[u8; IV_SIZE]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("failed to decrypt wallet seed"))
}
