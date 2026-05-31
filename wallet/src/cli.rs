// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

const DEFAULT_STATE_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_WALLET_DIR: &str = ".dusk/rusk-wallet";
const DEFAULT_CONTRACT_WASM: &str = "target/wasm32-unknown-unknown/release/license_contract.wasm";
const CONTRACT_WASM_ENV: &str = "CITADEL_CONTRACT_WASM";
pub const DEFAULT_DEPLOY_GAS_LIMIT: u64 = 114_857_600;
pub const DEFAULT_CALL_GAS_LIMIT: u64 = 2_000_000_000;
pub const DEFAULT_GAS_PRICE: u64 = 2_000;

#[derive(Debug, Parser)]
#[command(name = "zk-citadel-wallet")]
#[command(about = "Citadel wallet, deployment, and contract CLI")]
pub struct Cli {
    /// Path to the rusk-wallet wallet directory.
    #[arg(long, value_name = "PATH", default_value_os_t = default_wallet_dir())]
    pub wallet_dir: PathBuf,

    /// Wallet password. Prefer CITADEL_WALLET_PASSWORD in CI.
    #[arg(long, env = "CITADEL_WALLET_PASSWORD")]
    pub password: Option<String>,

    /// Rusk state node URL.
    #[arg(long, default_value = DEFAULT_STATE_URL)]
    pub state: String,

    /// Rusk prover URL. Defaults to --state.
    #[arg(long)]
    pub prover: Option<String>,

    /// Rusk archiver URL. Defaults to --state.
    #[arg(long)]
    pub archiver: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Open the terminal UI.
    Tui,
    /// Toggle whether profile 0 uses the public or shielded account.
    SetAccount(AccountArgs),
    /// Print this wallet's LP issuer address.
    Issuer,
    /// Deploy the Citadel license contract and store it as active.
    Deploy(DeployArgs),
    /// Persist an already deployed Citadel contract ID as active.
    SetContract(ContractTarget),
    /// Print an encrypted license request blob for a License Provider.
    #[command(name = "receive-license", alias = "request-license")]
    ReceiveLicense(ReceiveLicenseArgs),
    /// Issue a license from an encrypted request blob.
    IssueRequestLicense(IssueRequestLicenseArgs),
    /// Issue a license to a shielded address.
    IssueLicense(IssueLicenseArgs),
    /// List licenses owned by profile 0.
    ListLicenses,
    /// Read an encrypted license by position.
    GetLicense(PositionArgs),
    /// Use an owned license by tree position.
    UseLicense(UseLicenseArgs),
    /// Query an accepted session by session ID.
    GetSession(SessionArgs),
    /// List locally saved session cookies.
    ListCookies,
    /// Query active contract deployment metadata.
    Metadata,
    /// Query current and accepted Merkle roots.
    Roots,
    /// Query active contract counters.
    Info,
}

#[derive(Debug, Parser)]
pub struct AccountArgs {
    /// Use the profile 0 shielded account instead of its public account.
    #[arg(long)]
    pub shielded: bool,
}

#[derive(Debug, Parser)]
pub struct DeployArgs {
    /// Compiled WASM contract path.
    #[arg(
        long,
        env = "CITADEL_CONTRACT_WASM",
        value_name = "PATH",
        default_value_os_t = default_contract_wasm()
    )]
    pub code: PathBuf,

    /// Deployment nonce. Generated when omitted.
    #[arg(long)]
    pub deploy_nonce: Option<u64>,

    /// Gas limit.
    #[arg(long, default_value_t = DEFAULT_DEPLOY_GAS_LIMIT)]
    pub gas_limit: u64,

    /// Gas price in Lux.
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE)]
    pub gas_price: u64,
}

#[derive(Debug, Parser)]
pub struct ContractTarget {
    /// Contract ID as 32 bytes of hex, with or without 0x.
    #[arg(long)]
    pub contract_id: String,
}

#[derive(Debug, Parser)]
pub struct ReceiveLicenseArgs {
    /// License Provider shielded address.
    #[arg(long, value_name = "ADDRESS")]
    pub issuer_address: String,
}

#[derive(Debug, Parser)]
pub struct IssueRequestLicenseArgs {
    /// Hex-encoded encrypted request blob printed by receive-license.
    #[arg(long, value_name = "HEX")]
    pub request_blob: String,

    /// Attributes string to hash into the license attribute scalar.
    #[arg(long)]
    pub attributes: String,

    /// Gas limit.
    #[arg(long, default_value_t = DEFAULT_CALL_GAS_LIMIT)]
    pub gas_limit: u64,

    /// Gas price in Lux.
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE)]
    pub gas_price: u64,
}

#[derive(Debug, Parser)]
pub struct IssueLicenseArgs {
    /// Attributes string to hash into the license attribute scalar.
    #[arg(long)]
    pub attributes: String,

    /// Recipient shielded address.
    #[arg(long, value_name = "ADDRESS")]
    pub shielded_address: String,

    /// Gas limit.
    #[arg(long, default_value_t = DEFAULT_CALL_GAS_LIMIT)]
    pub gas_limit: u64,

    /// Gas price in Lux.
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE)]
    pub gas_price: u64,
}

#[derive(Debug, Parser)]
pub struct UseLicenseArgs {
    /// License tree position from list-licenses.
    #[arg(long)]
    pub position: u64,

    /// Service Provider shielded address.
    #[arg(long, value_name = "ADDRESS")]
    pub service_provider: String,

    /// SP challenge text. The wallet encodes it into the circuit challenge scalar.
    #[arg(long, value_name = "TEXT")]
    pub challenge: String,

    /// Gas limit.
    #[arg(long, default_value_t = DEFAULT_CALL_GAS_LIMIT)]
    pub gas_limit: u64,

    /// Gas price in Lux.
    #[arg(long, default_value_t = DEFAULT_GAS_PRICE)]
    pub gas_price: u64,
}

#[derive(Debug, Parser)]
pub struct PositionArgs {
    /// Contract collection position.
    #[arg(long)]
    pub position: u64,
}

#[derive(Debug, Parser)]
pub struct SessionArgs {
    /// Session ID as a canonical 32-byte scalar hex value.
    #[arg(long, value_name = "HEX")]
    pub session_id: String,
}

fn default_wallet_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        Path::new(&home).join(DEFAULT_WALLET_DIR)
    } else {
        PathBuf::from(DEFAULT_WALLET_DIR)
    }
}

pub fn default_contract_wasm() -> PathBuf {
    if let Some(path) = std::env::var_os(CONTRACT_WASM_ENV) {
        return PathBuf::from(path);
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(DEFAULT_CONTRACT_WASM)
}
