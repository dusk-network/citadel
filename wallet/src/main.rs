// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod citadel;
mod cli;
mod dusk;
mod state;
mod tui;

use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use zeroize::Zeroizing;

use cli::{Cli, Command};
use dusk::{
    CitadelQuery, ContractDeploy, Dusk, IssueLicense, ReceiveLicense, RuskWallet, RuskWalletConfig,
    UseLicense,
};
use state::{CitadelWalletState, SessionCookieRecord, SessionCookieStore};

const PROFILE_IDX: u8 = 0;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let command = cli.command.as_ref().unwrap_or(&Command::Tui);

    if matches!(command, Command::Tui) {
        return tui::run(&cli).await;
    }

    let wallet_password = dusk::prompt_wallet_password(cli.password.as_ref())?;
    let storage_key = wallet(&cli, Some(&wallet_password)).citadel_storage_key()?;

    match command {
        Command::Tui => unreachable!("handled before password setup"),
        Command::SetAccount(args) => {
            let mut state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            state.use_shielded = args.shielded;
            state.save(&cli.wallet_dir, &storage_key)?;
            println!("profile {PROFILE_IDX} account: {}", state.account_label());
            Ok(())
        }
        Command::Issuer => {
            let (_, issuer_address) = wallet(&cli, Some(&wallet_password)).addresses()?;
            println!("issuer_address: {issuer_address}");
            Ok(())
        }
        Command::Deploy(args) => {
            let mut state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let deploy_nonce = args
                .deploy_nonce
                .unwrap_or_else(RuskWallet::generated_deploy_nonce);
            let receipt = wallet(&cli, Some(&wallet_password))
                .deploy(ContractDeploy {
                    code: args.code.clone(),
                    init_args: String::new(),
                    deploy_nonce,
                    address: None,
                    profile_idx: Some(PROFILE_IDX),
                    shielded: state.use_shielded,
                    gas_limit: args.gas_limit,
                    gas_price: args.gas_price,
                })
                .await?;
            state.set_active_contract(receipt.contract_id.clone())?;
            state.save(&cli.wallet_dir, &storage_key)?;
            println!("deploy_nonce: {deploy_nonce}");
            println!("contract_id: {}", receipt.contract_id);
            println!("tx_hash: {}", receipt.tx_hash);
            Ok(())
        }
        Command::SetContract(target) => {
            let mut state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            state.set_active_contract(target.contract_id.clone())?;
            state.save(&cli.wallet_dir, &storage_key)?;
            println!("active contract: {}", state.active_contract()?);
            Ok(())
        }
        Command::ReceiveLicense(args) => {
            let issuer_public_key = citadel::parse_shielded_address(&args.issuer_address)?;
            let receipt = wallet(&cli, Some(&wallet_password)).receive_license(
                ReceiveLicense {
                    profile_idx: Some(PROFILE_IDX),
                },
                issuer_public_key,
            )?;
            println!("request_id: {}", receipt.request_id);
            println!("version: {}", receipt.version);
            println!("deployment_id: {}", receipt.deployment_id);
            println!("request_blob: {}", receipt.request_blob);
            Ok(())
        }
        Command::IssueRequestLicense(args) => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let contract_id = state.active_contract()?.to_string();
            let request = citadel::parse_request_blob_hex(&args.request_blob)?;
            let issuer = wallet(&cli, Some(&wallet_password)).citadel_secret_key(PROFILE_IDX)?;
            let (issue_arg, request_id) =
                citadel::issue_license_from_request_arg(&args.attributes, &request, &issuer)?;
            let receipt = wallet(&cli, Some(&wallet_password))
                .issue_license(
                    IssueLicense {
                        contract_id,
                        profile_idx: Some(PROFILE_IDX),
                        shielded: state.use_shielded,
                        gas_limit: args.gas_limit,
                        gas_price: args.gas_price,
                    },
                    issue_arg,
                )
                .await?;
            state.save(&cli.wallet_dir, &storage_key)?;
            println!("tx_hash: {}", receipt.tx_hash);
            println!("request_id: {}", hex::encode(request_id.to_bytes()));
            println!(
                "issuer_public_key: {}",
                citadel::issuer_public_key_hex(&issuer)
            );
            println!(
                "attribute_scalar: {}",
                citadel::attribute_scalar_hex(&args.attributes)
            );
            Ok(())
        }
        Command::IssueLicense(args) => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let issuer = wallet(&cli, Some(&wallet_password)).citadel_secret_key(PROFILE_IDX)?;
            let recipient = citadel::parse_shielded_address(&args.shielded_address)?;
            let issue_arg = citadel::issue_license_arg(&args.attributes, recipient, &issuer)?;
            let receipt = wallet(&cli, Some(&wallet_password))
                .issue_license(
                    IssueLicense {
                        contract_id: state.active_contract()?.to_string(),
                        profile_idx: Some(PROFILE_IDX),
                        shielded: state.use_shielded,
                        gas_limit: args.gas_limit,
                        gas_price: args.gas_price,
                    },
                    issue_arg,
                )
                .await?;
            state.save(&cli.wallet_dir, &storage_key)?;
            println!("tx_hash: {}", receipt.tx_hash);
            println!(
                "issuer_public_key: {}",
                citadel::issuer_public_key_hex(&issuer)
            );
            println!(
                "attribute_scalar: {}",
                citadel::attribute_scalar_hex(&args.attributes)
            );
            Ok(())
        }
        Command::ListLicenses => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let licenses = wallet(&cli, Some(&wallet_password))
                .list_owned_licenses(state.active_contract()?)
                .await?;
            if licenses.is_empty() {
                println!("no owned licenses found");
            }
            for license in licenses {
                println!(
                    "position: {} lp_public_key: {} attr_data: {}",
                    license.position,
                    citadel::public_key_hex(&license.issuer),
                    hex::encode(license.attr_data.to_bytes())
                );
            }
            Ok(())
        }
        Command::GetLicense(args) => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let Some(license) = dusk(&cli)
                .license(state.active_contract()?, args.position)
                .await?
            else {
                println!("license not found");
                return Ok(());
            };
            let info = citadel::license_info(args.position, &license)?;
            println!("position: {}", info.position);
            println!("version: {}", hex::encode(info.version.to_bytes()));
            println!(
                "deployment_id: {}",
                hex::encode(info.deployment_id.to_bytes())
            );
            println!("lpk_u: {}", hex::encode(info.lpk_u.to_bytes()));
            println!("lpk_v: {}", hex::encode(info.lpk_v.to_bytes()));
            println!("license_blob: {}", hex::encode(license));
            Ok(())
        }
        Command::UseLicense(args) => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let contract_id = state.active_contract()?.to_string();
            let service_provider = citadel::parse_shielded_address(&args.service_provider)?;
            let service_provider_hex = citadel::public_key_hex(&service_provider);
            let challenge = citadel::encode_challenge(&args.challenge)?;
            let receipt = wallet(&cli, Some(&wallet_password))
                .use_license(UseLicense {
                    contract_id: contract_id.clone(),
                    position: args.position,
                    service_provider,
                    challenge,
                    profile_idx: Some(PROFILE_IDX),
                    shielded: state.use_shielded,
                    gas_limit: args.gas_limit,
                    gas_price: args.gas_price,
                })
                .await?;
            state.save(&cli.wallet_dir, &storage_key)?;
            let cookie_path = SessionCookieStore::append(
                &cli.wallet_dir,
                &storage_key,
                SessionCookieRecord {
                    created_at: Utc::now().to_rfc3339(),
                    contract_id,
                    position: args.position,
                    service_provider: service_provider_hex,
                    session_id: receipt.session_id.clone(),
                    tx_hash: receipt.tx_hash.clone(),
                    session_cookie: receipt.session_cookie.clone(),
                },
            )?;
            println!("tx_hash: {}", receipt.tx_hash);
            println!("session_id: {}", receipt.session_id);
            println!("session_cookie: {}", receipt.session_cookie);
            println!("session_cookie_file: {}", cookie_path.display());
            Ok(())
        }
        Command::GetSession(args) => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let session_id = citadel::parse_bls_scalar_hex(&args.session_id, "session ID")?;
            let Some(session) = dusk(&cli)
                .session(state.active_contract()?, session_id)
                .await?
            else {
                println!("session not found");
                return Ok(());
            };
            println!("session_id: {}", hex::encode(session_id.to_bytes()));
            for (index, input) in session.public_inputs.iter().enumerate() {
                println!("public_input[{index}]: {}", hex::encode(input.to_bytes()));
            }
            Ok(())
        }
        Command::ListCookies => {
            let store = SessionCookieStore::load(&cli.wallet_dir, &storage_key)?;
            if store.records.is_empty() {
                println!("no saved session cookies found");
            }
            for (index, record) in store.records.iter().enumerate() {
                for line in session_cookie_lines(index, record) {
                    println!("{line}");
                }
            }
            Ok(())
        }
        Command::Metadata => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let metadata = dusk(&cli).metadata(state.active_contract()?).await?;
            println!(
                "deployment_id: {}",
                hex::encode(metadata.deployment_id.to_bytes())
            );
            println!(
                "protocol_version: {}",
                hex::encode(metadata.protocol_version.to_bytes())
            );
            println!("chain_id: {}", hex::encode(metadata.chain_id.to_bytes()));
            println!(
                "contract_id: {}",
                hex::encode(metadata.contract_id.to_bytes())
            );
            println!(
                "verifier_key_hash: {}",
                hex::encode(metadata.verifier_key_hash.to_bytes())
            );
            println!(
                "circuit_hash: {}",
                hex::encode(metadata.circuit_hash.to_bytes())
            );
            println!("merkle_arity: {}", metadata.merkle_arity);
            println!("merkle_depth: {}", metadata.merkle_depth);
            println!("root_history_size: {}", metadata.root_history_size);
            println!("public_inputs_len: {}", metadata.public_inputs_len);
            println!("max_license_blob_size: {}", metadata.max_license_blob_size);
            Ok(())
        }
        Command::Roots => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let current_root = dusk(&cli).current_root(state.active_contract()?).await?;
            let accepted_roots = dusk(&cli).accepted_roots(state.active_contract()?).await?;
            println!("current_root: {}", hex::encode(current_root.to_bytes()));
            if accepted_roots.is_empty() {
                println!("accepted_roots: none");
            }
            for (index, root) in accepted_roots.iter().enumerate() {
                println!("accepted_root[{index}]: {}", hex::encode(root.to_bytes()));
            }
            Ok(())
        }
        Command::Info => {
            let state = CitadelWalletState::load(&cli.wallet_dir, &storage_key)?;
            let CitadelQuery {
                licenses,
                tree_len,
                sessions,
                accepted_roots,
                current_root,
            } = dusk(&cli).citadel_info(state.active_contract()?).await?;
            println!("licenses: {licenses}");
            println!("tree_len: {tree_len}");
            println!("sessions: {sessions}");
            println!("accepted_roots: {accepted_roots}");
            println!("current_root: {}", hex::encode(current_root.to_bytes()));
            Ok(())
        }
    }
}

fn session_cookie_lines(index: usize, record: &SessionCookieRecord) -> Vec<String> {
    vec![
        format!("cookie[{index}].created_at: {}", record.created_at),
        format!("cookie[{index}].contract_id: {}", record.contract_id),
        format!("cookie[{index}].position: {}", record.position),
        format!(
            "cookie[{index}].service_provider: {}",
            record.service_provider
        ),
        format!("cookie[{index}].session_id: {}", record.session_id),
        format!("cookie[{index}].tx_hash: {}", record.tx_hash),
        format!("cookie[{index}].session_cookie: {}", record.session_cookie),
    ]
}

fn wallet(cli: &Cli, password: Option<&Zeroizing<String>>) -> RuskWallet {
    RuskWallet::new(RuskWalletConfig {
        wallet_dir: cli.wallet_dir.clone(),
        password: password.cloned().or_else(|| {
            cli.password
                .as_ref()
                .map(|password| Zeroizing::new(password.clone()))
        }),
        state: cli.state.clone(),
        prover: cli.prover.clone().unwrap_or_else(|| cli.state.clone()),
        archiver: cli.archiver.clone().unwrap_or_else(|| cli.state.clone()),
    })
}

fn dusk(cli: &Cli) -> Dusk {
    Dusk::new(cli.state.clone())
}
