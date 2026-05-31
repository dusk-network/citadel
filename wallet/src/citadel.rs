// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Citadel protocol glue used by the wallet commands.
//!
//! Types in this module mirror the contract's rkyv call/return payloads. Keep
//! them synchronized with `contract/src/license_types.rs` and the deployment
//! constants checked in `validate_metadata`.

use std::{path::Path, str::FromStr};

use anyhow::{Context, Result, anyhow};
use bytecheck::CheckBytes;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_core::{JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::Prover;
use phoenix_core::{PublicKey, SecretKey};
use poseidon_merkle::Opening;
use rand::rngs::OsRng;
use rkyv::{Archive, Deserialize, Serialize};
use rusk_wallet::Address;
use sha2::{Digest, Sha512};
use zk_citadel::{
    License, LicenseOptions, LicenseOrigin, Request, SessionCookie, circuit, gadgets,
    helpers::{
        DEFAULT_DEPLOYMENT, MERKLE_ARITY, OBJECT_VERSION_V1, PUBLIC_INPUTS_LEN,
        attr_data_from_canonical_attributes,
    },
};

const ROOT_HISTORY_SIZE: u32 = 8;
const MAX_LICENSE_BLOB_SIZE: u32 = 4096;

/// Serialized argument passed to the contract's `issue_license` method.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct IssueLicenseArg {
    pub license: Vec<u8>,
    pub lpk_u: BlsScalar,
    pub lpk_v: BlsScalar,
}

/// Serialized proof payload passed to the contract's `use_license` method.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct UseLicenseArg {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<BlsScalar>,
}

/// Contract query argument for looking up a session by nullifier.
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct LicenseSessionId {
    pub id: BlsScalar,
}

/// Contract query response for an accepted license-use session.
#[derive(Debug, Clone, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct LicenseSession {
    pub public_inputs: Vec<BlsScalar>,
}

/// Deployment metadata returned by `get_metadata`.
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct DeploymentMetadata {
    pub deployment_id: BlsScalar,
    pub protocol_version: BlsScalar,
    pub chain_id: BlsScalar,
    pub contract_id: BlsScalar,
    pub verifier_key_hash: BlsScalar,
    pub circuit_hash: BlsScalar,
    pub merkle_arity: u32,
    pub merkle_depth: u32,
    pub root_history_size: u32,
    pub public_inputs_len: u32,
    pub max_license_blob_size: u32,
}

/// Summary returned by the contract's `get_state_info` query.
#[derive(Debug, Clone, Copy, PartialEq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct ContractInfo {
    pub licenses: u32,
    pub tree_len: u32,
    pub sessions: u32,
    pub accepted_roots: u32,
    pub current_root: BlsScalar,
}

pub type LicenseOpening = Opening<(), { circuit::DEPTH }>;

/// A decrypted license owned by wallet profile 0.
#[derive(Debug, Clone)]
pub struct OwnedLicense {
    pub position: u64,
    pub attr_data: JubJubScalar,
    pub issuer: PublicKey,
    pub license: License,
}

/// Request blob created for request-based issuance.
#[derive(Debug, Clone)]
pub struct LicenseRequest {
    pub request_id: BlsScalar,
    pub version: BlsScalar,
    pub deployment_id: BlsScalar,
    pub blob: Vec<u8>,
}

/// Public envelope fields decoded from an encrypted license blob.
#[derive(Debug, Clone)]
pub struct LicenseInfo {
    pub position: u64,
    pub version: BlsScalar,
    pub deployment_id: BlsScalar,
    pub lpk_u: BlsScalar,
    pub lpk_v: BlsScalar,
}

/// Locally prepared proof and cookie before the on-chain use transaction.
#[derive(Debug, Clone)]
pub struct PreparedUseLicense {
    pub arg: UseLicenseArg,
    pub session_cookie: SessionCookie,
}

pub fn serialize_unit() -> Result<Vec<u8>> {
    serialize::<(), 0>(&())
}

pub fn serialize<I, const N: usize>(value: &I) -> Result<Vec<u8>>
where
    I: Archive + Serialize<rkyv::ser::serializers::AllocSerializer<N>>,
{
    Ok(rkyv::to_bytes::<_, N>(value)
        .map_err(|_| anyhow!("failed to serialize contract argument"))?
        .to_vec())
}

pub fn decode_state_info(bytes: &[u8]) -> Result<ContractInfo> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode get_state_info response"))
}

pub fn decode_metadata(bytes: &[u8]) -> Result<DeploymentMetadata> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode get_metadata response"))
}

pub fn decode_current_root(bytes: &[u8]) -> Result<BlsScalar> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode get_current_root response"))
}

pub fn decode_accepted_roots(bytes: &[u8]) -> Result<Vec<BlsScalar>> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode get_accepted_roots response"))
}

pub fn decode_blob_option(bytes: &[u8], method: &str) -> Result<Option<Vec<u8>>> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode {method} response"))
}

pub fn decode_session(bytes: &[u8]) -> Result<Option<LicenseSession>> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode get_session response"))
}

pub fn parse_shielded_address(address: &str) -> Result<PublicKey> {
    let address = Address::from_str(address.trim()).map_err(|error| anyhow!("{error:?}"))?;
    address
        .shielded_key()
        .copied()
        .map_err(|_| anyhow!("expected a shielded address, got a public account address"))
}

pub fn license_request(
    user_secret: &SecretKey,
    issuer_public_key: &PublicKey,
) -> Result<LicenseRequest> {
    let user_public_key = PublicKey::from(user_secret);
    let request = Request::new(user_secret, &user_public_key, issuer_public_key, &mut OsRng)
        .map_err(|error| anyhow!("{error}"))?;
    let request_id = request.id();
    let version = request.version;
    let deployment_id = request.deployment_id;
    let request = rkyv::to_bytes::<_, 4096>(&request)
        .map_err(|_| anyhow!("failed to serialize request"))?
        .to_vec();

    Ok(LicenseRequest {
        request_id,
        version,
        deployment_id,
        blob: request,
    })
}

pub fn issue_license_arg(
    attributes: &str,
    recipient: PublicKey,
    issuer: &SecretKey,
) -> Result<IssueLicenseArg> {
    let attr_data = attribute_scalar(attributes);
    let license = License::new(
        &attr_data,
        issuer,
        &LicenseOrigin::FromPublicKey(Box::new(recipient)),
        LicenseOptions::default(),
        &mut OsRng,
    )
    .map_err(|error| anyhow!("{error}"))?;
    issue_arg_from_license(&license)
}

pub fn issue_license_from_request_arg(
    attributes: &str,
    request_blob: &[u8],
    issuer: &SecretKey,
) -> Result<(IssueLicenseArg, BlsScalar)> {
    let request: Request =
        rkyv::from_bytes(request_blob).map_err(|_| anyhow!("failed to decode request"))?;
    let request_id = request.id();
    let attr_data = attribute_scalar(attributes);
    let license = License::new(
        &attr_data,
        issuer,
        &LicenseOrigin::FromRequest(Box::new(request)),
        LicenseOptions::default(),
        &mut OsRng,
    )
    .map_err(|error| anyhow!("{error}"))?;

    Ok((issue_arg_from_license(&license)?, request_id))
}

fn issue_arg_from_license(license: &License) -> Result<IssueLicenseArg> {
    let license_blob = rkyv::to_bytes::<_, 4096>(license)
        .map_err(|_| anyhow!("failed to serialize license"))?
        .to_vec();
    let lpk = JubJubAffine::from(license.lsa.note_pk().as_ref());

    Ok(IssueLicenseArg {
        license: license_blob,
        lpk_u: lpk.get_u(),
        lpk_v: lpk.get_v(),
    })
}

pub fn parse_request_blob_hex(value: &str) -> Result<Vec<u8>> {
    let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let blob = hex::decode(value).map_err(|_| anyhow!("request blob is not valid hex"))?;
    rkyv::from_bytes::<Request>(&blob).map_err(|_| anyhow!("failed to decode request"))?;
    Ok(blob)
}

pub fn license_info(position: u64, license_blob: &[u8]) -> Result<LicenseInfo> {
    let license: License =
        rkyv::from_bytes(license_blob).map_err(|_| anyhow!("failed to decode license"))?;
    let lpk = JubJubAffine::from(license.lsa.note_pk().as_ref());
    Ok(LicenseInfo {
        position,
        version: license.version,
        deployment_id: license.deployment_id,
        lpk_u: lpk.get_u(),
        lpk_v: lpk.get_v(),
    })
}

pub fn issuer_public_key_hex(secret: &SecretKey) -> String {
    public_key_hex(&PublicKey::from(secret))
}

pub fn public_key_hex(public_key: &PublicKey) -> String {
    hex::encode(public_key.to_bytes())
}

pub fn attribute_scalar_hex(attributes: &str) -> String {
    hex::encode(attribute_scalar(attributes).to_bytes())
}

pub fn owned_license(
    position: u64,
    license_blob: &[u8],
    sk: &SecretKey,
) -> Result<Option<OwnedLicense>> {
    let license: License =
        rkyv::from_bytes(license_blob).map_err(|_| anyhow!("failed to decode license"))?;
    if !sk.owns(&license.lsa) {
        return Ok(None);
    }

    let payload = license
        .open(sk)
        .map_err(|error| anyhow!("failed to open owned license: {error:?}"))?;
    if payload.context.version != license.version
        || payload.context.deployment_id != license.deployment_id
        || payload.context.version != OBJECT_VERSION_V1
        || payload.context.deployment_id != DEFAULT_DEPLOYMENT.id
    {
        return Err(anyhow!("license context does not match its envelope"));
    }

    Ok(Some(OwnedLicense {
        position,
        attr_data: payload.attr_data,
        issuer: payload.pk_lp,
        license,
    }))
}

pub fn decode_merkle_opening(bytes: &[u8]) -> Result<Option<LicenseOpening>> {
    rkyv::from_bytes(bytes).map_err(|_| anyhow!("failed to decode merkle opening response"))
}

pub fn use_license_arg(
    prover_path: &Path,
    sk: &SecretKey,
    pk_lp: &PublicKey,
    pk_sp: &PublicKey,
    challenge: JubJubScalar,
    license: &License,
    merkle_opening: LicenseOpening,
) -> Result<PreparedUseLicense> {
    let prover_bytes = std::fs::read(prover_path).with_context(|| {
        format!(
            "failed to read {}. Build the contract first with `make contract` so contract/build.rs writes target/prover, or set CITADEL_PROVER_PATH to matching prover material",
            prover_path.display()
        )
    })?;
    let prover = Prover::try_from_bytes(&prover_bytes)
        .map_err(|_| anyhow!("failed to decode {}", prover_path.display()))?;
    let (gp, sc) = gadgets::GadgetParameters::compute_parameters(
        sk,
        license,
        pk_lp,
        pk_sp,
        &challenge,
        &mut OsRng,
        merkle_opening,
    )
    .map_err(|error| anyhow!("{error:?}"))?;
    let circuit = circuit::LicenseCircuit::new(&gp, &sc);
    let (proof, public_inputs) = prover
        .prove(&mut OsRng, &circuit)
        .map_err(|error| anyhow!("failed to prove license use: {error:?}"))?;

    Ok(PreparedUseLicense {
        arg: UseLicenseArg {
            proof: proof.to_bytes().to_vec(),
            public_inputs,
        },
        session_cookie: sc,
    })
}

pub fn validate_contract_info(info: &ContractInfo) -> Result<()> {
    if MERKLE_ARITY != 4 || circuit::DEPTH != 16 || PUBLIC_INPUTS_LEN != 8 {
        return Err(anyhow!(
            "local Citadel constants are not the base circuit parameters"
        ));
    }
    if info.tree_len > info.licenses {
        return Err(anyhow!(
            "contract state is inconsistent: tree_len exceeds licenses"
        ));
    }
    Ok(())
}

pub fn validate_metadata(metadata: &DeploymentMetadata) -> Result<()> {
    // The wallet only targets the repository's prototype/default deployment
    // profile. Rejecting mismatched metadata prevents silently mixing verifier
    // keys, tree parameters, or public-input layouts.
    if metadata.deployment_id != DEFAULT_DEPLOYMENT.id
        || metadata.protocol_version != DEFAULT_DEPLOYMENT.version
        || metadata.chain_id != DEFAULT_DEPLOYMENT.chain_id
        || metadata.contract_id != DEFAULT_DEPLOYMENT.contract_id
    {
        return Err(anyhow!(
            "contract metadata does not match DEFAULT_DEPLOYMENT"
        ));
    }
    if metadata.merkle_arity != MERKLE_ARITY as u32
        || metadata.merkle_depth != circuit::DEPTH as u32
        || metadata.root_history_size != ROOT_HISTORY_SIZE
        || metadata.public_inputs_len != PUBLIC_INPUTS_LEN as u32
        || metadata.max_license_blob_size != MAX_LICENSE_BLOB_SIZE
    {
        return Err(anyhow!(
            "contract metadata does not match local deployment parameters"
        ));
    }
    Ok(())
}

pub fn session_cookie_hex(cookie: &SessionCookie) -> Result<String> {
    let bytes = rkyv::to_bytes::<_, 2048>(cookie)
        .map_err(|_| anyhow!("failed to serialize session cookie"))?;
    Ok(hex::encode(bytes.as_slice()))
}

pub fn parse_bls_scalar_hex(value: &str, label: &str) -> Result<BlsScalar> {
    let bytes = decode_fixed_hex::<32>(value, label)?;
    Option::<BlsScalar>::from(BlsScalar::from_bytes(&bytes))
        .ok_or_else(|| anyhow!("{label} is not a canonical scalar"))
}

pub fn encode_challenge(challenge: &str) -> Result<JubJubScalar> {
    let challenge = challenge.trim();
    if challenge.is_empty() {
        return Err(anyhow!("challenge must not be empty"));
    }

    let digest = Sha512::digest(challenge.as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Ok(JubJubScalar::from_bytes_wide(&wide))
}

fn decode_fixed_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = hex::decode(value).map_err(|_| anyhow!("{label} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be {N} bytes of hex"))
}

fn attribute_scalar(attributes: &str) -> JubJubScalar {
    attr_data_from_canonical_attributes(
        DEFAULT_DEPLOYMENT,
        LicenseOptions::default().schema_id,
        attributes.as_bytes(),
        JubJubScalar::from(0u64),
    )
}
