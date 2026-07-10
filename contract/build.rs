// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use build_print::*;
use dusk_plonk::prelude::*;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::PathBuf;
use zk_citadel::circuit;

static LABEL: &[u8; 12] = b"dusk-network";

const CRS_URL: &str = "https://nodes.dusk.network/trusted-setup";
const CRS_17_HASH: &str = "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";

const PROVER_PATH: &str = "../target/prover";
const VERIFIER_PATH: &str = "../target/verifier";
const CIRCUIT_MARKER_PATH: &str = "../target/license-circuit-build-id";
const OUT_DIR_VERIFIER_FILENAME: &str = "license_verifier";
const CIRCUIT_BUILD_DOMAIN: &[u8] = b"zk-citadel-license-circuit-v2";
const CIRCUIT_SOURCE_PATHS: &[(&str, &str)] = &[
    ("core/Cargo.toml", "../core/Cargo.toml"),
    ("core/src/helpers.rs", "../core/src/helpers.rs"),
    ("core/src/signatures.rs", "../core/src/signatures.rs"),
    ("core/src/zk/circuit.rs", "../core/src/zk/circuit.rs"),
    ("core/src/zk/gadgets.rs", "../core/src/zk/gadgets.rs"),
];

#[tokio::main]
async fn main() {
    emit_rerun_directives();

    let circuit_build_id = circuit_build_id();
    let response = reqwest::get(CRS_URL).await;
    let verifier_bytes = match response {
        Ok(pp_bytes) => compile_from_trusted_crs(pp_bytes, &circuit_build_id).await,
        Err(_e) => compile_from_fresh_setup(&circuit_build_id),
    };

    write_metadata_hashes(&circuit_build_id, &verifier_bytes);
}

fn emit_rerun_directives() {
    std::println!("cargo:rerun-if-changed=build.rs");
    for (_, disk_path) in CIRCUIT_SOURCE_PATHS {
        std::println!("cargo:rerun-if-changed={disk_path}");
    }
}

async fn compile_from_trusted_crs(pp_bytes: reqwest::Response, circuit_build_id: &str) -> Vec<u8> {
    let pp_bytes = pp_bytes.bytes().await.unwrap();
    let mut hasher = Sha256::new();
    hasher.update(pp_bytes.clone());
    let hash = format!("{:x}", hasher.finalize());

    // We check the file integrity
    assert_eq!(hash, CRS_17_HASH);

    let pp = PublicParameters::from_slice(pp_bytes.to_vec().as_slice())
        .expect("Creating PublicParameters from slice failed.");
    let verifier_bytes = compile_and_write_setup_material(&pp, circuit_build_id);

    info!("License circuit setup material was regenerated from the trusted CRS.");
    verifier_bytes
}

fn compile_from_fresh_setup(circuit_build_id: &str) -> Vec<u8> {
    // If download fails, we create a setup from scratch
    let pp = PublicParameters::setup(1 << circuit::CAPACITY, &mut OsRng).unwrap();
    let verifier_bytes = compile_and_write_setup_material(&pp, circuit_build_id);

    warn!(
        "Download of trusted setup from server failed. A new one was generated from scratch. USE AT YOUR OWN RISK."
    );
    verifier_bytes
}

fn compile_and_write_setup_material(pp: &PublicParameters, circuit_build_id: &str) -> Vec<u8> {
    let (prover, verifier) =
        Compiler::compile::<circuit::LicenseCircuit>(pp, LABEL).expect("failed to compile circuit");
    let prover_bytes = prover.to_bytes();
    let verifier_bytes = verifier.to_bytes();

    // Keep the legacy target paths for wallets/tests, but embed the verifier
    // from OUT_DIR so deployed bytecode cannot observe a stale target file.
    let mut file = File::create(PROVER_PATH).unwrap();
    file.write_all(&prover_bytes).unwrap();

    let mut file = File::create(VERIFIER_PATH).unwrap();
    file.write_all(&verifier_bytes).unwrap();

    let out_dir_verifier = out_dir().join(OUT_DIR_VERIFIER_FILENAME);
    fs::write(out_dir_verifier, &verifier_bytes).expect("OUT_DIR verifier should be written");

    write_circuit_marker(circuit_build_id);
    verifier_bytes
}

fn circuit_build_id() -> String {
    let mut hasher = Sha256::new();
    hasher.update(CIRCUIT_BUILD_DOMAIN);

    for (canonical_path, disk_path) in CIRCUIT_SOURCE_PATHS {
        let source = fs::read(disk_path)
            .unwrap_or_else(|error| panic!("failed to read {disk_path}: {error}"));
        hasher.update((*canonical_path).as_bytes());
        hasher.update((source.len() as u64).to_le_bytes());
        hasher.update(source);
    }

    format!("{:x}", hasher.finalize())
}

fn write_circuit_marker(circuit_build_id: &str) {
    let prover_hash = file_sha256_hex(PROVER_PATH).expect("prover hash should be computed");
    let verifier_hash = file_sha256_hex(VERIFIER_PATH).expect("verifier hash should be computed");
    let marker = format!(
        "circuit_build_id={circuit_build_id}\nprover_hash={prover_hash}\nverifier_hash={verifier_hash}\n"
    );
    fs::write(CIRCUIT_MARKER_PATH, marker).expect("circuit marker should be written");
}

fn write_metadata_hashes(circuit_build_id: &str, verifier: &[u8]) {
    let verifier_key_hash = scalar_from_sha256(b"CITADEL_VERIFIER_KEY_HASH_V1", verifier);
    let circuit_hash = scalar_from_sha256(b"CITADEL_CIRCUIT_HASH_V1", circuit_build_id.as_bytes());

    let generated = out_dir().join("metadata_hashes.rs");
    let contents = format!(
        "const VERIFIER_KEY_HASH: BlsScalar = BlsScalar::from_raw({verifier_key_hash:?});\n\
         const CIRCUIT_HASH: BlsScalar = BlsScalar::from_raw({circuit_hash:?});\n",
    );

    fs::write(generated, contents).expect("metadata hash constants should be written");
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should be set"))
}

fn scalar_from_sha256(domain: &[u8], bytes: &[u8]) -> [u64; 4] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..31].copy_from_slice(&digest[..31]);

    let mut limbs = [0u64; 4];
    for (i, byte) in scalar_bytes.iter().enumerate() {
        limbs[i / 8] |= (*byte as u64) << ((i % 8) * 8);
    }

    limbs
}

fn file_sha256_hex(path: &str) -> std::io::Result<String> {
    fs::read(path).map(|bytes| sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
