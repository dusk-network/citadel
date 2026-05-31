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
use std::path::{Path, PathBuf};
use zk_citadel::circuit;

static LABEL: &[u8; 12] = b"dusk-network";

const CRS_URL: &str = "https://nodes.dusk.network/trusted-setup";
const CRS_17_HASH: &str = "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";

const PROVER_PATH: &str = "../target/prover";
const VERIFIER_PATH: &str = "../target/verifier";
const CIRCUIT_MARKER_PATH: &str = "../target/license-circuit-build-id";
const CIRCUIT_BUILD_ID: &str = "zk-citadel-license-circuit";

#[tokio::main]
async fn main() {
    if setup_material_stale() {
        let response = reqwest::get(CRS_URL).await;

        match response {
            Ok(pp_bytes) => {
                // If setup didn't exist locally, we download the setup again from server
                let pp_bytes = pp_bytes.bytes().await.unwrap();
                let mut hasher = Sha256::new();
                hasher.update(pp_bytes.clone());
                let hash = format!("{:x}", hasher.finalize());

                // We check the file integrity
                assert_eq!(hash, CRS_17_HASH);

                let pp = PublicParameters::from_slice(pp_bytes.to_vec().as_slice())
                    .expect("Creating PublicParameters from slice failed.");

                // Compile the license circuit
                let (prover, verifier) = Compiler::compile::<circuit::LicenseCircuit>(&pp, LABEL)
                    .expect("failed to compile circuit");

                // Write prover key to disk
                let mut file = File::create(PROVER_PATH).unwrap();
                file.write_all(&prover.to_bytes()).unwrap();

                // Write verifier key to disk
                let mut file = File::create(VERIFIER_PATH).unwrap();
                file.write_all(&verifier.to_bytes()).unwrap();
                write_circuit_marker();

                info!("Local trusted setup not found, a new one was downloaded.");
            }
            Err(_e) => {
                // If download fails, we create a setup from scratch
                let pp = PublicParameters::setup(1 << circuit::CAPACITY, &mut OsRng).unwrap();

                // Compile the license circuit
                let (prover, verifier) = Compiler::compile::<circuit::LicenseCircuit>(&pp, LABEL)
                    .expect("failed to compile circuit");

                // Write prover key to disk
                let mut file = File::create(PROVER_PATH).unwrap();
                file.write_all(&prover.to_bytes()).unwrap();

                // Write verifier key to disk
                let mut file = File::create(VERIFIER_PATH).unwrap();
                file.write_all(&verifier.to_bytes()).unwrap();
                write_circuit_marker();

                warn!(
                    "Download of trusted setup from server failed. A new one was generated from scratch. USE AT YOUR OWN RISK."
                );
            }
        }
    }

    write_metadata_hashes();
}

fn setup_material_stale() -> bool {
    if !(Path::new(PROVER_PATH).exists()) || !(Path::new(VERIFIER_PATH).exists()) {
        return true;
    }

    fs::read_to_string(CIRCUIT_MARKER_PATH)
        .map(|marker| marker.trim() != CIRCUIT_BUILD_ID)
        .unwrap_or(true)
}

fn write_circuit_marker() {
    fs::write(CIRCUIT_MARKER_PATH, CIRCUIT_BUILD_ID).expect("circuit marker should be written");
}

fn write_metadata_hashes() {
    let verifier = fs::read(VERIFIER_PATH).expect("verifier key should exist after build");
    let verifier_key_hash = scalar_from_sha256(b"CITADEL_VERIFIER_KEY_HASH_V1", &verifier);
    let circuit_hash = scalar_from_sha256(b"CITADEL_CIRCUIT_HASH_V1", CIRCUIT_BUILD_ID.as_bytes());

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should be set"));
    let generated = out_dir.join("metadata_hashes.rs");
    let contents = format!(
        "const VERIFIER_KEY_HASH: BlsScalar = BlsScalar::from_raw({verifier_key_hash:?});\n\
         const CIRCUIT_HASH: BlsScalar = BlsScalar::from_raw({circuit_hash:?});\n",
    );

    fs::write(generated, contents).expect("metadata hash constants should be written");
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
