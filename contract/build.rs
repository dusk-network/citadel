// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use build_print::*;
use dusk_plonk::prelude::*;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use zk_citadel::circuit;

static LABEL: &[u8; 12] = b"dusk-network";

const CRS_URL: &str = "https://nodes.dusk.network/trusted-setup";
const CRS_17_HASH: &str = "6161605616b62356cf09fa28252c672ef53b2c8489ad5f81d87af26e105f6059";
const VERIFIER_PATH: &str = "../target/verifier";

#[tokio::main]
async fn main() {
    // If verifier key already exists, no need to download again
    if !(Path::new(VERIFIER_PATH).exists()) {
        let response = reqwest::get(CRS_URL).await;

        match response {
            Ok(pp_bytes) => {
                // If verifier key didn't exist, we download again from server
                let pp_bytes = pp_bytes.bytes().await.unwrap();
                let mut hasher = Sha256::new();
                hasher.update(pp_bytes.clone());
                let hash = format!("{:x}", hasher.finalize());

                // We check the file integrity
                assert_eq!(hash, CRS_17_HASH);

                let pp = PublicParameters::from_slice(pp_bytes.to_vec().as_slice())
                    .expect("Creating PublicParameters from slice failed.");

                // Compile the license circuit
                let (_prover, verifier) = Compiler::compile::<circuit::LicenseCircuit>(&pp, LABEL)
                    .expect("failed to compile circuit");

                // Write verifier key to disk
                let mut file = File::create(VERIFIER_PATH).unwrap();
                file.write_all(&verifier.to_bytes()).unwrap();

                info!("Local trusted setup not found, a new one was downloaded.");
            }
            Err(_e) => {
                // If download fails, we create a setup from scratch
                let pp = PublicParameters::setup(1 << circuit::CAPACITY, &mut OsRng).unwrap();

                // Compile the license circuit
                let (_prover, verifier) = Compiler::compile::<circuit::LicenseCircuit>(&pp, LABEL)
                    .expect("failed to compile circuit");

                // Write verifier key to disk
                let mut file = File::create(VERIFIER_PATH).unwrap();
                file.write_all(&verifier.to_bytes()).unwrap();

                warn!("Download of trusted setup from server failed. A new one was generated from scratch. USE AT YOUR OWN RISK.");
            }
        }
    }
}
