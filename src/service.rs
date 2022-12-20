use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::from_utf8;

use colored::Colorize;
use dusk_bytes::Serializable;
use rand_core::OsRng;

use dusk_plonk::prelude::*;

const NUM_PUBLIC_INPUTS: usize = 8;
static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 17; // capacity required for the setup

use crate::gadget;
use crate::license::License;

#[derive(Default, Debug)]
pub struct Service {
    license: License,
}

impl Service {
    pub fn new(license: License) -> Self {
        Self { license }
    }

    pub fn generate_setup_to_file() {
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
        let (prover, verifier) =
            Compiler::compile::<Service>(&pp, LABEL).expect("failed to compile circuit");

        let prover_bytes = prover.to_bytes();
        let verifier_bytes = verifier.to_bytes();

        fs::create_dir("setup").unwrap();
        fs::write("setup/prover_bytes", prover_bytes).expect("Unable to write file");
        fs::write("setup/verifier_bytes", verifier_bytes).expect("Unable to write file");
    }

    pub fn clean() {
        fs::remove_dir_all("setup").unwrap();
    }

    fn handle_user(mut stream: TcpStream, verifier: &Verifier<Service>) {
        let mut buffer_proof = [0; 1040];
        let mut buffer_public_inputs = [[0; 32]; NUM_PUBLIC_INPUTS];

        stream.read(&mut buffer_proof).unwrap();

        for i in 0..NUM_PUBLIC_INPUTS {
            stream.read(&mut buffer_public_inputs[i]).unwrap();
        }

        println!(
            "{} License proof received.",
            format!("[log] :").bold().blue()
        );

        let mut public_inputs = Vec::new();

        for i in 0..NUM_PUBLIC_INPUTS {
            public_inputs.push(BlsScalar::from_bytes(&buffer_public_inputs[i]).unwrap());
        }

        let proof = Proof::from_bytes(&buffer_proof).unwrap();

        println!(
            "{} Verifying license proof...",
            format!("[log] :").bold().blue()
        );

        if verifier.verify(&proof, &public_inputs).is_ok() {
            stream.write(b"AUTHORIZED").unwrap();
            println!(
                "{} License proof verified. User authorized.\n",
                format!("[log] :").bold().blue()
            );
        } else {
            stream.write(b"DENIED").unwrap();
            println!(
                "{} License proof not verified. User not authorized.\n",
                format!("[log] :").bold().blue()
            );
        }

        stream.flush().unwrap();
    }

    pub fn run_service_provider(port: String) {
        println!(
            "\n{} Setting up the Service Provider...",
            format!("[INFO] :").bold().yellow()
        );

        let verifier_bytes = fs::read("setup/verifier_bytes").expect("Unable to read file");
        let verifier = dusk_plonk::composer::Verifier::try_from_bytes(&verifier_bytes).unwrap();

        let listener = TcpListener::bind("localhost:".to_owned() + &port).unwrap();
        println!(
            "{} Service Provider listening on port {}.\n",
            format!("[INFO] :").bold().yellow(),
            port
        );

        for stream in listener.incoming() {
            let stream = stream.unwrap();
            println!(
                "{} New connection from {}",
                format!("[log] :").bold().blue(),
                stream.peer_addr().unwrap()
            );
            Self::handle_user(stream, &verifier);
        }
    }

    pub fn run_user(ip: String, port: String) {
        println!(
            "\n{} Setting up the user...",
            format!("[INFO] :").bold().yellow()
        );

        let prover_bytes = fs::read("setup/prover_bytes").expect("Unable to read file");
        let prover = Prover::try_from_bytes(&prover_bytes).unwrap();

        let server = ip + ":" + &port;

        match TcpStream::connect(server.clone()) {
            Ok(mut stream) => {
                println!(
                    "{} Connected to Service Provider {}.\n",
                    format!("[INFO] :").bold().yellow(),
                    server
                );
                println!(
                    "{} Computing license proof...",
                    format!("[log] :").bold().blue()
                );

                let license = License::random(&mut OsRng);
                let (proof, public_inputs) = prover
                    .prove(&mut OsRng, &Service::new(license))
                    .expect("failed to prove");

                stream.write(&proof.to_bytes()).unwrap();

                for i in 0..NUM_PUBLIC_INPUTS {
                    stream.write(&public_inputs[i].to_bytes()).unwrap();
                }

                println!(
                    "{} License proof sent to Service Provider.",
                    format!("[log] :").bold().blue()
                );

                let mut data = [0 as u8; 128];
                stream.read(&mut data).unwrap();
                let text = from_utf8(&data).unwrap();

                if text[..10].eq("AUTHORIZED") {
                    println!(
                        "{} Login: {}\n",
                        format!("[log] :").bold().blue(),
                        format!("[ACCESS GRANTED]").bold().green()
                    );
                } else {
                    println!(
                        "{} Login: {}\n",
                        format!("[log] :").bold().blue(),
                        format!("[ACCESS DENIED]").bold().red()
                    );
                }
            }

            Err(e) => {
                println!("Connection error: {}", e);
            }
        }
    }
}

impl Circuit for Service {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        gadget::nullify_license(composer, &self.license)?;
        Ok(())
    }
}
