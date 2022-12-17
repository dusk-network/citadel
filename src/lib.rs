use dusk_jubjub::{GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS, GENERATOR_NUMS_EXTENDED};
use dusk_pki::SecretKey;
use dusk_poseidon::sponge;
use dusk_schnorr::{gadgets, Signature};
use rand_core::{CryptoRng, OsRng, RngCore};

use dusk_poseidon::tree::{self, PoseidonBranch, PoseidonLeaf, PoseidonTree};

use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::from_utf8;

use colored::Colorize;
use nstack::annotation::Keyed;

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";

const CAPACITY: usize = 17; // capacity required for the setup
const NUM_PUBLIC_INPUTS: usize = 8;

const DEPTH: usize = 17; // depth of the 4-ary Merkle tree
type Tree = PoseidonTree<DataLeaf, (), DEPTH>;

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct DataLeaf {
    data: BlsScalar,
    pos: u64,
}

// Keyed needs to be implemented for a leaf type and the tree key.
impl Keyed<()> for DataLeaf {
    fn key(&self) -> &() {
        &()
    }
}

impl DataLeaf {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let data = BlsScalar::random(rng);
        let pos = 0;

        Self { data, pos }
    }
    pub fn new(hash: BlsScalar, n: u64) -> DataLeaf {
        DataLeaf { data: hash, pos: n }
    }
}

impl From<u64> for DataLeaf {
    fn from(n: u64) -> DataLeaf {
        DataLeaf {
            data: BlsScalar::from(n),
            pos: n,
        }
    }
}

impl PoseidonLeaf for DataLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        self.data
    }

    fn pos(&self) -> &u64 {
        &self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

pub struct LicenseProof {
    proof: Proof,
    public_inputs: Vec<BlsScalar>,
}

impl LicenseProof {
    pub fn new(proof: Proof, public_inputs: Vec<BlsScalar>) -> Self {
        Self {
            proof,
            public_inputs,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct License {
    npk_user: JubJubAffine,   // note public key
    npk_user_p: JubJubAffine, // note public key prime

    pk_sp: JubJubAffine, // static public key of the service provider SP
    attr: JubJubScalar,  // set of attributes describing our license
    sig_lic: Signature,  // signature of the license

    note_type: BlsScalar, // 2: transparent, 3: obfuscated
    enc: BlsScalar,       // encryption of the commitment opening
    nonce: BlsScalar,     // IV for the encryption
    r_user: JubJubAffine, // R value of the user
    pos: BlsScalar,       // position of the note in the Merkle tree

    s0: BlsScalar,    // randomness for the hash
    s1: JubJubScalar, // randomness for the Pedersen Commitment
    s2: JubJubScalar, // randomness for the Pedersen Commitment

    com_0: BlsScalar,      // Hash commitment 0
    com_1: JubJubExtended, // Pedersen Commitment 1
    com_2: JubJubExtended, // Pedersen Ccommitment 2

    c: JubJubScalar,             // challenge for the nullifier
    tx_hash: BlsScalar,          // hash of the transaction nullifying the license
    sig_tx: dusk_schnorr::Proof, // signature of the tx_hash
    nullifier_lic: BlsScalar,    // License nullifier

    merkle_proof: PoseidonBranch<DEPTH>, // Merkle proof for the Proof of Validity
}

impl License {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // First, the user computes these values and requests a License
        let nsk_user = SecretKey::random(rng);
        let npk_user = JubJubAffine::from(GENERATOR_EXTENDED * nsk_user.as_ref());
        let npk_user_p = JubJubAffine::from(GENERATOR_NUMS_EXTENDED * nsk_user.as_ref());

        // Second, the SP computes these values and grants the License
        let sk_sp = SecretKey::random(rng);
        let pk_sp = JubJubAffine::from(GENERATOR_EXTENDED * sk_sp.as_ref());

        let attr = JubJubScalar::from(00112233445566778899u64);
        let message = sponge::hash(&[npk_user.get_x(), npk_user.get_y(), BlsScalar::from(attr)]);

        let sig_lic = Signature::new(&sk_sp, rng, message);

        let note_type = BlsScalar::from(3u64);
        let enc = BlsScalar::random(rng);
        let nonce = BlsScalar::random(rng);
        let r_user = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(rng));
        let pos = BlsScalar::from(1u64);

        // Third, the user computes these values to generate the ZKP later on
        let s0 = BlsScalar::random(rng);
        let s1 = JubJubScalar::random(rng);
        let s2 = JubJubScalar::random(rng);

        let c = JubJubScalar::from(20221126u64);
        let tx_hash = BlsScalar::from(00112233445566778899u64);
        let sig_tx = dusk_schnorr::Proof::new(&nsk_user, rng, tx_hash);

        let com_0 = sponge::hash(&[pk_sp.get_x(), pk_sp.get_y(), s0]);

        let com_1 = (GENERATOR_EXTENDED * attr) + (GENERATOR_NUMS_EXTENDED * s1);
        let com_2 = (GENERATOR_EXTENDED * c) + (GENERATOR_NUMS_EXTENDED * s2);

        let nullifier_lic =
            sponge::hash(&[npk_user_p.get_x(), npk_user_p.get_y(), BlsScalar::from(c)]);

        let note_hash = sponge::hash(&[
            note_type,
            enc,
            nonce,
            r_user.get_x(),
            r_user.get_y(),
            npk_user.get_x(),
            npk_user.get_y(),
            pos,
        ]);

        let mut tree = Tree::default();
        let pos_tree = tree.push(DataLeaf::new(note_hash, 0));

        for i in 1..1024 {
            let l = DataLeaf::from(i as u64);
            tree.push(l);
        }

        let merkle_proof = tree.branch(pos_tree).expect("Tree was read successfully");

        Self {
            npk_user,
            npk_user_p,

            pk_sp,
            attr,
            sig_lic,

            note_type,
            enc,
            nonce,
            r_user,
            pos,

            s0,
            s1,
            s2,

            com_0,
            com_1,
            com_2,

            c,
            tx_hash,
            sig_tx,
            nullifier_lic,

            merkle_proof,
        }
    }
}

#[derive(Default, Debug)]
pub struct Citadel {
    license: License,
}

impl Citadel {
    pub fn new(license: License) -> Self {
        Self { license }
    }

    pub fn generate_setup() -> (usize, Prover<Self>, Verifier<Self>) {
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
        let (pk, vk) = Compiler::compile::<Citadel>(&pp, LABEL).expect("failed to compile circuit");

        unsafe { (CONSTRAINTS, pk, vk) }
    }

    pub fn prove(license: License, pk: Prover<Citadel>) -> LicenseProof {
        let (proof, public_inputs) = pk
            .prove(&mut OsRng, &Citadel::new(license))
            .expect("failed to prove");
        LicenseProof::new(proof, public_inputs)
    }

    pub fn verify(proof: &LicenseProof, vk: &Verifier<Citadel>) -> bool {
        vk.verify(&proof.proof, &proof.public_inputs).is_ok()
    }

    pub fn generate_setup_to_file() {
        let (_constraints, pk, vk) = Self::generate_setup();

        let pk_bytes = pk.to_bytes();
        let vk_bytes = vk.to_bytes();

        fs::create_dir("setup").unwrap();
        fs::write("setup/pk_bytes", pk_bytes).expect("Unable to write file");
        fs::write("setup/vk_bytes", vk_bytes).expect("Unable to write file");
    }

    pub fn clean() {
        fs::remove_dir_all("setup").unwrap();
    }

    fn handle_client(mut stream: TcpStream, vk: &Verifier<Citadel>) {
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

        let proof = LicenseProof::new(Proof::from_bytes(&buffer_proof).unwrap(), public_inputs);

        println!(
            "{} Verifying license proof...",
            format!("[log] :").bold().blue()
        );

        if Citadel::verify(&proof, &vk) {
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

    pub fn run_server(port: String) {
        println!(
            "\n{} Setting up the Citadel Server...",
            format!("[INFO] :").bold().yellow()
        );

        let vk_bytes = fs::read("setup/vk_bytes").expect("Unable to read file");
        let vk = Verifier::try_from_bytes(&vk_bytes).unwrap();

        let listener = TcpListener::bind("localhost:".to_owned() + &port).unwrap();
        println!(
            "{} Citadel Server listening on port {}.\n",
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
            Self::handle_client(stream, &vk);
        }
    }

    pub fn run_client(ip: String, port: String) {
        println!(
            "\n{} Setting up the Citadel Client...",
            format!("[INFO] :").bold().yellow()
        );

        let pk_bytes = fs::read("setup/pk_bytes").expect("Unable to read file");
        let pk = Prover::try_from_bytes(&pk_bytes).unwrap();

        let server = ip + ":" + &port;

        match TcpStream::connect(server.clone()) {
            Ok(mut stream) => {
                println!(
                    "{} Connected to Citadel Server {}.\n",
                    format!("[INFO] :").bold().yellow(),
                    server
                );
                println!(
                    "{} Computing license proof...",
                    format!("[log] :").bold().blue()
                );

                let license = License::random(&mut OsRng);
                let proof = Citadel::prove(license, pk);

                stream.write(&proof.proof.to_bytes()).unwrap();

                for i in 0..NUM_PUBLIC_INPUTS {
                    stream.write(&proof.public_inputs[i].to_bytes()).unwrap();
                }

                println!(
                    "{} License proof sent to Citadel Server.",
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

impl Circuit for Citadel {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        // APPEND THE NOTE PUBLIC KEYS OF THE USER
        let npk_user = composer.append_point(self.license.npk_user);
        let npk_user_p = composer.append_point(self.license.npk_user_p);

        // COMPUTE THE LICENSE NULLIFIER
        let c = composer.append_witness(self.license.c);
        let nullifier_lic_pi = composer.append_public(self.license.nullifier_lic);
        let nullifier_lic = sponge::gadget(composer, &[*npk_user_p.x(), *npk_user_p.y(), c]);

        composer.assert_equal(nullifier_lic, nullifier_lic_pi);

        // VERIFY THE SIGNATURES
        let (sig_lic_u, sig_lic_r) = self.license.sig_lic.to_witness(composer);
        let pk_sp = composer.append_point(self.license.pk_sp);
        let attr = composer.append_witness(self.license.attr);

        let message = sponge::gadget(composer, &[*npk_user.x(), *npk_user.y(), attr]);
        gadgets::single_key_verify(composer, sig_lic_u, sig_lic_r, pk_sp, message)?;

        let (sig_tx_u, sig_tx_r, sig_tx_r_p) = self.license.sig_tx.to_witness(composer);
        let tx_hash = composer.append_public(self.license.tx_hash);
        gadgets::double_key_verify(
            composer, sig_tx_u, sig_tx_r, sig_tx_r_p, npk_user, npk_user_p, tx_hash,
        )?;

        // COMMIT TO THE PK_SP USING A HASH FUNCTION
        let s0 = composer.append_witness(self.license.s0);
        let com_0_pi = composer.append_public(self.license.com_0);
        let com_0 = sponge::gadget(composer, &[*pk_sp.x(), *pk_sp.y(), s0]);

        composer.assert_equal(com_0, com_0_pi);

        // COMMIT TO THE ATTRIBUTE
        let s1 = composer.append_witness(self.license.s1);
        let pc_1_1 = composer.component_mul_generator(attr, GENERATOR);
        let pc_1_2 = composer.component_mul_generator(s1, GENERATOR_NUMS);
        let com_1 = composer.component_add_point(pc_1_1.unwrap(), pc_1_2.unwrap());

        composer.assert_equal_public_point(com_1, self.license.com_1);

        // COMMIT TO THE CHALLENGE
        let s2 = composer.append_witness(self.license.s2);
        let pc_2_1 = composer.component_mul_generator(c, GENERATOR);
        let pc_2_2 = composer.component_mul_generator(s2, GENERATOR_NUMS);
        let com_2 = composer.component_add_point(pc_2_1.unwrap(), pc_2_2.unwrap());

        composer.assert_equal_public_point(com_2, self.license.com_2);

        // COMPUTE THE HASH OF THE NOTE
        let note_type = composer.append_witness(self.license.note_type);
        let enc = composer.append_witness(self.license.enc);
        let nonce = composer.append_witness(self.license.nonce);
        let r_user = composer.append_point(self.license.r_user);
        let pos = composer.append_witness(self.license.pos);

        let note_hash = sponge::gadget(
            composer,
            &[
                note_type,
                enc,
                nonce,
                *r_user.x(),
                *r_user.y(),
                *npk_user.x(),
                *npk_user.y(),
                pos,
            ],
        );

        // VERIFY THE MERKLE PROOF
        let root_pi = composer.append_public(*self.license.merkle_proof.root());
        let root =
            tree::merkle_opening::<C, DEPTH>(composer, &self.license.merkle_proof, note_hash);

        composer.assert_equal(root, root_pi);

        unsafe {
            CONSTRAINTS = composer.constraints();
        }

        Ok(())
    }
}

#[test]
fn test_full_citadel() {
    let (_constraints, pk, vk) = Citadel::generate_setup();
    let license = License::random(&mut OsRng);
    let proof = Citadel::prove(license, pk);
    assert_eq!(Citadel::verify(&proof, &vk), true);
}

#[test]
fn test_full_citadel_false_public_input() {
    let (_constraints, pk, vk) = Citadel::generate_setup();
    let license = License::random(&mut OsRng);
    let mut proof = Citadel::prove(license, pk);

    // set a false public input
    proof.public_inputs[0] = BlsScalar::random(&mut OsRng);

    assert_eq!(Citadel::verify(&proof, &vk), false);
}
