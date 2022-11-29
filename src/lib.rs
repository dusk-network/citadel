use dusk_jubjub::{GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS, GENERATOR_NUMS_EXTENDED};
use dusk_pki::SecretKey;
use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::sponge;
use dusk_poseidon::sponge::truncated;
use dusk_schnorr::{gadgets, Signature};
use rand_core::{CryptoRng, OsRng, RngCore};

use canonical_derive::Canon;
use dusk_poseidon::tree::{self, PoseidonAnnotation, PoseidonBranch, PoseidonLeaf, PoseidonTree};

use dusk_bytes::Serializable;
use dusk_plonk::prelude::*;

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::from_utf8;

use colored::Colorize;

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 17; // capacity required for the setup
const DEPTH: usize = 17; // depth of the 4-ary Merkle tree
type Tree = PoseidonTree<DataLeaf, PoseidonAnnotation, DEPTH>;

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon)]
pub struct DataLeaf {
    data: BlsScalar,
    pos: u64,
}

impl DataLeaf {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let data = BlsScalar::random(rng);
        let pos = 0;

        Self { data, pos }
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

#[derive(Debug, Copy, Clone)]
pub struct License {
    npk_user: JubJubAffine,   // note public key
    npk_user_p: JubJubAffine, // note public key prime

    pk_sp: JubJubAffine, // static public key of the service provider SP
    attr: BlsScalar,     // set of attributes describing our license
    sig_lic: Signature,  // signature of the license

    note_type: BlsScalar, // 2: transparent, 3: obfuscated
    enc: BlsScalar,       // encryption of the commitment opening
    nonce: BlsScalar,     // IV for the encryption
    r_user: JubJubAffine, // R value of the user
    pos: BlsScalar,       // position of the note in the Merkle tree

    s0: JubJubScalar, // randomness for the hash
    s1: JubJubScalar, // randomness for the Pedersen Commitment
    s2: JubJubScalar, // randomness for the Pedersen Commitment

    c: BlsScalar,                // challenge for the nullifier
    tx_hash: BlsScalar,          // hash of the transaction nullifying the license
    sig_tx: dusk_schnorr::Proof, // signature of the tx_hash
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

        let attr = BlsScalar::from(00112233445566778899u64);
        let message = sponge::truncated::hash(&[npk_user.get_x(), npk_user.get_y(), attr]);

        let sig_lic = Signature::new(&sk_sp, rng, BlsScalar::from(message));

        let note_type = BlsScalar::from(3u64);
        let enc = BlsScalar::random(rng);
        let nonce = BlsScalar::random(rng);
        let r_user = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(rng));
        let pos = BlsScalar::from(1u64);

        // Third, the user computes these values to generate the ZKP later on
        let s0 = JubJubScalar::random(rng);
        let s1 = JubJubScalar::random(rng);
        let s2 = JubJubScalar::random(rng);

        let c = BlsScalar::from(20221126u64);
        let tx_hash = BlsScalar::from(00112233445566778899u64);
        let sig_tx = dusk_schnorr::Proof::new(&nsk_user, rng, tx_hash);

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

            c,
            tx_hash,
            sig_tx,
        }
    }

    pub fn prove(
        &self,
        pp: &PublicParameters,
        branch: &PoseidonBranch<DEPTH>,
        pk: &ProverKey,
    ) -> Proof {
        Citadel::new(*self, branch.clone())
            .prove(&pp, &pk, LABEL, &mut OsRng)
            .expect("Proof computed")
    }

    pub fn verify(pp: &PublicParameters, vd: &VerifierData, proof: &Proof) -> bool {
        Citadel::verify(&pp, &vd, &proof, &[], LABEL).is_ok()
    }
}

#[derive(Debug)]
pub struct Citadel {
    license: License,
    branch: PoseidonBranch<DEPTH>,
}

impl Citadel {
    pub fn new(license: License, branch: PoseidonBranch<DEPTH>) -> Self {
        Self { license, branch }
    }

    pub fn poseidon_branch_random<R: RngCore + CryptoRng>(rng: &mut R) -> PoseidonBranch<DEPTH> {
        // Instantiate a tree with random elements as an example
        let mut tree = Tree::default();
        let leaf = DataLeaf::random(rng);
        let pos_tree = tree.push(leaf).expect("Appended to the tree");

        for i in 0..1024 {
            let l = DataLeaf::from(i as u64);
            tree.push(l).expect("Appended to the tree");
        }

        tree.branch(pos_tree)
            .expect("Tree was read successfully")
            .expect("The branch of the created leaf from the tree was fetched successfully")
    }

    pub fn generate_setup() -> (PublicParameters, usize, ProverKey, VerifierData) {
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
        let mut circuit = Self::new(
            License::random(&mut OsRng),
            Self::poseidon_branch_random(&mut OsRng),
        );
        let (pk, vd) = circuit.compile(&pp).expect("Circuit compiled");

        unsafe { (pp, CONSTRAINTS, pk, vd) }
    }

    pub fn generate_setup_to_file() {
        let (pp, _constraints, pk, vd) = Self::generate_setup();

        let pp_bytes = pp.to_var_bytes();
        let pk_bytes = pk.to_var_bytes();
        let vd_bytes = vd.to_var_bytes();

        fs::create_dir("setup").unwrap();
        fs::write("setup/pp_bytes", pp_bytes).expect("Unable to write file");
        fs::write("setup/pk_bytes", pk_bytes).expect("Unable to write file");
        fs::write("setup/vd_bytes", vd_bytes).expect("Unable to write file");
    }

    pub fn clean() {
        fs::remove_dir_all("setup").unwrap();
    }

    fn handle_client(mut stream: TcpStream, pp: PublicParameters, vd: VerifierData) {
        let mut buffer = [0; 1040];
        stream.read(&mut buffer).unwrap();

        println!(
            "{} License proof received.",
            format!("[log] :").bold().blue()
        );
        let proof = Proof::from_bytes(&buffer).unwrap();

        println!(
            "{} Verifying license proof...",
            format!("[log] :").bold().blue()
        );

        if License::verify(&pp, &vd, &proof) {
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

        let pp_bytes = fs::read("setup/pp_bytes").expect("Unable to read file");
        let pp = PublicParameters::from_slice(&pp_bytes).unwrap();
        let vd_bytes = fs::read("setup/vd_bytes").expect("Unable to read file");
        let vd = VerifierData::from_slice(&vd_bytes).unwrap();

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
            Self::handle_client(stream, pp.clone(), vd.clone());
        }
    }

    pub fn run_client(ip: String, port: String) {
        println!(
            "\n{} Setting up the Citadel Client...",
            format!("[INFO] :").bold().yellow()
        );

        let pp_bytes = fs::read("setup/pp_bytes").expect("Unable to read file");
        let pp = PublicParameters::from_slice(&pp_bytes).unwrap();
        let pk_bytes = fs::read("setup/pk_bytes").expect("Unable to read file");
        let pk = ProverKey::from_slice(&pk_bytes).unwrap();

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

                let branch = Citadel::poseidon_branch_random(&mut OsRng);
                let license = License::random(&mut OsRng);
                let proof = license.prove(&pp, &branch, &pk);

                stream.write(&proof.to_bytes()).unwrap();

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
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), PlonkError> {
        // APPEND THE NOTE PUBLIC KEYS OF THE USER
        let npk_user = composer.append_point(self.license.npk_user);
        let npk_user_p = composer.append_point(self.license.npk_user_p);

        // COMPUTE THE LICENSE NULLIFIER
        let c = composer.append_witness(self.license.c);
        let _nullifier_lic = sponge::gadget(composer, &[*npk_user_p.x(), *npk_user_p.y(), c]);

        // VERIFY THE SIGNATURES
        let (sig_lic_u, sig_lic_r) = self.license.sig_lic.to_witness(composer);
        let pk_sp = composer.append_point(self.license.pk_sp);
        let attr = composer.append_witness(self.license.attr);

        let message = truncated::gadget(composer, &[*npk_user.x(), *npk_user.y(), attr]);
        gadgets::single_key_verify(composer, sig_lic_u, sig_lic_r, pk_sp, message);

        let (sig_tx_u, sig_tx_r, sig_tx_r_p) = self.license.sig_tx.to_witness(composer);
        let tx_hash = composer.append_witness(self.license.tx_hash);
        gadgets::double_key_verify(
            composer, sig_tx_u, sig_tx_r, sig_tx_r_p, npk_user, npk_user_p, tx_hash,
        );

        // COMMIT TO THE PK_SP USING A HASH FUNCTION
        let s0 = composer.append_witness(self.license.s0);
        let _com_0 = sponge::gadget(composer, &[*pk_sp.x(), *pk_sp.y(), s0]);

        // COMMIT TO THE ATTRIBUTE
        let s1 = composer.append_witness(self.license.s1);
        let pc_1_1 = composer.component_mul_generator(attr, GENERATOR);
        let pc_1_2 = composer.component_mul_generator(s1, GENERATOR_NUMS);
        let _com_1 = composer.component_add_point(pc_1_1, pc_1_2);

        // COMMIT TO THE CHALLENGE
        let s2 = composer.append_witness(self.license.s2);
        let pc_2_1 = composer.component_mul_generator(c, GENERATOR);
        let pc_2_2 = composer.component_mul_generator(s2, GENERATOR_NUMS);
        let _com_2 = composer.component_add_point(pc_2_1, pc_2_2);

        // COMPUTE THE HASH OF THE NOTE
        let note_type = composer.append_witness(self.license.note_type);
        let enc = composer.append_witness(self.license.enc);
        let nonce = composer.append_witness(self.license.nonce);
        let r_user = composer.append_point(self.license.r_user);
        let pos = composer.append_witness(self.license.pos);

        let _hash = sponge::gadget(
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
        use std::ops::Deref;

        let leaf: BlsScalar = *self.branch.deref();
        let leaf = composer.append_witness(leaf);

        let root = self.branch.root();
        let root = composer.append_witness(*root);

        // TODO: use _hash instead of leaf
        let root_p = tree::merkle_opening::<DEPTH>(composer, &self.branch, leaf);

        composer.assert_equal(root_p, root);

        unsafe {
            CONSTRAINTS = composer.gates();
        }

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![] // TODO: add public inputs
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY - 1
    }
}

#[test]
fn test_full_citadel() {
    let (pp, _constraints, pk, vd) = Citadel::generate_setup();
    let branch = Citadel::poseidon_branch_random(&mut OsRng);
    let license = License::random(&mut OsRng);

    let proof = license.prove(&pp, &branch, &pk);
    assert_eq!(License::verify(&pp, &vd, &proof), true);
}

#[test]
fn test_full_citadel_false_proof() {
    let (pp_false, _constraints, pk_false, _vd_false) = Citadel::generate_setup();
    let branch = Citadel::poseidon_branch_random(&mut OsRng);
    let license = License::random(&mut OsRng);

    let proof = license.prove(&pp_false, &branch, &pk_false);
    let (pp, _constraints, _pk, vd) = Citadel::generate_setup();
    assert_eq!(License::verify(&pp, &vd, &proof), false);
}
