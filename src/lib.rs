use dusk_jubjub::{GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS};
use dusk_pki::SecretKey;
use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::sponge;
use dusk_poseidon::sponge::truncated;
use dusk_schnorr::{gadgets, Signature};
use rand_core::{CryptoRng, OsRng, RngCore};

use canonical_derive::Canon;
use dusk_poseidon::tree::{self, PoseidonAnnotation, PoseidonBranch, PoseidonLeaf, PoseidonTree};

use dusk_plonk::prelude::*;

static mut CONSTRAINTS: usize = 0;
static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 16; // capacity required for the setup
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

#[derive(Debug)]
pub struct Citadel {
    c: BlsScalar,           // challenge for the nullifier
    npk_user: JubJubAffine, // note public key of the user
    lsk: JubJubScalar,      // license secret key

    attr: BlsScalar,     // set of attributes describing our license
    lsig: Signature,     // signature of the license
    pk_sp: JubJubAffine, // static public key of the service provider SP
    t: JubJubScalar,     // randomness for the Pedersen Commitment

    note_type: BlsScalar, // 2: transparent, 3: obfuscated
    enc: BlsScalar,       // encryption of the commitment opening
    nonce: BlsScalar,     // IV for the encryption
    r_user: JubJubAffine, // R value of the user
    pos: BlsScalar,       // position of the note in the Merkle tree

    branch: PoseidonBranch<DEPTH>, // merkle tree branch
}

impl Citadel {
    pub fn new(
        c: BlsScalar,
        npk_user: JubJubAffine,
        lsk: JubJubScalar,

        attr: BlsScalar,
        lsig: Signature,
        pk_sp: JubJubAffine,
        t: JubJubScalar,

        note_type: BlsScalar,
        enc: BlsScalar,
        nonce: BlsScalar,
        r_user: JubJubAffine,
        pos: BlsScalar,

        branch: PoseidonBranch<DEPTH>,
    ) -> Self {
        Self {
            c,
            npk_user,
            lsk,

            attr,
            lsig,
            pk_sp,
            t,

            note_type,
            enc,
            nonce,
            r_user,
            pos,

            branch,
        }
    }

    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, tree: &mut Tree) -> Self {
        // We set random values as an example
        let c = BlsScalar::random(rng);
        let r = JubJubScalar::random(rng);
        let npk_user = JubJubAffine::from(GENERATOR_EXTENDED * r);

        let lsk = JubJubScalar::random(rng);
        let lpk = JubJubAffine::from(GENERATOR_EXTENDED * lsk);

        let sk_sp = SecretKey::random(rng);
        let attr = BlsScalar::from(00112233445566778899u64);

        let message = sponge::truncated::hash(&[
            npk_user.get_x(),
            npk_user.get_y(),
            attr,
            lpk.get_x(),
            lpk.get_y(),
        ]);
        let lsig = Signature::new(&sk_sp, rng, BlsScalar::from(message));

        let pk_sp = JubJubAffine::from(GENERATOR_EXTENDED * sk_sp.as_ref());

        let t = JubJubScalar::random(rng);

        let leaf = DataLeaf::random(rng);
        let pos_tree = tree.push(leaf).expect("Failed to append to the tree");

        let branch = tree
            .branch(pos_tree)
            .expect("Failed to read the tree for the branch")
            .expect("Failed to fetch the branch of the created leaf from the tree");

        let note_type = BlsScalar::from(3u64);
        let enc = BlsScalar::random(rng);
        let nonce = BlsScalar::random(rng);
        let r_user = JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::random(rng));
        let pos = BlsScalar::from(1u64);

        Self {
            c,
            npk_user,
            lsk,

            attr,
            lsig,
            pk_sp,
            t,

            note_type,
            enc,
            nonce,
            r_user,
            pos,

            branch,
        }
    }
}

impl Circuit for Citadel {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), PlonkError> {
        // COMPUTE THE LICENSE KEYPAIR
        let lsk = composer.append_witness(self.lsk);
        let lpk = composer.component_mul_generator(lsk, GENERATOR);

        // COMPUTE THE LICENSE NULLIFIER
        let c = composer.append_witness(self.c);
        let npk_user = composer.append_point(self.npk_user);
        let _lnullifier = sponge::gadget(composer, &[c, *npk_user.x(), *npk_user.y(), lsk]);

        // VERIFYING THE SIGNATURE
        let (lsig_u, lsig_r) = self.lsig.to_witness(composer);
        let pk_sp = composer.append_point(self.pk_sp);
        let attr = composer.append_witness(self.attr);

        let message = truncated::gadget(
            composer,
            &[*npk_user.x(), *npk_user.y(), attr, *lpk.x(), *lpk.y()],
        );
        gadgets::single_key_verify(composer, lsig_u, lsig_r, pk_sp, message);

        // COMMIT TO THE PAYLOAD_NFT
        let payload_nft = truncated::gadget(composer, &[lsig_u, *lsig_r.x(), *lsig_r.y(), attr]);
        let t = composer.append_witness(self.t);

        let pc_1 = composer.component_mul_generator(payload_nft, GENERATOR);
        let pc_2 = composer.component_mul_generator(t, GENERATOR_NUMS);

        let com = composer.component_add_point(pc_1, pc_2);

        // COMPUTE THE HASH OF THE NOTE
        let note_type = composer.append_witness(self.note_type);
        let enc = composer.append_witness(self.enc);
        let nonce = composer.append_witness(self.nonce);
        let r_user = composer.append_point(self.r_user);
        let pos = composer.append_witness(self.pos);

        let _hash = sponge::gadget(
            composer,
            &[
                *com.x(),
                *com.y(),
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

pub fn citadel_setup() -> (PublicParameters, usize, Citadel, ProverKey, VerifierData) {
    // Perform the circuit setup
    let mut tree = Tree::default();
    let mut circuit = Citadel::random(&mut OsRng, &mut tree);
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

    // Instantiate a tree with random elements as an example
    let mut tree: PoseidonTree<DataLeaf, PoseidonAnnotation, DEPTH> = PoseidonTree::new();
    for i in 0..1024 {
        let l = DataLeaf::from(i as u64);
        tree.push(l).expect("Failed appending to the tree");
    }

    unsafe { (pp, CONSTRAINTS, circuit, pk, vd) }
}

pub fn citadel_prover(pp: &PublicParameters, input: &Citadel, pk: &ProverKey) -> Proof {
    Citadel::new(
        input.c,
        input.npk_user,
        input.lsk,
        input.attr,
        input.lsig,
        input.pk_sp,
        input.t,
        input.note_type,
        input.enc,
        input.nonce,
        input.r_user,
        input.pos,
        input.branch.clone(),
    )
    .prove(&pp, &pk, LABEL, &mut OsRng)
    .expect("Failed to prove")
}

pub fn citadel_verifier(pp: &PublicParameters, vd: &VerifierData, proof: &Proof) {
    Citadel::verify(&pp, &vd, &proof, &[], LABEL).expect("Proof verification failed");
}

#[test]
fn test_full_citadel() {
    let (pp, _constraints, circuit, pk, vd) = citadel_setup();
    let proof = citadel_prover(&pp, &circuit, &pk);
    citadel_verifier(&pp, &vd, &proof);
}
