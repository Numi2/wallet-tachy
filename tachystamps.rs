// tachystamps.rs
// Fully functional Groth16-based implementation for Tachystamps over BLS12-381.
// This module defines tachygrams, anchors, tachystamps, and a Groth16 circuit that
// verifies Merkle membership of multiple tachygrams using SHA-256 inside the circuit.
// It includes APIs to setup parameters, create/verify stamps, and a naive aggregation
// that proves many memberships in one circuit instance.

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use blake3::hash as blake3_hash_fn;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ----------------------------- Constants & Types -----------------------------

pub const TACHYGRAM_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tachygram(pub [u8; TACHYGRAM_LEN]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRange {
    pub start: u64,
    pub end: u64,
}

// ----------------------------- CPU Merkle (for witness generation) -----------------------------

#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<bool>, // true means current node is right child
}

#[derive(Clone, Debug)]
pub struct MerkleTreeCPU {
    pub height: usize,
    pub levels: Vec<Vec<[u8; 32]>>, // levels[0] = leaves, levels[h] = root level
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

impl MerkleTreeCPU {
    pub fn new(leaves_raw: &[Tachygram], height: usize) -> Self {
        let cap = 1usize << height;
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(cap);
        for i in 0..cap {
            if i < leaves_raw.len() {
                leaves.push(sha256_bytes(&leaves_raw[i].0));
            } else {
                leaves.push(sha256_bytes(&[0u8; 32]));
            }
        }
        let mut levels = Vec::with_capacity(height + 1);
        levels.push(leaves);
        for lvl in 0..height {
            let cur = &levels[lvl];
            let mut next = Vec::with_capacity(cur.len() / 2);
            for j in 0..(cur.len() / 2) {
                let left = cur[2 * j];
                let right = cur[2 * j + 1];
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&left);
                buf[32..].copy_from_slice(&right);
                next.push(sha256_bytes(&buf));
            }
            levels.push(next);
        }
        Self { height, levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels[self.height][0]
    }

    pub fn open(&self, mut index: usize) -> MerklePath {
        let mut siblings = Vec::with_capacity(self.height);
        let mut directions = Vec::with_capacity(self.height);
        for lvl in 0..self.height {
            let is_right = (index & 1) == 1;
            let sib_index = if is_right { index - 1 } else { index + 1 };
            siblings.push(self.levels[lvl][sib_index]);
            directions.push(is_right);
            index >>= 1;
        }
        MerklePath { siblings, directions }
    }
}

// ----------------------------- Circuit -----------------------------

// Circuit checks that all given tachygrams are members of the Merkle tree with a given root,
// using their sibling paths and direction bits. It also exposes an anchor range as public inputs.

#[derive(Clone)]
pub struct TachystampCircuit {
    pub merkle_root: [u8; 32],
    pub leaf_values: Vec<[u8; 32]>,
    pub sibling_paths: Vec<Vec<[u8; 32]>>, // per-leaf, length = height
    pub direction_bits: Vec<Vec<bool>>,    // per-leaf, length = height
    pub anchor_start: u64,
    pub anchor_end: u64,
}

impl ConstraintSynthesizer<BlsFr> for TachystampCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<BlsFr>) -> Result<(), SynthesisError> {
        // Public inputs: merkle_root (32 bytes) + anchor_start (8 bytes) + anchor_end (8 bytes)
        let root_bytes_var = UInt8::<BlsFr>::new_input_vec(cs.clone(), &self.merkle_root)?;

        let start_bytes = self.anchor_start.to_le_bytes();
        let end_bytes = self.anchor_end.to_le_bytes();
        let _anchor_start_var = UInt8::<BlsFr>::new_input_vec(cs.clone(), &start_bytes)?;
        let _anchor_end_var = UInt8::<BlsFr>::new_input_vec(cs.clone(), &end_bytes)?;

        for (i, leaf_bytes) in self.leaf_values.iter().enumerate() {
            // Witness leaf and compute its hash
            let leaf_var = UInt8::<BlsFr>::new_witness_vec(ark_relations::ns!(cs, format!("leaf_{}", i)), leaf_bytes)?;
            let mut cur = ark_r1cs_std::sha256::constraints::Sha256Gadget::evaluate(&leaf_var)?; // 32 bytes

            // Iterate over path levels
            let sibs = &self.sibling_paths[i];
            let dirs = &self.direction_bits[i];
            for (lvl, (sib_bytes, dir_bit)) in sibs.iter().zip(dirs.iter()).enumerate() {
                // Witness sibling and direction
                let sib_var = UInt8::<BlsFr>::new_witness_vec(ark_relations::ns!(cs, format!("sib_{}_{}", i, lvl)), sib_bytes)?;
                let dir_var = Boolean::new_witness(ark_relations::ns!(cs, format!("dir_{}_{}", i, lvl)), || Ok(*dir_bit))?;

                // Hash current||sibling and sibling||current
                let mut in_lr = Vec::with_capacity(64);
                in_lr.extend_from_slice(&cur);
                in_lr.extend_from_slice(&sib_var);
                let h_lr = ark_r1cs_std::sha256::constraints::Sha256Gadget::evaluate(&in_lr)?;

                let mut in_rl = Vec::with_capacity(64);
                in_rl.extend_from_slice(&sib_var);
                in_rl.extend_from_slice(&cur);
                let h_rl = ark_r1cs_std::sha256::constraints::Sha256Gadget::evaluate(&in_rl)?;

                // Select based on direction: if current is right (dir=true) then use h_rl, else h_lr
                let mut new_cur = Vec::with_capacity(32);
                for j in 0..32 {
                    let b = UInt8::<BlsFr>::conditionally_select(&dir_var, &h_rl[j], &h_lr[j])?;
                    new_cur.push(b);
                }
                cur = new_cur;
            }

            // Enforce root equality
            cur.enforce_equal(&root_bytes_var)?;
        }

        Ok(())
    }
}

// ----------------------------- API -----------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    pub merkle_root: [u8; 32],
    pub anchor: AnchorRange,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tachystamp {
    pub tachygrams: Vec<Tachygram>,
    pub anchor: AnchorRange,
    pub proof: Vec<u8>,                 // serialized Groth16 proof
    pub vk: Vec<u8>,                    // serialized verifying key (optional carry; can be separated)
    pub merkle_root: [u8; 32],
}

#[derive(Clone)]
pub struct Keys {
    pub pk: ProvingKey<Bls12_381>,
    pub vk: VerifyingKey<Bls12_381>,
    pub tree_height: usize,
    pub batch_leaves: usize,
}

pub fn setup_keys<R: Rng>(rng: &mut R, tree_height: usize, batch_leaves: usize) -> Result<Keys, SynthesisError> {
    // Build an empty circuit shape for CRS generation using zeros.
    let circuit = TachystampCircuit {
        merkle_root: [0u8; 32],
        leaf_values: vec![[0u8; 32]; batch_leaves],
        sibling_paths: vec![vec![[0u8; 32]; tree_height]; batch_leaves],
        direction_bits: vec![vec![false; tree_height]; batch_leaves],
        anchor_start: 0,
        anchor_end: 0,
    };

    let params = generate_random_parameters::<Bls12_381, _, _>(circuit, rng)?;
    let vk = params.vk.clone();
    Ok(Keys { pk: params, vk, tree_height, batch_leaves })
}

pub fn create_tachystamp<R: Rng>(
    rng: &mut R,
    keys: &Keys,
    merkle_root: [u8; 32],
    leaves: &[Tachygram],
    paths: &[MerklePath],
    anchor: AnchorRange,
) -> Result<Tachystamp, SynthesisError> {
    if leaves.len() != paths.len() || leaves.len() != keys.batch_leaves {
        return Err(SynthesisError::Unsatisfiable);
    }
    for p in paths {
        if p.siblings.len() != keys.tree_height || p.directions.len() != keys.tree_height {
            return Err(SynthesisError::Unsatisfiable);
        }
    }

    let leaf_values: Vec<[u8; 32]> = leaves.iter().map(|t| t.0).collect();
    let sibling_paths: Vec<Vec<[u8; 32]>> = paths.iter().map(|p| p.siblings.clone()).collect();
    let direction_bits: Vec<Vec<bool>> = paths.iter().map(|p| p.directions.clone()).collect();

    let circuit = TachystampCircuit {
        merkle_root,
        leaf_values,
        sibling_paths,
        direction_bits,
        anchor_start: anchor.start,
        anchor_end: anchor.end,
    };

    let proof = create_random_proof(circuit, &keys.pk, rng)?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    keys.vk.serialize_compressed(&mut vk_bytes).unwrap();

    Ok(Tachystamp { tachygrams: leaves.to_vec(), anchor, proof: proof_bytes, vk: vk_bytes, merkle_root })
}

pub fn verify_tachystamp(ts: &Tachystamp) -> Result<bool, SynthesisError> {
    // Prepare public inputs: root bytes + start bytes + end bytes
    let mut public_inputs: Vec<BlsFr> = Vec::new();

    // Root as 32 bytes -> interpret each byte as a field element of Fr.
    for b in ts.merkle_root.iter() {
        public_inputs.push(BlsFr::from(*b as u128));
    }
    // Anchor start/end bytes
    for b in ts.anchor.start.to_le_bytes().iter() {
        public_inputs.push(BlsFr::from(*b as u128));
    }
    for b in ts.anchor.end.to_le_bytes().iter() {
        public_inputs.push(BlsFr::from(*b as u128));
    }

    let vk: VerifyingKey<Bls12_381> = VerifyingKey::deserialize_compressed(ts.vk.as_slice()).map_err(|_| SynthesisError::AssignmentMissing)?;
    let pvk = prepare_verifying_key(&vk);
    let proof: Proof<Bls12_381> = Proof::deserialize_compressed(ts.proof.as_slice()).map_err(|_| SynthesisError::AssignmentMissing)?;
    let ok = verify_proof(&pvk, &proof, &public_inputs)?;
    Ok(ok)
}

// Naive aggregation: concatenate tachygrams and prove all in a single proof (requires CRS that supports total count)
pub fn aggregate_tachystamps<R: Rng>(
    rng: &mut R,
    keys: &Keys,
    merkle_root: [u8; 32],
    all_leaves: &[Tachygram],
    all_paths: &[MerklePath],
    anchor: AnchorRange,
) -> Result<Tachystamp, SynthesisError> {
    create_tachystamp(rng, keys, merkle_root, all_leaves, all_paths, anchor)
}

// ----------------------------- Helper: Build Merkle -----------------------------

// Builds a CPU Merkle tree and returns it.
pub fn build_merkle(leaves: &[Tachygram], height: usize) -> MerkleTreeCPU {
    MerkleTreeCPU::new(leaves, height)
}

pub fn open_path(tree: &MerkleTreeCPU, index: usize) -> MerklePath {
    tree.open(index)
}

pub fn blake3_label(label: &[u8], body: &[u8]) -> [u8; 32] {
    let mut v = Vec::with_capacity(label.len() + body.len());
    v.extend_from_slice(label);
    v.extend_from_slice(body);
    *blake3_hash_fn(&v).as_bytes()
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn prove_verify_single_and_aggregate() {
        let mut rng = test_rng();
        let height = 4; // 16 leaves capacity

        // CRS supports up to 4 leaves per proof in this example
        let keys = setup_keys(&mut rng, height, 4).expect("setup");

        // Build a small tree with some leaves
        let mut leaves = Vec::new();
        for i in 0..8u8 {
            let mut b = [0u8; 32];
            b[0] = i;
            leaves.push(Tachygram(b));
        }
        let (root, tree) = build_merkle(&leaves, height);
        let mut root_arr = [0u8; 32];
        root_arr.copy_from_slice(&root);

        // Proof for 4 leaves (batch size = 4)
        let l = vec![leaves[0], leaves[1], leaves[2], leaves[3]];
        let p = vec![
            open_path(&tree, 0),
            open_path(&tree, 1),
            open_path(&tree, 2),
            open_path(&tree, 3),
        ];
        let anchor = AnchorRange { start: 100, end: 200 };
        let ts = create_tachystamp(&mut rng, &keys, root_arr, &l, &p, anchor).unwrap();
        assert!(verify_tachystamp(&ts).unwrap());

        // Aggregate 4 leaves into one proof (batch size 4)
        let l3 = vec![leaves[4], leaves[5], leaves[6], leaves[7]];
        let p3 = vec![
            open_path(&tree, 4),
            open_path(&tree, 5),
            open_path(&tree, 6),
            open_path(&tree, 7),
        ];
        let ts2 = aggregate_tachystamps(&mut rng, &keys, root_arr, &l3, &p3, anchor).unwrap();
        assert!(verify_tachystamp(&ts2).unwrap());
    }
}


