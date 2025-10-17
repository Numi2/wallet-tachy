//! tachystamp_ivc.rs
//!
//! attempt at  IVC aggregation for Tachystamps using Nova over the Pasta cycle.
//! One action per step. Each step verifies a Merkle membership of a (cv_net, rk)
//! leaf under an arbitrary anchor. Aggregation happens inside IVC (no post-hoc folding).
//!
//! Hash inside the circuit: SHA-256 using the bellpepper gadget.
//!
//! Public state z = [accumulator, count] in Pallas Fp.
//! - `accumulator` is a field element updated per step via packed SHA-256 outputs.
//! - `count` increments by 1 per step.
//!Numan
//! - Builder `build_ivc_aggregate` producing a `CompressedSNARK`
//! - Verifier `verify_ivc_aggregate`
//! - Native Merkle helpers for witness construction and tests

#![allow(clippy::needless_borrow)]
#![allow(clippy::too_many_arguments)]

use bellpepper::gadgets::{
    boolean::{AllocatedBit, Boolean},
    multipack,
    num::AllocatedNum,
    sha256::sha256 as sha256_gadget,
};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use halo2curves::ff::{Field, PrimeField};
use halo2curves::pasta::Fp as PallasFp;
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::Group;
use nova_snark::{CompressedSNARK, PublicParams, RecursiveSNARK};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use thiserror::Error;

// =====================================================================================
// Errors
// =====================================================================================

#[derive(Error, Debug)]
pub enum IVCError {
    #[error("empty step list")]
    Empty,
    #[error("mismatched tree height: expected {expected}, got {got}")]
    BadTreeHeight { expected: usize, got: usize },
    #[error("nova: {0}")]
    Nova(String),
    #[error("synthesis error: {0}")]
    Synthesis(String),
}

impl From<SynthesisError> for IVCError {
    fn from(e: SynthesisError) -> Self {
        IVCError::Synthesis(format!("{e:?}"))
    }
}

// =====================================================================================
// Merkle utilities (SHA-256 based, binary tree, hash(left || right))
// =====================================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    pub siblings: Vec<[u8; 32]>, // from leaf to root
    pub is_right: Vec<bool>,     // true if current node is right child at that level
}

impl MerklePath {
    pub fn height(&self) -> usize {
        self.siblings.len()
    }
}

fn sha256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

fn sha256_leaf(cv: &[u8; 32], rk: &[u8; 32]) -> [u8; 32] {
    sha256_concat(cv, rk)
}

fn verify_membership_native(
    leaf: [u8; 32],
    path: &MerklePath,
    leaf_is_right: &[bool],
) -> [u8; 32] {
    // leaf_is_right[i] describes the position of the running node at each level.
    let mut cur = leaf;
    for (i, sib) in path.siblings.iter().enumerate() {
        let left_right = if leaf_is_right[i] {
            (sib, &cur)
        } else {
            (&cur, sib)
        };
        cur = sha256_concat(left_right.0, left_right.1);
    }
    cur
}

// =====================================================================================
// Step witness and circuit
// =====================================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepWitness {
    pub cv: [u8; 32],
    pub rk: [u8; 32],
    pub anchor: [u8; 32],
    pub path: MerklePath,   // Merkle siblings
    pub pos: Vec<bool>,     // position bits: true => current is right child
    pub tx_index: u32,      // optional metadata
    pub action_index: u32,  // optional metadata
}

#[derive(Clone, Debug)]
pub struct TachyIVCParams {
    pub tree_height: usize,
}

#[derive(Clone)]
pub struct TachyStepCircuit<F: PrimeField> {
    pub params: TachyIVCParams,
    pub wit: Option<StepWitness>,
    _m: PhantomData<F>,
}

impl<F: PrimeField> TachyStepCircuit<F> {
    pub fn empty(params: TachyIVCParams) -> Self {
        Self { params, wit: None, _m: PhantomData }
    }

    pub fn with_witness(params: TachyIVCParams, wit: StepWitness) -> Self {
        Self { params, wit: Some(wit), _m: PhantomData }
    }

    // Allocate a 32-byte array as 256 little-endian bits.
    fn alloc_bytes_as_bits_le<CS: ConstraintSystem<F>>(
        mut cs: CS,
        label: &str,
        bytes: &[u8; 32],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let mut bits = Vec::with_capacity(256);
        for (i, byte) in bytes.iter().enumerate() {
            for j in 0..8 {
                let b = (byte >> j) & 1u8 != 0;
                let bit = AllocatedBit::alloc(cs.namespace(|| format!("{label}_{i}_{j}")), Some(b))?;
                bits.push(Boolean::from(bit));
            }
        }
        Ok(bits)
    }

    // Conditional select between two Boolean bit-vectors: out = sel? b : a
    fn select_bits<CS: ConstraintSystem<F>>(
        mut cs: CS,
        sel: &Boolean,
        a: &[Boolean],
        b: &[Boolean],
        label: &str,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        assert_eq!(a.len(), b.len());
        let mut out = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            // out = (a AND NOT sel) XOR (b AND sel)
            let not_sel = sel.not();
            let a_part = Boolean::and(cs.namespace(|| format!("{label}_aand_{i}")), &a[i], &not_sel)?;
            let b_part = Boolean::and(cs.namespace(|| format!("{label}_band_{i}")), &b[i], sel)?;
            let bit = Boolean::xor(cs.namespace(|| format!("{label}_xor_{i}")), &a_part, &b_part)?;
            out.push(bit);
        }
        Ok(out)
    }

    // Pack first 248 bits into a field element
    fn pack_248_bits<CS: ConstraintSystem<F>>(
        mut cs: CS,
        label: &str,
        bits: &[Boolean],
    ) -> Result<AllocatedNum<F>, SynthesisError> {
        assert!(bits.len() >= 248);
        let slice = &bits[..248];
        multipack::pack_bits(cs.namespace(|| label), slice)
    }

    fn synthesize_inner<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        z_in: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // z = [acc, count]
        assert!(z_in.len() == 2, "arity must be 2");

        let acc_in = &z_in[0];
        let count_in = &z_in[1];

        let wit = self.wit.as_ref().expect("witness must be present");
        if wit.path.height() != self.params.tree_height || wit.pos.len() != self.params.tree_height {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Allocate cv, rk, anchor as bit arrays
        let cv_bits = Self::alloc_bytes_as_bits_le(cs.namespace(|| "cv_bits"), &wit.cv)?;
        let rk_bits = Self::alloc_bytes_as_bits_le(cs.namespace(|| "rk_bits"), &wit.rk)?;
        let anchor_bits = Self::alloc_bytes_as_bits_le(cs.namespace(|| "anchor_bits"), &wit.anchor)?;

        // leaf = SHA256(cv || rk)
        let mut leaf_bits = {
            let mut input = Vec::with_capacity(512);
            input.extend_from_slice(&cv_bits);
            input.extend_from_slice(&rk_bits);
            sha256_gadget(cs.namespace(|| "leaf_sha256"), &input)?
        };

        // Climb the Merkle path
        for (i, sib_bytes) in wit.path.siblings.iter().enumerate() {
            let sib_bits = Self::alloc_bytes_as_bits_le(cs.namespace(|| format!("sib_bits_{i}")), sib_bytes)?;

            // Select ordering based on position: if current is right, parent = H(sib || cur) else H(cur || sib)
            let dir_bit = AllocatedBit::alloc(cs.namespace(|| format!("dir_{i}")), Some(wit.pos[i]))?;
            let dir = Boolean::from(dir_bit);

            let left_bits = Self::select_bits(
                cs.namespace(|| format!("select_left_{i}")),
                &dir,              // sel=true => choose sibling
                &leaf_bits,        // a
                &sib_bits,         // b
                "sel_left",
            )?;
            let right_bits = Self::select_bits(
                cs.namespace(|| format!("select_right_{i}")),
                &dir,              // sel=true => choose current
                &sib_bits,         // a
                &leaf_bits,        // b
                "sel_right",
            )?;

            // parent = SHA256(left || right)
            let mut input = Vec::with_capacity(512);
            input.extend_from_slice(&left_bits);
            input.extend_from_slice(&right_bits);
            leaf_bits = sha256_gadget(cs.namespace(|| format!("parent_sha256_{i}")), &input)?;
        }

        // Enforce root == anchor (bitwise equality)
        assert_eq!(leaf_bits.len(), 256);
        for i in 0..256 {
            // leaf_bits[i] XOR anchor_bits[i] == false
            let diff = Boolean::xor(cs.namespace(|| format!("root_eq_xor_{i}")), &leaf_bits[i], &anchor_bits[i])?;
            // Enforce diff == 0
            match diff {
                Boolean::Constant(false) => {}
                Boolean::Constant(true) => return Err(SynthesisError::Unsatisfiable),
                Boolean::Is(ref bit) => {
                    // bit * 1 = 0
                    cs.enforce(
                        || format!("root_bit_zero_{i}"),
                        |lc| lc + bit.get_variable(),
                        |lc| lc + CS::one(),
                        |lc| lc,
                    );
                }
                Boolean::Not(_) => unreachable!("xor of booleans never returns Not at this stage"),
            }
        }

        // Mix into accumulator:
        // acc_out = acc_in + pack(leaf_bits[0..248]) + 3*pack(anchor_bits[0..248]) + 1
        let leaf_packed = Self::pack_248_bits(cs.namespace(|| "pack_leaf"), &leaf_bits)?;
        let anchor_packed = Self::pack_248_bits(cs.namespace(|| "pack_anchor"), &anchor_bits)?;

        // three = 3
        let three = AllocatedNum::alloc(cs.namespace(|| "three"), || Ok(F::from(3u64)))?;
        cs.enforce(
            || "three is 3",
            |lc| lc + CS::one() + CS::one() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + three.get_variable(),
        );

        let three_anchor = AllocatedNum::mul(cs.namespace(|| "3*anchor"), &anchor_packed, &three)?;

        let tmp_sum = AllocatedNum::alloc(cs.namespace(|| "tmp_sum"), || {
            let mut v = *acc_in.get_value().get()?;
            v.add_assign(leaf_packed.get_value().get()?);
            let mut t = *three_anchor.get_value().get()?;
            v.add_assign(&t);
            v.add_assign(&F::ONE);
            Ok(v)
        })?;
        // Enforce: tmp_sum - acc_in - leaf_packed - (3*anchor_packed) - 1 = 0
        cs.enforce(
            || "accumulate",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc
                + tmp_sum.get_variable()
                - acc_in.get_variable()
                - leaf_packed.get_variable()
                - three_anchor.get_variable()
                - CS::one(),
        );

        let acc_out = tmp_sum;

        // count_out = count_in + 1
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::ONE))?;
        cs.enforce(
            || "one is 1",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + one.get_variable(),
        );

        let count_out = AllocatedNum::alloc(cs.namespace(|| "count_out"), || {
            let mut v = *count_in.get_value().get()?;
            v.add_assign(&F::ONE);
            Ok(v)
        })?;
        cs.enforce(
            || "count_out = count_in + 1",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count_out.get_variable() - count_in.get_variable() - one.get_variable(),
        );

        Ok(vec![acc_out, count_out])
    }
}

// Primary circuit over Pallas scalar
impl<G: Group<Scalar = PallasFp>> StepCircuit<G::Scalar> for TachyStepCircuit<G::Scalar> {
    fn arity(&self) -> usize {
        2
    }
    fn synthesize<CS: ConstraintSystem<G::Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<G::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError> {
        self.synthesize_inner(cs.namespace(|| "TachyStep"), z)
    }
}

// Trivial identity circuit for secondary side
#[derive(Clone)]
pub struct TrivialIdentity<F: PrimeField> {
    pub arity: usize,
    _m: PhantomData<F>,
}
impl<F: PrimeField> TrivialIdentity<F> {
    pub fn new(arity: usize) -> Self {
        Self { arity, _m: PhantomData }
    }
}
impl<F: PrimeField> StepCircuit<F> for TrivialIdentity<F> {
    fn arity(&self) -> usize {
        self.arity
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Enforce z' = z
        let mut out = Vec::with_capacity(self.arity);
        for (i, zi) in z.iter().enumerate() {
            let o = AllocatedNum::alloc(cs.namespace(|| format!("id_out_{i}")), || Ok(*zi.get_value().get()?))?;
            cs.enforce(
                || format!("id copy {i}"),
                |lc| lc + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + o.get_variable() - zi.get_variable(),
            );
            out.push(o);
        }
        Ok(out)
    }
}

// =====================================================================================
// Aggregate artifact
// =====================================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMetadata {
    pub tx_index: u32,
    pub action_start_index: usize,
    pub action_count: usize,
    pub action_pairs: Vec<([u8; 32], [u8; 32])>,
}

#[derive(Clone, Debug)]
pub struct IVCAggregate {
    pub pp: PublicParams<
        PallasEngine,
        VestaEngine,
        TachyStepCircuit<PallasFp>,
        TrivialIdentity<<VestaEngine as Group>::Scalar>,
    >,
    pub compressed: CompressedSNARK<
        PallasEngine,
        VestaEngine,
        TachyStepCircuit<PallasFp>,
        TrivialIdentity<<VestaEngine as Group>::Scalar>,
    >,
    pub z0_primary: Vec<PallasFp>,
    pub zn_primary: Vec<PallasFp>,
    pub num_steps: usize,
    pub tree_height: usize,
    pub aggregate_id: u32,
    pub tx_meta: Vec<TransactionMetadata>,
}

// =====================================================================================
// Builder and verifier
// =====================================================================================

#[derive(Clone, Debug)]
pub struct BuildInput {
    pub steps: Vec<StepWitness>,
    pub tree_height: usize,
    pub aggregate_id: u32,
    pub tx_boundaries: Vec<(u32, usize, usize)>, // (tx_index, start_step, count)
}

/// Build a true IVC aggregate. One step per action.
/// z0 = [acc0, 0] with acc0 = pack_248( SHA256( agg_id_bytes || zeros[32] ) )
pub fn build_ivc_aggregate(input: BuildInput) -> Result<IVCAggregate, IVCError> {
    if input.steps.is_empty() {
        return Err(IVCError::Empty);
    }
    // Check uniform height and positions
    for s in &input.steps {
        if s.path.height() != input.tree_height || s.pos.len() != input.tree_height {
            return Err(IVCError::BadTreeHeight {
                expected: input.tree_height,
                got: s.path.height(),
            });
        }
    }

    // Circuits
    let primary_empty: TachyStepCircuit<PallasFp> =
        TachyStepCircuit::empty(TachyIVCParams { tree_height: input.tree_height });
    let secondary_id: TrivialIdentity<<VestaEngine as Group>::Scalar> = TrivialIdentity::new(2);

    // Public params
    let pp: PublicParams<PallasEngine, VestaEngine, _, _> =
        PublicParams::setup(&primary_empty, &secondary_id);

    // z0
    let acc0 = {
        let mut id_bytes = [0u8; 32];
        id_bytes[..4].copy_from_slice(&input.aggregate_id.to_le_bytes());
        let seed = sha256_concat(&id_bytes, &[0u8; 32]);
        // pack first 248 bits little-endian into field
        let mut bits = Vec::with_capacity(256);
        for byte in seed {
            for j in 0..8 {
                bits.push(((byte >> j) & 1u8) != 0);
            }
        }
        // interpret 248 little-endian bits
        let mut acc = PallasFp::ZERO;
        let mut coeff = PallasFp::ONE;
        for i in 0..248 {
            if bits[i] {
                acc += coeff;
            }
            coeff = coeff.double(); // multiply by 2
        }
        acc
    };
    let mut z0_primary = vec![acc0, PallasFp::ZERO];
    let mut z0_secondary = vec![<VestaEngine as Group>::Scalar::ZERO; 2];

    // Recursive SNARK
    let mut rn: RecursiveSNARK<PallasEngine, VestaEngine, _, _> =
        RecursiveSNARK::new(&pp, &primary_empty, &secondary_id, &z0_primary, &z0_secondary)
            .map_err(|e| IVCError::Nova(format!("{e:?}")))?;

    // Prove steps
    for (i, step) in input.steps.iter().enumerate() {
        let c_primary = TachyStepCircuit::<PallasFp>::with_witness(
            TachyIVCParams { tree_height: input.tree_height },
            step.clone(),
        );
        let c_secondary = secondary_id.clone();

        rn.prove_step(&pp, &c_primary, &c_secondary)
            .map_err(|e| IVCError::Nova(format!("prove_step {i}: {e:?}")))?;
    }

    // Derive final z
    let (zn_primary, zn_secondary) = rn
        .get_state()
        .map_err(|e| IVCError::Nova(format!("get_state: {e:?}")))?;

    // Verify uncompressed recursive proof
    rn.verify(&pp, &primary_empty, &secondary_id, &z0_primary, &z0_secondary, &zn_primary, &zn_secondary)
        .map_err(|e| IVCError::Nova(format!("verify recursive: {e:?}")))?;

    // Compress
    let csnark = CompressedSNARK::prove(&pp, &rn)
        .map_err(|e| IVCError::Nova(format!("compress: {e:?}")))?;

    // Build metadata from tx boundaries
    let mut tx_meta = Vec::new();
    for (tx_index, start, count) in input.tx_boundaries {
        let mut pairs = Vec::with_capacity(count);
        for j in 0..count {
            let s = &input.steps[start + j];
            pairs.push((s.cv, s.rk));
        }
        tx_meta.push(TransactionMetadata {
            tx_index,
            action_start_index: start,
            action_count: count,
            action_pairs: pairs,
        });
    }

    Ok(IVCAggregate {
        pp,
        compressed: csnark,
        z0_primary,
        zn_primary,
        num_steps: input.steps.len(),
        tree_height: input.tree_height,
        aggregate_id: input.aggregate_id,
        tx_meta,
    })
}

/// Verify a compressed IVC aggregate.
///
/// Recomputes z0 from aggregate_id. Expects zn from aggregate.
pub fn verify_ivc_aggregate(agg: &IVCAggregate) -> Result<(), IVCError> {
    let primary_empty: TachyStepCircuit<PallasFp> =
        TachyStepCircuit::empty(TachyIVCParams { tree_height: agg.tree_height });
    let secondary_id: TrivialIdentity<<VestaEngine as Group>::Scalar> = TrivialIdentity::new(2);

    // Recompute acc0 the same way as in build
    let acc0 = {
        let mut id_bytes = [0u8; 32];
        id_bytes[..4].copy_from_slice(&agg.aggregate_id.to_le_bytes());
        let seed = sha256_concat(&id_bytes, &[0u8; 32]);
        let mut bits = Vec::with_capacity(256);
        for byte in seed {
            for j in 0..8 {
                bits.push(((byte >> j) & 1u8) != 0);
            }
        }
        let mut acc = PallasFp::ZERO;
        let mut coeff = PallasFp::ONE;
        for i in 0..248 {
            if bits[i] {
                acc += coeff;
            }
            coeff = coeff.double();
        }
        acc
    };

    let z0_primary = vec![acc0, PallasFp::ZERO];
    let z0_secondary = vec![<VestaEngine as Group>::Scalar::ZERO; 2];

    agg.compressed
        .verify(
            &agg.pp,
            &primary_empty,
            &secondary_id,
            &z0_primary,
            &z0_secondary,
            &agg.zn_primary,
            &vec![<VestaEngine as Group>::Scalar::ZERO; 2],
        )
        .map_err(|e| IVCError::Nova(format!("verify compressed: {e:?}")))
}

// =====================================================================================
// Helper: native Merkle tree builder for witness prep
// =====================================================================================

#[derive(Clone, Debug)]
pub struct MerkleTree {
    pub height: usize,
    pub leaves: Vec<[u8; 32]>,
    pub nodes: Vec<Vec<[u8; 32]>>, // nodes[0] = leaves, nodes[h] root layer length 1
}

impl MerkleTree {
    pub fn new(height: usize, pairs: &Vec<([u8; 32], [u8; 32])>) -> Self {
        assert!(pairs.len() <= (1 << height));
        let n_leaves = 1 << height;

        let mut leaves = vec!([0u8; 32]); // placeholder to allow resize
        leaves.resize(n_leaves, [0u8; 32]);

        for (i, (cv, rk)) in pairs.iter().enumerate() {
            leaves[i] = sha256_leaf(cv, rk);
        }

        let mut nodes = Vec::with_capacity(height + 1);
        nodes.push(leaves.clone());

        let mut cur = leaves;
        for _ in 0..height {
            let mut next = Vec::with_capacity(cur.len() / 2);
            for j in (0..cur.len()).step_by(2) {
                let l = cur[j];
                let r = cur[j + 1];
                next.push(sha256_concat(&l, &r));
            }
            nodes.push(next.clone());
            cur = next;
        }
        Self { height, leaves: nodes[0].clone(), nodes }
    }

    pub fn root(&self) -> [u8; 32] {
        self.nodes[self.height][0]
    }

    pub fn path(&self, index: usize) -> (MerklePath, Vec<bool>) {
        assert!(index < (1 << self.height));
        let mut idx = index;
        let mut siblings = Vec::with_capacity(self.height);
        let mut is_right = Vec::with_capacity(self.height);

        for h in 0..self.height {
            let sib_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sib = self.nodes[h][sib_idx];
            siblings.push(sib);
            is_right.push(idx % 2 == 1);
            idx >>= 1;
        }
        (MerklePath { siblings, is_right: is_right.clone() }, is_right)
    }
}

// =====================================================================================
// Tests
// =====================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pairs(n: usize) -> Vec<([u8; 32], [u8; 32])> {
        (0..n)
            .map(|i| {
                let mut cv = [0u8; 32];
                cv[0] = (i & 0xff) as u8;
                let mut rk = [0u8; 32];
                rk[0] = ((i + 100) & 0xff) as u8;
                (cv, rk)
            })
            .collect()
    }

    #[test]
    fn test_native_merkle() {
        let h = 3;
        let pairs = make_pairs(8);
        let tree = MerkleTree::new(h, &pairs);
        let root = tree.root();

        for i in 0..8 {
            let (path, pos) = tree.path(i);
            let leaf = sha256_leaf(&pairs[i].0, &pairs[i].1);
            let comp = verify_membership_native(leaf, &path, &pos);
            assert_eq!(comp, root);
        }
    }

    #[test]
    fn test_ivc_end_to_end() {
        // Build a tree with 8 leaves
        let height = 3;
        let pairs = make_pairs(8);
        let tree = MerkleTree::new(height, &pairs);
        let root = tree.root();

        // Prepare two transactions: tx0 covers 3 actions (0..2), tx1 covers 2 actions (3..4)
        let mut steps = Vec::new();
        let mut tx_bounds = Vec::new();

        // tx 0
        let tx0_start = steps.len();
        for i in 0..3 {
            let (path, pos) = tree.path(i);
            steps.push(StepWitness {
                cv: pairs[i].0,
                rk: pairs[i].1,
                anchor: root,
                path,
                pos,
                tx_index: 0,
                action_index: i as u32,
            });
        }
        tx_bounds.push((0u32, tx0_start, 3));

        // tx 1
        let tx1_start = steps.len();
        for i in 3..5 {
            let (path, pos) = tree.path(i);
            steps.push(StepWitness {
                cv: pairs[i].0,
                rk: pairs[i].1,
                anchor: root,
                path,
                pos,
                tx_index: 1,
                action_index: (i - 3) as u32,
            });
        }
        tx_bounds.push((1u32, tx1_start, 2));

        let agg = build_ivc_aggregate(BuildInput {
            steps,
            tree_height: height,
            aggregate_id: 42,
            tx_boundaries: tx_bounds,
        })
        .unwrap();

        // Verify compressed aggregate
        verify_ivc_aggregate(&agg).unwrap();

        // Sanity: zn[1] == total actions
        assert_eq!(agg.zn_primary[1], PallasFp::from(5u64));

        // Accumulator nontrivial
        assert_ne!(agg.zn_primary[0], PallasFp::ZERO);
    }
}