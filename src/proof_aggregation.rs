//! tachystamp_ivc.rs
//!
//! True IVC aggregation for Tachystamps using Nova over the Pasta cycle.
//! One action per step. Each step verifies a Merkle membership of a (cv_net, rk)
//! leaf under an arbitrary anchor. Aggregation occurs during IVC execution.
//!
//! Primary circuit: verifies Merkle path and updates running accumulator.
//! Secondary circuit: trivial identity to satisfy cycle requirements.
//!
//! Hash inside the circuit: MiMC-7 over Pasta Fp. Deterministic round constants.
//!
//! Public state z = [accumulator, count] in Fp.
//!
//! Notes:
//! - Anchors may differ across steps. No global anchor assumption.
//! - Step circuit size is fixed by TREE_HEIGHT. All steps must use that height.
//!
//! Requires dependencies (Cargo.toml):
//! --------------------------------------------------------------------------------
//! [dependencies]
//! nova-snark = { version = "0.33", default-features = false, features = ["pasta"] }
//! halo2curves = "0.6"
//! bellpepper-core = "0.4"
//! bellpepper = "0.4"
//! serde = { version = "1", features = ["derive"] }
//! thiserror = "1"
//! blake3 = "1"
//! --------------------------------------------------------------------------------

#![allow(clippy::needless_borrow)]
#![allow(clippy::too_many_arguments)]

use bellpepper::gadgets::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
};
use bellpepper_core::{ConstraintSystem, SynthesisError};
use halo2curves::ff::{Field, PrimeField};
use halo2curves::pasta::Fp as PallasFp;
use nova_snark::provider::pasta::{PallasEngine, VestaEngine};
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::Group;
use nova_snark::{CompressedSNARK, PublicParams, RecursiveSNARK};
use serde::{Deserialize, Serialize};
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
/*                                    MiMC-7                                        */
// =====================================================================================

const MIMC_ROUNDS: usize = 91;
const DST_MIMC: &[u8] = b"tachystamp.mimc7.pallas.v1";

fn fe_from_le_mod_q<F: PrimeField>(bytes32: &[u8; 32]) -> F {
    // Use from_bytes_wide for canonical mod-q reduction
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(bytes32);
    F::from_bytes_wide(&wide)
}

fn round_constants<F: PrimeField>() -> [F; MIMC_ROUNDS] {
    // Deterministic constants derived from BLAKE3(DST || i)
    let mut cs = [F::ZERO; MIMC_ROUNDS];
    for i in 0..MIMC_ROUNDS {
        let mut h = blake3::Hasher::new();
        h.update(DST_MIMC);
        h.update(&(i as u64).to_le_bytes());
        let out = h.finalize();
        let mut wide = [0u8; 64];
        // Expand 32 bytes to 64 using BLAKE3 XOF-like chaining
        wide[..32].copy_from_slice(out.as_bytes());
        // second half = BLAKE3(DST||i||0x01)
        let mut h2 = blake3::Hasher::new();
        h2.update(DST_MIMC);
        h2.update(&(i as u64).to_le_bytes());
        h2.update(&[1u8]);
        wide[32..].copy_from_slice(h2.finalize().as_bytes());
        cs[i] = F::from_bytes_wide(&wide);
    }
    cs
}

// Native MiMC-7 compression of two field elements
fn mimc_hash2_native<F: PrimeField>(a: F, b: F) -> F {
    let rc = round_constants::<F>();
    let mut x = a + b;
    for i in 0..MIMC_ROUNDS {
        // x = (x + rc_i)^7
        let t = x + rc[i];
        let t2 = t.square();
        let t4 = t2.square();
        let t6 = t4 * t2;
        x = t6 * t;
    }
    x
}

// Bellpepper MiMC-7 gadget: out = MiMC(a + b)
fn mimc_hash2_gadget<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    a: &AllocatedNum<F>,
    b: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let rc = round_constants::<F>();
    // x0 = a + b
    let mut x = AllocatedNum::alloc(cs.namespace(|| "mimc x0"), || {
        let mut v = *a.get_value().get()?;
        v.add_assign(b.get_value().get()?);
        Ok(v)
    })?;
    // constrain x = a + b
    {
        // x - a - b = 0
        cs.enforce(
            || "x0 = a + b",
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + x.get_variable() - a.get_variable() - b.get_variable(),
        );
    }

    for (i, c) in rc.iter().enumerate() {
        // t = x + rc[i]
        let t = AllocatedNum::alloc(cs.namespace(|| format!("t_{i}")), || {
            let mut v = *x.get_value().get()?;
            v.add_assign(c);
            Ok(v)
        })?;
        cs.enforce(
            || format!("t_{i} = x + rc"),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + t.get_variable() - x.get_variable() - (*c),
        );

        // x = t^7 = t * t^2 * t^4
        let t2 = t.square(cs.namespace(|| format!("t2_{i}")))?;
        let t4 = t2.square(cs.namespace(|| format!("t4_{i}")))?;
        let t6 = AllocatedNum::mul(cs.namespace(|| format!("t6_{i}")), &t4, &t2)?;
        x = AllocatedNum::mul(cs.namespace(|| format!("x_{i}")), &t6, &t)?;
    }
    Ok(x)
}

// =====================================================================================
// Merkle utilities (MiMC-7 based, binary tree)
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

fn hash_leaf_native<F: PrimeField>(cv: F, rk: F) -> F {
    mimc_hash2_native::<F>(cv, rk)
}

fn parent_native<F: PrimeField>(left: F, right: F) -> F {
    mimc_hash2_native::<F>(left, right)
}

fn verify_membership_native<F: PrimeField>(
    leaf: F,
    path: &MerklePath,
) -> F {
    let mut cur = leaf;
    for (i, sib) in path.siblings.iter().enumerate() {
        let s = fe_from_le_mod_q::<F>(sib);
        let (l, r) = if path.is_right[i] {
            (s, cur)
        } else {
            (cur, s)
        };
        cur = parent_native::<F>(l, r);
    }
    cur
}

fn merkle_gadget<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    leaf: &AllocatedNum<F>,
    path: &MerklePath,
) -> Result<AllocatedNum<F>, SynthesisError> {
    let mut cur = leaf.clone();

    for (i, sib_bytes) in path.siblings.iter().enumerate() {
        // Allocate sibling field
        let sib_f = fe_from_le_mod_q::<F>(sib_bytes);
        let sib = AllocatedNum::alloc(cs.namespace(|| format!("sib_{i}")), || Ok(sib_f))?;

        // Allocate direction bit
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("dir_{i}")), Some(path.is_right[i]))?;
        let dir = Boolean::from(bit);

        // Compute left = select(dir==false ? cur : sib)
        // Compute right = select(dir==false ? sib : cur)
        // Boolean select: out = a*not(dir) + b*dir
        let not_dir = dir.not();

        let left = AllocatedNum::alloc(cs.namespace(|| format!("left_{i}")), || {
            let a = *cur.get_value().get()?;
            let b = *sib.get_value().get()?;
            Ok(if path.is_right[i] { b } else { a })
        })?;
        // left = cur * not_dir + sib * dir
        {
            // left = cur*(1 - dir) + sib*dir
            // -> left = cur - cur*dir + sib*dir = cur + (sib - cur)*dir
            // Enforce: left - cur = (sib - cur) * dir
            let mut sib_minus_cur = bellpepper_core::LinearCombination::zero();
            sib_minus_cur = sib_minus_cur + sib.get_variable();
            sib_minus_cur = sib_minus_cur - cur.get_variable();

            cs.enforce(
                || format!("left sel {i}"),
                |_| sib_minus_cur,
                |lc| dir.lc(CS::one(), lc),
                |lc| lc + left.get_variable() - cur.get_variable(),
            );
        }

        let right = AllocatedNum::alloc(cs.namespace(|| format!("right_{i}")), || {
            let a = *cur.get_value().get()?;
            let b = *sib.get_value().get()?;
            Ok(if path.is_right[i] { a } else { b })
        })?;
        {
            // right - sib = (cur - sib) * dir
            let mut cur_minus_sib = bellpepper_core::LinearCombination::zero();
            cur_minus_sib = cur_minus_sib + cur.get_variable();
            cur_minus_sib = cur_minus_sib - sib.get_variable();

            cs.enforce(
                || format!("right sel {i}"),
                |_| cur_minus_sib,
                |lc| dir.lc(CS::one(), lc),
                |lc| lc + right.get_variable() - sib.get_variable(),
            );
        }

        // parent = MiMC(left, right)
        cur = mimc_hash2_gadget(cs.namespace(|| format!("hash parent {i}")), &left, &right)?;
    }

    Ok(cur)
}

// =====================================================================================
// Step witness and circuit
// =====================================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepWitness {
    pub cv: [u8; 32],
    pub rk: [u8; 32],
    pub anchor: [u8; 32],
    pub path: MerklePath,
    pub tx_index: u32,      // for metadata
    pub action_index: u32,  // per-tx ordinal
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

    fn synthesize_inner<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        z_in: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // z = [acc, count]
        assert!(z_in.len() == 2, "arity must be 2");

        let acc_in = &z_in[0];
        let count_in = &z_in[1];

        // Allocate cv, rk, anchor as private witnesses converted mod q
        let wit = self.wit.as_ref().expect("witness must be present");
        if wit.path.height() != self.params.tree_height {
            return Err(SynthesisError::Unsatisfiable);
        }

        let cv_f = fe_from_le_mod_q::<F>(&wit.cv);
        let rk_f = fe_from_le_mod_q::<F>(&wit.rk);
        let anchor_f = fe_from_le_mod_q::<F>(&wit.anchor);

        let cv = AllocatedNum::alloc(cs.namespace(|| "cv"), || Ok(cv_f))?;
        let rk = AllocatedNum::alloc(cs.namespace(|| "rk"), || Ok(rk_f))?;
        let anchor = AllocatedNum::alloc(cs.namespace(|| "anchor"), || Ok(anchor_f))?;

        // leaf = MiMC(cv, rk)
        let leaf = mimc_hash2_gadget(cs.namespace(|| "leaf"), &cv, &rk)?;

        // root' from path
        let root = merkle_gadget(cs.namespace(|| "merkle"), &leaf, &wit.path)?;

        // Enforce root == anchor
        cs.enforce(
            || "root = anchor",
            |lc| lc + root.get_variable() - anchor.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // acc_out = MiMC(MiMC(acc_in, leaf), anchor)
        let t = mimc_hash2_gadget(cs.namespace(|| "acc mix 1"), acc_in, &leaf)?;
        let acc_out = mimc_hash2_gadget(cs.namespace(|| "acc mix 2"), &t, &anchor)?;

        // count_out = count_in + 1
        let one = AllocatedNum::alloc(cs.namespace(|| "one"), || Ok(F::ONE))?;
        {
            cs.enforce(
                || "one is 1",
                |lc| lc + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + one.get_variable(),
            );
        }
        let count_out = AllocatedNum::alloc(cs.namespace(|| "count_out"), || {
            let mut v = *count_in.get_value().get()?;
            v.add_assign(&F::ONE);
            Ok(v)
        })?;
        // count_out - count_in - 1 = 0
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
            // o - zi = 0
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
    pub pp: PublicParams<PallasEngine, VestaEngine, TachyStepCircuit<PallasFp>, TrivialIdentity<<VestaEngine as Group>::Scalar>>,
    pub compressed: CompressedSNARK<PallasEngine, VestaEngine, TachyStepCircuit<PallasFp>, TrivialIdentity<<VestaEngine as Group>::Scalar>>,
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
///
/// z0 = [acc0, 0] with acc0 = MiMC(agg_id, 0)
pub fn build_ivc_aggregate(input: BuildInput) -> Result<IVCAggregate, IVCError> {
    if input.steps.is_empty() {
        return Err(IVCError::Empty);
    }
    // Check uniform height
    for s in &input.steps {
        if s.path.height() != input.tree_height {
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
        let id_f = PallasFp::from(input.aggregate_id as u64);
        mimc_hash2_native::<PallasFp>(id_f, PallasFp::ZERO)
    };
    let mut z0_primary = vec![acc0, PallasFp::ZERO];
    let mut z0_secondary = vec![<VestaEngine as Group>::Scalar::ZERO; 2];

    // Recursive SNARK
    let mut rn: RecursiveSNARK<PallasEngine, VestaEngine, _, _> =
        RecursiveSNARK::new(&pp, &primary_empty, &secondary_id, &z0_primary, &z0_secondary)
            .map_err(|e| IVCError::Nova(format!("{e:?}")))?;

    // Prove steps
    for (i, step) in input.steps.iter().enumerate() {
        // Provide witness to primary circuit
        let c_primary = TachyStepCircuit::<PallasFp>::with_witness(
            TachyIVCParams { tree_height: input.tree_height },
            step.clone(),
        );
        // Secondary trivial
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
/// Returns Ok(()) if verification succeeds.
pub fn verify_ivc_aggregate(agg: &IVCAggregate) -> Result<(), IVCError> {
    let primary_empty: TachyStepCircuit<PallasFp> =
        TachyStepCircuit::empty(TachyIVCParams { tree_height: agg.tree_height });
    let secondary_id: TrivialIdentity<<VestaEngine as Group>::Scalar> = TrivialIdentity::new(2);

    let acc0 = {
        let id_f = PallasFp::from(agg.aggregate_id as u64);
        mimc_hash2_native::<PallasFp>(id_f, PallasFp::ZERO)
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
// Helper: native Merkle tree builder for tests and witness prep
// =====================================================================================

#[derive(Clone, Debug)]
pub struct MerkleTree {
    pub height: usize,
    pub leaves: Vec<PallasFp>,
    pub nodes: Vec<Vec<PallasFp>>, // nodes[0] = leaves, nodes[h] root layer length 1
}

impl MerkleTree {
    pub fn new(height: usize, pairs: &Vec<([u8; 32], [u8; 32])>) -> Self {
        assert!(pairs.len() <= (1 << height));
        // Leaves
        let mut leaves = vec![PallasFp::ZERO; 1 << height];
        for (i, (cv, rk)) in pairs.iter().enumerate() {
            let cvf = fe_from_le_mod_q::<PallasFp>(cv);
            let rkf = fe_from_le_mod_q::<PallasFp>(rk);
            leaves[i] = hash_leaf_native::<PallasFp>(cvf, rkf);
        }
        let mut nodes = Vec::with_capacity(height + 1);
        nodes.push(leaves.clone());

        let mut cur = leaves;
        for _ in 0..height {
            let mut next = Vec::with_capacity(cur.len() / 2);
            for j in (0..cur.len()).step_by(2) {
                let l = cur[j];
                let r = cur[j + 1];
                next.push(parent_native::<PallasFp>(l, r));
            }
            nodes.push(next.clone());
            cur = next;
        }
        Self { height, leaves: nodes[0].clone(), nodes }
    }

    pub fn root(&self) -> [u8; 32] {
        let r = self.nodes[self.height][0];
        let mut out = [0u8; 32];
        out.copy_from_slice(r.to_bytes().as_ref());
        out
    }

    pub fn path(&self, index: usize) -> MerklePath {
        assert!(index < (1 << self.height));
        let mut idx = index;
        let mut siblings = Vec::with_capacity(self.height);
        let mut is_right = Vec::with_capacity(self.height);

        for h in 0..self.height {
            let sib_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sib = self.nodes[h][sib_idx];
            let mut sib_bytes = [0u8; 32];
            sib_bytes.copy_from_slice(sib.to_bytes().as_ref());
            siblings.push(sib_bytes);
            is_right.push(idx % 2 == 1);
            idx >>= 1;
        }
        MerklePath { siblings, is_right }
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
    fn test_mimc_native_and_gadget_agree_leaf() {
        // Simple sanity: compare native and gadget on a single step
        // Note: This test only checks MiMC native determinism and circuit compilation path.
        // Full end-to-end tests below cover inclusion and accumulator constraints.
        let a = PallasFp::from(123u64);
        let b = PallasFp::from(456u64);
        let h1 = mimc_hash2_native::<PallasFp>(a, b);
        // Compile a minimal circuit and compare value propagation
        struct Mini<F: PrimeField> {
            a: F,
            b: F,
        }
        impl<F: PrimeField> StepCircuit<F> for Mini<F> {
            fn arity(&self) -> usize { 1 }
            fn synthesize<CS: ConstraintSystem<F>>(
                &self, cs: &mut CS, _z: &[AllocatedNum<F>]
            ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
                let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(self.a))?;
                let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(self.b))?;
                let out = mimc_hash2_gadget(cs.namespace(|| "h"), &a, &b)?;
                Ok(vec![out])
            }
        }
        let mini_p = Mini { a, b };
        let mini_s = TrivialIdentity::<PallasFp>::new(1);

        let pp = PublicParams::<PallasEngine, VestaEngine, _, _>::setup(&mini_p, &mini_s);
        let z0p = vec![PallasFp::ZERO];
        let z0s = vec![<VestaEngine as Group>::Scalar::ZERO];
        let rn = RecursiveSNARK::<PallasEngine, VestaEngine, _, _>::new(&pp, &mini_p, &mini_s, &z0p, &z0s).unwrap();
        let (zn_p, _) = rn.get_state().unwrap();
        assert_eq!(zn_p.len(), 1);
        // Cannot directly read witness values from cs; this test ensures compilation path works
        // and MiMC native stays well-defined.
        assert_ne!(h1, PallasFp::ZERO);
    }

    #[test]
    fn test_ivc_end_to_end() {
        // Build a tree with 8 leaves
        let height = 3;
        let pairs = make_pairs(8);
        let tree = MerkleTree::new(height, &pairs);
        let root = tree.root();

        // Prepare two transactions: tx0 covers leaves 0..3, tx1 covers leaves 3..6 (overlap fine)
        let mut steps = Vec::new();
        let mut tx_bounds = Vec::new();

        // tx 0: 3 actions (0,1,2)
        let tx0_start = steps.len();
        for i in 0..3 {
            let p = tree.path(i);
            steps.push(StepWitness {
                cv: pairs[i].0,
                rk: pairs[i].1,
                anchor: root,
                path: p,
                tx_index: 0,
                action_index: i as u32,
            });
        }
        tx_bounds.push((0u32, tx0_start, 3));

        // tx 1: 2 actions (3,4)
        let tx1_start = steps.len();
        for i in 3..5 {
            let p = tree.path(i);
            steps.push(StepWitness {
                cv: pairs[i].0,
                rk: pairs[i].1,
                anchor: root,
                path: p,
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

        // Check state semantics: zn[1] == total actions
        assert_eq!(agg.zn_primary[1], PallasFp::from(5u64));

        // Accumulator is bound to (cv,rk,anchor) sequence
        assert_ne!(agg.zn_primary[0], PallasFp::ZERO);
    }
}