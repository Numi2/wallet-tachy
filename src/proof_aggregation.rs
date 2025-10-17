//! Tachystamp Proof Aggregation

use halo2curves::{ff::PrimeField, pasta::Fp as PallasFp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tachystamps::{Compressed, ProofMeta, TachyError};

// ----------------------------- Types -----------------------------

/// An aggregate proof covering multiple transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateProof {
    /// The merged compressed proof.
    ///
    /// Conventions:
    /// - `merged_proof.proof` holds `agg_digest` bytes
    /// - `merged_proof.vk` is empty (no separate VK for the aggregate artifact)
    /// - `merged_proof.meta.authorized_pairs` is the concatenation of all pairs
    /// - `merged_proof.meta.steps` is the sum of per-proof steps
    pub merged_proof: Compressed,

    /// Metadata for each transaction in the aggregate.
    /// Index corresponds to the transaction's position in the aggregate.
    pub tx_metadata: Vec<TransactionMetadata>,

    /// Total number of actions covered by this aggregate
    pub total_actions: usize,

    /// Aggregate ID (for referencing)
    pub aggregate_id: u32,

    /// Merkle root over all (cv_net, rk) pairs in `merged_proof.meta.authorized_pairs`
    #[serde(default)]
    pub pairs_root: [u8; 32],

    /// Deterministic aggregate digest binding:
    /// `aggregate_id || pairs_root || proof_digests.len() || proof_digests[*]`
    #[serde(default)]
    pub agg_digest: [u8; 32],

    /// Per-proof digests in order. Used to recompute `agg_digest` and to bind
    /// the aggregate to the exact set and order of proofs.
    #[serde(default)]
    pub proof_digests: Vec<[u8; 32]>,
}

/// Metadata for a single transaction within an aggregate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionMetadata {
    /// (cv_net, rk) pairs for this transaction's actions
    pub action_pairs: Vec<([u8; 32], [u8; 32])>,

    /// Index of first action in the merged proof
    pub action_start_index: usize,

    /// Number of actions in this transaction
    pub action_count: usize,

    /// Transaction-specific context (optional, for debugging)
    pub tx_context: Vec<u8>,
}

/// A collection of proofs ready for aggregation
#[derive(Clone, Debug)]
pub struct ProofBatch {
    /// Individual proofs to aggregate
    pub proofs: Vec<Compressed>,

    /// Mapping from proof index to transaction metadata
    pub metadata: Vec<TransactionMetadata>,
}

impl ProofBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self { proofs: Vec::new(), metadata: Vec::new() }
    }

    /// Add a proof to the batch
    pub fn add_proof(&mut self, proof: Compressed, tx_context: Vec<u8>) {
        let action_start_index: usize = self.metadata.iter().map(|m| m.action_count).sum();
        let action_pairs = proof.meta.authorized_pairs.clone();
        let action_count = action_pairs.len();

        self.metadata.push(TransactionMetadata {
            action_pairs,
            action_start_index,
            action_count,
            tx_context,
        });

        self.proofs.push(proof);
    }

    /// Get total number of proofs in batch
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum AggregationError {
    #[error("empty proof batch")]
    EmptyBatch,

    #[error("proof verification failed at index {0}")]
    ProofVerificationFailed(usize),

    #[error("incompatible proof parameters")]
    IncompatibleProofs,

    #[error("merging failed: {0}")]
    MergeFailed(String),

    #[error("pairs root mismatch")]
    PairsRootMismatch,

    #[error("aggregate digest mismatch")]
    AggDigestMismatch,

    #[error("proof digest mismatch at index {0}")]
    ProofDigestMismatch(usize),

    #[error("tachystamp error: {0}")]
    Tachystamps(#[from] TachyError),
}

// ----------------------------- Proof verification hook -----------------------------

/// Pluggable verifier for individual compressed proofs.
///
/// Implement this with your production verifier. The default `NoopVerifier`
/// only does structural checks and is suitable for non-consensus testing.
pub trait ProofVerifier {
    /// Verifies an individual compressed proof.
    fn verify(&self, proof: &Compressed) -> Result<(), TachyError>;
}

/// Non-consensus, structural-only verifier.
///
/// This does **not** perform cryptographic verification. Use only in tests or
/// non-critical contexts. For production, provide a real verifier.
pub struct NoopVerifier;

impl ProofVerifier for NoopVerifier {
    fn verify(&self, proof: &Compressed) -> Result<(), TachyError> {
        if proof.proof.is_empty() || proof.meta.authorized_pairs.is_empty() {
            return Err(TachyError::InvalidProof("empty proof or pairs".into()));
        }
        Ok(())
    }
}

// ----------------------------- Aggregation -----------------------------

/// Aggregate and verify multiple tachystamp proofs using the provided verifier.
///
/// This is the production entrypoint. It **verifies each input proof**, then
/// builds a canonical aggregate with Merkle and digest commitments.
///
/// - `batch`: Collection of proofs + per-tx metadata
/// - `aggregate_id`: Domain separation for the aggregate
/// - `verifier`: Pluggable proof verifier
pub fn aggregate_proofs_with_verifier(
    batch: ProofBatch,
    aggregate_id: u32,
    verifier: &impl ProofVerifier,
) -> Result<AggregateProof, AggregationError> {
    if batch.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }

    // Verify all proofs
    for (i, proof) in batch.proofs.iter().enumerate() {
        verifier
            .verify(proof)
            .map_err(|_| AggregationError::ProofVerificationFailed(i))?;
    }

    // Collect and commit all pairs
    let mut all_pairs = Vec::new();
    let mut total_actions = 0usize;
    for proof in &batch.proofs {
        if proof.meta.authorized_pairs.is_empty() {
            return Err(AggregationError::ProofVerificationFailed(total_actions)); // index approximation
        }
        total_actions += proof.meta.authorized_pairs.len();
        all_pairs.extend_from_slice(&proof.meta.authorized_pairs);
    }

    // Build commitments
    let pairs_root = merkle_root_from_pairs(&all_pairs);
    let proof_digests: Vec<[u8; 32]> = batch.proofs.iter().map(digest_proof).collect();
    let agg_digest = digest_aggregate_fields(aggregate_id, pairs_root, &proof_digests);

    // Compose merged proof metadata
    let steps_sum: usize = batch.proofs.iter().map(|p| p.meta.steps).sum();
    let acc_init: PallasFp = batch
        .proofs
        .first()
        .map(|p| p.meta.acc_init)
        .unwrap_or_else(|| PallasFp::from(0u64));
    let acc_final: PallasFp = batch
        .proofs
        .last()
        .map(|p| p.meta.acc_final)
        .unwrap_or_else(|| PallasFp::from(0u64));

    let merged = Compressed {
        // Store the aggregate digest as the "proof" bytes for binding
        proof: agg_digest.to_vec(),
        // No aggregate VK for the metadata artifact
        vk: Vec::new(),
        meta: ProofMeta {
            steps: steps_sum,
            acc_init,
            acc_final,
            // You can set a context policy here if desired. We leave zero.
            ctx: PallasFp::from(0u64),
            authorized_pairs: all_pairs.clone(),
        },
    };

    Ok(AggregateProof {
        merged_proof: merged,
        tx_metadata: batch.metadata,
        total_actions,
        aggregate_id,
        pairs_root,
        agg_digest,
        proof_digests,
    })
}

/// Backwards-compatible wrapper that aggregates without cryptographic verification.
///
/// Prefer `aggregate_proofs_with_verifier`. This exists for legacy callers.
/// It performs structural checks only.
#[deprecated(note = "use aggregate_proofs_with_verifier with a real ProofVerifier")]
pub fn aggregate_proofs(batch: ProofBatch, aggregate_id: u32) -> Result<AggregateProof, AggregationError> {
    aggregate_proofs_with_verifier(batch, aggregate_id, &NoopVerifier)
}

/// Verify an aggregate proof (structural and commitment checks).
///
/// This does **not** re-verify the underlying proofs. It validates:
/// 1. Metadata partitions match the concatenated pairs
/// 2. `pairs_root` matches the Merkle root over concatenated pairs
/// 3. `agg_digest` matches `aggregate_id`, `pairs_root`, and `proof_digests`
///
/// Use `verify_aggregate_full` to re-verify each original proof and bind them
/// to the aggregate via their digests.
pub fn verify_aggregate(aggregate: &AggregateProof, _z0: &[PallasFp]) -> Result<(), AggregationError> {
    // Partition checks
    let metadata_action_count: usize = aggregate.tx_metadata.iter().map(|m| m.action_count).sum();
    let proof_pair_count = aggregate.merged_proof.meta.authorized_pairs.len();

    if metadata_action_count != proof_pair_count {
        return Err(AggregationError::MergeFailed(format!(
            "action count mismatch: metadata says {}, proof has {}",
            metadata_action_count, proof_pair_count
        )));
    }

    for (i, tx_meta) in aggregate.tx_metadata.iter().enumerate() {
        let start = tx_meta.action_start_index;
        let end = start + tx_meta.action_count;

        if end > proof_pair_count {
            return Err(AggregationError::MergeFailed(format!(
                "tx {} metadata out of bounds: [{}, {})", i, start, end
            )));
        }

        let proof_slice = &aggregate.merged_proof.meta.authorized_pairs[start..end];
        if proof_slice != tx_meta.action_pairs.as_slice() {
            return Err(AggregationError::MergeFailed(format!(
                "tx {} action pairs don't match proof", i
            )));
        }
    }

    // Commitment checks
    let recomputed_root =
        merkle_root_from_pairs(&aggregate.merged_proof.meta.authorized_pairs);
    if recomputed_root != aggregate.pairs_root {
        return Err(AggregationError::PairsRootMismatch);
    }

    let recomputed_agg =
        digest_aggregate_fields(aggregate.aggregate_id, aggregate.pairs_root, &aggregate.proof_digests);
    if recomputed_agg != aggregate.agg_digest {
        return Err(AggregationError::AggDigestMismatch);
    }

    // Also bind the merged_proof.proof bytes to agg_digest
    if aggregate.merged_proof.proof.as_slice() != aggregate.agg_digest {
        return Err(AggregationError::MergeFailed(
            "merged_proof.proof does not match agg_digest".into(),
        ));
    }

    Ok(())
}

/// Fully verify an aggregate against the original proofs.
///
/// Steps:
/// 1. Run `verify_aggregate` for structure + commitments
/// 2. Recompute each original proof digest and compare to `proof_digests`
/// 3. Re-verify each original proof via the supplied `verifier`
///
/// Returns `Ok(())` if and only if all checks pass.
pub fn verify_aggregate_full(
    aggregate: &AggregateProof,
    originals: &[Compressed],
    verifier: &impl ProofVerifier,
) -> Result<(), AggregationError> {
    verify_aggregate(aggregate, &[])?;

    if originals.len() != aggregate.proof_digests.len() {
        return Err(AggregationError::MergeFailed(format!(
            "original proof count {} != digest count {}",
            originals.len(),
            aggregate.proof_digests.len()
        )));
    }

    for (i, proof) in originals.iter().enumerate() {
        let d = digest_proof(proof);
        if d != aggregate.proof_digests[i] {
            return Err(AggregationError::ProofDigestMismatch(i));
        }
        verifier
            .verify(proof)
            .map_err(|_| AggregationError::ProofVerificationFailed(i))?;
    }

    let recomputed_agg =
        digest_aggregate_fields(aggregate.aggregate_id, aggregate.pairs_root, &aggregate.proof_digests);
    if recomputed_agg != aggregate.agg_digest {
        return Err(AggregationError::AggDigestMismatch);
    }

    Ok(())
}

/// Extract metadata for a specific transaction from an aggregate
///
/// # Arguments
/// - `aggregate`: The aggregate proof
/// - `tx_index`: Index of the transaction in the aggregate
///
/// # Returns
/// The (cv_net, rk) pairs authorized for that transaction
pub fn get_tx_authorized_pairs(
    aggregate: &AggregateProof,
    tx_index: usize,
) -> Option<Vec<([u8; 32], [u8; 32])>> {
    aggregate.tx_metadata.get(tx_index).map(|meta| meta.action_pairs.clone())
}

// ----------------------------- Internals: hashing & Merkle -----------------------------

const DST_LEAF: &[u8] = b"tachystamp.pair.v1";
const DST_NODE: &[u8] = b"tachystamp.node.v1";
const DST_META: &[u8] = b"tachystamp.meta.v1";
const DST_PROOF: &[u8] = b"tachystamp.proof.v1";
const DST_AGG: &[u8] = b"tachystamp.aggregate.v1";

fn hash_leaf(cv: &[u8; 32], rk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_LEAF);
    h.update(cv);
    h.update(rk);
    *h.finalize().as_bytes()
}

fn hash_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_NODE);
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

fn empty_root() -> [u8; 32] {
    // Domain-separated constant: hash of an empty leaf pair
    hash_node(&[0u8; 32], &[0u8; 32])
}

fn leaves_from_pairs(pairs: &Vec<([u8; 32], [u8; 32])>) -> Vec<[u8; 32]> {
    pairs.iter().map(|(cv, rk)| hash_leaf(cv, rk)).collect()
}

fn merkle_root_from_pairs(pairs: &Vec<([u8; 32], [u8; 32])>) -> [u8; 32] {
    let leaves = leaves_from_pairs(pairs);
    merkle_root_from_leaves(&leaves)
}

fn merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        if layer.len() & 1 == 1 {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            next.push(hash_node(&chunk[0], &chunk[1]));
        }
        layer = next;
    }
    layer[0]
}

fn digest_meta(meta: &ProofMeta) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_META);

    let steps = (meta.steps as u64).to_le_bytes();
    h.update(&steps);

    let acc_init = meta.acc_init.to_repr();
    let acc_final = meta.acc_final.to_repr();
    let ctx = meta.ctx.to_repr();

    h.update(acc_init.as_ref());
    h.update(acc_final.as_ref());
    h.update(ctx.as_ref());

    let root = merkle_root_from_pairs(&meta.authorized_pairs);
    h.update(&root);

    *h.finalize().as_bytes()
}

fn digest_proof(proof: &Compressed) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_PROOF);

    let plen = (proof.proof.len() as u64).to_le_bytes();
    h.update(&plen);
    h.update(&proof.proof);

    let vklen = (proof.vk.len() as u64).to_le_bytes();
    h.update(&vklen);
    h.update(&proof.vk);

    let md = digest_meta(&proof.meta);
    h.update(&md);

    *h.finalize().as_bytes()
}

fn digest_aggregate_fields(
    aggregate_id: u32,
    pairs_root: [u8; 32],
    proof_digests: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DST_AGG);

    h.update(&aggregate_id.to_le_bytes());
    h.update(&pairs_root);

    let n = (proof_digests.len() as u64).to_le_bytes();
    h.update(&n);

    for d in proof_digests {
        h.update(d);
    }

    *h.finalize().as_bytes()
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_compressed(num_pairs: usize) -> Compressed {
        let pairs: Vec<([u8; 32], [u8; 32])> = (0..num_pairs)
            .map(|i| {
                let mut cv = [0u8; 32];
                cv[0] = i as u8;
                let mut rk = [0u8; 32];
                rk[0] = (i + 100) as u8;
                (cv, rk)
            })
            .collect();

        Compressed {
            proof: vec![1, 2, 3],
            vk: vec![4, 5, 6],
            meta: ProofMeta {
                steps: 1,
                acc_init: PallasFp::from(0u64),
                acc_final: PallasFp::from(1u64),
                ctx: PallasFp::from(2u64),
                authorized_pairs: pairs,
            },
        }
    }

    #[test]
    fn test_proof_batch() {
        let mut batch = ProofBatch::new();
        assert!(batch.is_empty());

        batch.add_proof(dummy_compressed(2), b"tx1".to_vec());
        batch.add_proof(dummy_compressed(3), b"tx2".to_vec());

        assert_eq!(batch.len(), 2);
        assert_eq!(batch.metadata[0].action_count, 2);
        assert_eq!(batch.metadata[1].action_count, 3);
        assert_eq!(batch.metadata[0].action_start_index, 0);
        assert_eq!(batch.metadata[1].action_start_index, 2);
    }

    #[test]
    fn test_aggregate_proofs() {
        let mut batch = ProofBatch::new();
        batch.add_proof(dummy_compressed(2), b"tx1".to_vec());
        batch.add_proof(dummy_compressed(3), b"tx2".to_vec());
        batch.add_proof(dummy_compressed(1), b"tx3".to_vec());

        let aggregate = aggregate_proofs(batch, 42).unwrap();

        assert_eq!(aggregate.aggregate_id, 42);
        assert_eq!(aggregate.total_actions, 6); // 2 + 3 + 1
        assert_eq!(aggregate.tx_metadata.len(), 3);
        assert_eq!(aggregate.merged_proof.meta.authorized_pairs.len(), 6);
        // Commitments are populated
        assert_ne!(aggregate.pairs_root, [0u8; 32]);
        assert_ne!(aggregate.agg_digest, [0u8; 32]);
        assert_eq!(aggregate.merged_proof.proof.as_slice(), aggregate.agg_digest);
    }

    #[test]
    fn test_verify_aggregate() {
        let mut batch = ProofBatch::new();
        batch.add_proof(dummy_compressed(2), b"tx1".to_vec());
        batch.add_proof(dummy_compressed(1), b"tx2".to_vec());

        let aggregate = aggregate_proofs(batch, 1).unwrap();

        let z0 = vec![
            PallasFp::from(0u64),
            PallasFp::from(0u64),
            PallasFp::from(0u64),
        ];
        assert!(verify_aggregate(&aggregate, &z0).is_ok());
    }

    #[test]
    fn test_get_tx_authorized_pairs() {
        let mut batch = ProofBatch::new();
        batch.add_proof(dummy_compressed(2), b"tx1".to_vec());
        batch.add_proof(dummy_compressed(3), b"tx2".to_vec());

        let aggregate = aggregate_proofs(batch, 1).unwrap();

        let tx0_pairs = get_tx_authorized_pairs(&aggregate, 0).unwrap();
        assert_eq!(tx0_pairs.len(), 2);

        let tx1_pairs = get_tx_authorized_pairs(&aggregate, 1).unwrap();
        assert_eq!(tx1_pairs.len(), 3);

        // Out of bounds should return None
        assert!(get_tx_authorized_pairs(&aggregate, 2).is_none());
    }

    #[test]
    fn test_empty_batch_fails() {
        let batch = ProofBatch::new();
        assert!(aggregate_proofs(batch, 0).is_err());
    }

    #[test]
    fn test_metadata_partitioning() {
        let mut batch = ProofBatch::new();
        batch.add_proof(dummy_compressed(5), b"tx1".to_vec());
        batch.add_proof(dummy_compressed(7), b"tx2".to_vec());
        batch.add_proof(dummy_compressed(3), b"tx3".to_vec());

        let aggregate = aggregate_proofs(batch, 1).unwrap();

        // Check partitioning
        assert_eq!(aggregate.tx_metadata[0].action_start_index, 0);
        assert_eq!(aggregate.tx_metadata[0].action_count, 5);

        assert_eq!(aggregate.tx_metadata[1].action_start_index, 5);
        assert_eq!(aggregate.tx_metadata[1].action_count, 7);

        assert_eq!(aggregate.tx_metadata[2].action_start_index, 12);
        assert_eq!(aggregate.tx_metadata[2].action_count, 3);

        // Totals and commitments
        assert_eq!(aggregate.total_actions, 15);
        assert_eq!(aggregate.merged_proof.meta.authorized_pairs.len(), 15);
        assert_ne!(aggregate.pairs_root, [0u8; 32]);
    }

    #[test]
    fn test_verify_aggregate_full_binds_originals() {
        let p1 = dummy_compressed(2);
        let p2 = dummy_compressed(1);
        let mut batch = ProofBatch::new();
        batch.add_proof(p1.clone(), b"tx1".to_vec());
        batch.add_proof(p2.clone(), b"tx2".to_vec());

        let aggregate = aggregate_proofs_with_verifier(batch, 77, &NoopVerifier).unwrap();

        // Full verify against originals
        assert!(verify_aggregate_full(&aggregate, &[p1, p2], &NoopVerifier).is_ok());
    }
}