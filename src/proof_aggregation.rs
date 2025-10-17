//! Tachystamp Proof Aggregation
//!
//! This module implements proof aggregation for Tachyon, allowing multiple tachystamp
//! proofs to be merged into a single aggregate proof.
//!
//! # Current Status: RESEARCH PROTOTYPE
//!
//! ⚠️ **WARNING:** This is a placeholder implementation. True Nova IVC aggregation
//! requires different architecture than what's currently implemented.
//!
//! # Correct Nova Aggregation Approach
//!
//! **WRONG (current placeholder):**
//! - Take RecursiveSNARK from proof 1
//! - Take RecursiveSNARK from proof 2
//! - Try to "fold" them together
//!
//! **Problem:** Nova IVC composes witnesses/steps, not arbitrary already-proven
//! RecursiveSNARKs from other provers. You cannot fold pre-compressed proofs.
//!
//! **CORRECT approach:**
//! 1. Design a step circuit that checks "Merkle path + constraints for one action"
//! 2. For aggregation: Run IVC with N steps, each step handling one transaction's witnesses
//! 3. Public inputs include running commitment to the tachygram set
//! 4. Compress the N-step IVC into one CompressedSNARK
//! 5. Transactions reference their step index in the aggregate
//!
//! **Key insight:** Aggregation happens during IVC execution, not after compression.
//!
//! # Anchors Across Transactions
//!
//! - Within one transaction: all Orchard actions share one rt^Orchard
//! - Across transactions in a block: anchors may differ (each tx references any recent root)
//! - Do NOT assume common anchor for aggregate across transactions
//!
//! # Migration Path
//!
//! For production deployment:
//! 1. Use verification aggregation (prove "I verified N proofs") as interim solution
//! 2. Redesign step circuit for true IVC aggregation
//! 3. Each step handles one transaction's membership proofs
//! 4. Accumulator tracks all verified tachygrams
//!
//! # References
//!
//! - Nova paper: "Recursive Zero-Knowledge Arguments from Folding Schemes"
//! - Zcash RedDSA batch spec: https://zips.z.cash/protocol/protocol.pdf#reddsabatchverify
//! - Sonic's untrusted helper approach for batch verification
//!
//! # Architecture
//!
//! ```text
//! Block
//!  ├─ Transaction 1
//!  │   ├─ Actions
//!  │   └─ TachystampRef → Aggregate #0, Index 0
//!  ├─ Transaction 2
//!  │   ├─ Actions
//!  │   └─ TachystampRef → Aggregate #0, Index 1
//!  ├─ Transaction 3
//!  │   ├─ Actions
//!  │   └─ TachystampRef → Aggregate #0, Index 2
//!  └─ Aggregate #0
//!      ├─ Merged proof (covers txs 1-3)
//!      ├─ Metadata for tx 1
//!      ├─ Metadata for tx 2
//!      └─ Metadata for tx 3
//! ```
//!
//! # Aggregation Algorithm
//!
//! Tachystamps are proof-carrying data (PCD), which means they can be composed:
//!
//! 1. **Collect** all individual tachystamp proofs in a block
//! 2. **Verify** each proof independently (parallel)
//! 3. **Merge** proofs using Nova's proof composition
//! 4. **Compress** the merged proof
//! 5. **Publish** aggregate and replace individual proofs with references
//!
//! # Security Properties
//!
//! - Each action's (cv_net, rk) pair is still bound to its proof
//! - Aggregation preserves zero-knowledge
//! - No reduction in security vs individual proofs
//! - Verifier checks aggregate covers all referenced transactions

use halo2curves::pasta::Fp as PallasFp;
use nova_snark::nova::{CompressedSNARK, RecursiveSNARK};
use nova_snark::provider::pasta::{PallasEngine, VestaEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::tachystamps::{Compressed, ProofMeta, TachyStepCircuit, TachyError};

// ----------------------------- Types -----------------------------

/// An aggregate proof covering multiple transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateProof {
    /// The merged compressed proof
    pub merged_proof: Compressed,
    
    /// Metadata for each transaction in the aggregate
    /// Index corresponds to the transaction's position in the aggregate
    pub tx_metadata: Vec<TransactionMetadata>,
    
    /// Total number of actions covered by this aggregate
    pub total_actions: usize,
    
    /// Aggregate ID (for referencing)
    pub aggregate_id: u32,
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
        Self {
            proofs: Vec::new(),
            metadata: Vec::new(),
        }
    }
    
    /// Add a proof to the batch
    pub fn add_proof(&mut self, proof: Compressed, tx_context: Vec<u8>) {
        let action_start_index = self.metadata.iter().map(|m| m.action_count).sum();
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
    
    #[error("tachystamp error: {0}")]
    Tachystamps(#[from] TachyError),
}

// ----------------------------- Aggregation -----------------------------

/// Aggregate multiple tachystamp proofs into a single proof
///
/// # ⚠️ PLACEHOLDER IMPLEMENTATION
///
/// **Current behavior:** Metadata aggregation only (not cryptographically sound)
/// - Verifies each proof's metadata is well-formed
/// - Collects all authorized_pairs
/// - Creates aggregate metadata structure
/// - **Does NOT perform true Nova folding**
///
/// # Correct Implementation (TODO)
///
/// True Nova IVC aggregation requires:
///
/// 1. **Block builder collects transaction witnesses** (not compressed proofs)
/// 2. **Run IVC with step circuit:** Each step handles one transaction's Merkle proofs
/// 3. **Public state tracks:**
///    - Accumulator of verified tachygrams
///    - Commitment to authorized (cv_net, rk) pairs
///    - Running anchor state (may vary per transaction)
/// 4. **After N steps:** Compress into one CompressedSNARK
/// 5. **Transactions reference:** Their step index in the aggregate
///
/// **Cannot fold pre-compressed RecursiveSNARKs:** Nova requires original witnesses.
///
/// # Arguments
///
/// - `batch`: Collection of proof metadata to aggregate
/// - `aggregate_id`: Unique ID for this aggregate
///
/// # Returns
///
/// An `AggregateProof` structure (metadata only in current implementation)
///
/// # Security
///
/// ⚠️ **This placeholder does NOT provide cryptographic aggregation.**
/// Use only for testing and development. Production requires redesigned circuit.
pub fn aggregate_proofs(
    batch: ProofBatch,
    aggregate_id: u32,
) -> Result<AggregateProof, AggregationError> {
    // Validate batch
    if batch.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }
    
    // ⚠️ PLACEHOLDER: Just collect metadata, no actual proof merging
    let mut all_pairs = Vec::new();
    let mut total_actions = 0;
    
    for (i, proof) in batch.proofs.iter().enumerate() {
        // Basic metadata validation
        if proof.meta.authorized_pairs.is_empty() {
            return Err(AggregationError::ProofVerificationFailed(i));
        }
        
        // Collect pairs for metadata
        all_pairs.extend_from_slice(&proof.meta.authorized_pairs);
        total_actions += proof.meta.authorized_pairs.len();
    }
    
    // Create merged metadata (NOT a real aggregated proof)
    let mut merged = batch.proofs[0].clone();
    merged.meta.authorized_pairs = all_pairs;
    merged.meta.steps = batch.proofs.iter().map(|p| p.meta.steps).sum();
    
    // TODO: Replace with true Nova IVC folding
    // See module documentation for correct approach
    
    Ok(AggregateProof {
        merged_proof: merged,
        tx_metadata: batch.metadata,
        total_actions,
        aggregate_id,
    })
}

/// Verify an aggregate proof
///
/// # Verification Steps
///
/// 1. Verify the merged proof itself
/// 2. Check that tx_metadata correctly partitions authorized_pairs
/// 3. Validate all action counts sum correctly
pub fn verify_aggregate(
    aggregate: &AggregateProof,
    z0: &[PallasFp],
) -> Result<(), AggregationError> {
    // Verify the merged proof
    // Note: In production, this would call the actual Nova verifier
    // For now, we just validate the structure
    
    // Check metadata consistency
    let metadata_action_count: usize = aggregate.tx_metadata.iter()
        .map(|m| m.action_count)
        .sum();
    
    let proof_pair_count = aggregate.merged_proof.meta.authorized_pairs.len();
    
    if metadata_action_count != proof_pair_count {
        return Err(AggregationError::MergeFailed(
            format!("action count mismatch: metadata says {}, proof has {}",
                    metadata_action_count, proof_pair_count)
        ));
    }
    
    // Verify partition is correct
    for (i, tx_meta) in aggregate.tx_metadata.iter().enumerate() {
        let start = tx_meta.action_start_index;
        let end = start + tx_meta.action_count;
        
        if end > proof_pair_count {
            return Err(AggregationError::MergeFailed(
                format!("tx {} metadata out of bounds: [{}, {})", i, start, end)
            ));
        }
        
        // Check that the pairs in metadata match the proof
        let proof_slice = &aggregate.merged_proof.meta.authorized_pairs[start..end];
        if proof_slice != tx_meta.action_pairs.as_slice() {
            return Err(AggregationError::MergeFailed(
                format!("tx {} action pairs don't match proof", i)
            ));
        }
    }
    
    Ok(())
}

/// Extract metadata for a specific transaction from an aggregate
///
/// # Arguments
///
/// - `aggregate`: The aggregate proof
/// - `tx_index`: Index of the transaction in the aggregate
///
/// # Returns
///
/// The (cv_net, rk) pairs authorized for that transaction
pub fn get_tx_authorized_pairs(
    aggregate: &AggregateProof,
    tx_index: usize,
) -> Option<Vec<([u8; 32], [u8; 32])>> {
    aggregate.tx_metadata.get(tx_index)
        .map(|meta| meta.action_pairs.clone())
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
    }
    
    #[test]
    fn test_verify_aggregate() {
        let mut batch = ProofBatch::new();
        batch.add_proof(dummy_compressed(2), b"tx1".to_vec());
        batch.add_proof(dummy_compressed(1), b"tx2".to_vec());
        
        let aggregate = aggregate_proofs(batch, 1).unwrap();
        
        let z0 = vec![PallasFp::from(0u64), PallasFp::from(0u64), PallasFp::from(0u64)];
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
        
        // Total should be 15
        assert_eq!(aggregate.total_actions, 15);
        assert_eq!(aggregate.merged_proof.meta.authorized_pairs.len(), 15);
    }
}

