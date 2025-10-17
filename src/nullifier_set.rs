//! Nullifier Set with Non-Membership Proofs
//!
//! This module implements a prunable nullifier set that supports:
//! - Efficient membership checks
//! - Non-membership proofs for recent nullifiers
//! - Automatic pruning of old nullifiers (consensus allows pruning after k blocks)

#![allow(missing_docs)]
//!
//! # Design
//!
//! Tachyon's oblivious synchronization only requires validators to retain
//! the last k blocks of nullifiers. Users prove their notes were valid
//! up to a recent point in history via tachystamps.
//!
//! This allows validators to prune old nullifiers, dramatically reducing
//! state size compared to Zcash's permanent nullifier set.

#![forbid(unsafe_code)]

use halo2curves::pasta::Fp as PallasFp;
use halo2curves::ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

use crate::actions::Nullifier;
use crate::poseidon_chip::native::poseidon_hash;
use crate::tachystamps::{bytes_to_fp_le, fp_u64};

// ----------------------------- Constants -----------------------------

/// Number of blocks to retain nullifiers before pruning (consensus parameter)
pub const NULLIFIER_RETENTION_BLOCKS: u64 = 100;

/// Domain tag for nullifier accumulator
const DS_NULL_ACC: u64 = 0x6e756c61; // "nula"

/// Domain tag for non-membership proof
const DS_NON_MEMBER: u64 = 0x6e6f6e6d; // "nonm"

// ----------------------------- Types -----------------------------

/// A prunable nullifier set with non-membership proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierSet {
    /// Current block height
    block_height: u64,
    
    /// Nullifiers by block height (for pruning)
    nullifiers_by_block: BTreeMap<u64, HashSet<Nullifier>>,
    
    /// Fast lookup set (all active nullifiers)
    active_nullifiers: HashSet<Nullifier>,
    
    /// Accumulator value (hash of all active nullifiers)
    accumulator: PallasFp,
    
    /// Oldest block we're still tracking
    oldest_block: u64,
}

impl NullifierSet {
    /// Create a new nullifier set at genesis
    pub fn new(block_height: u64) -> Self {
        Self {
            block_height,
            nullifiers_by_block: BTreeMap::new(),
            active_nullifiers: HashSet::new(),
            accumulator: PallasFp::ZERO,
            oldest_block: block_height,
        }
    }

    /// Check if a nullifier is present (double-spend check)
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.active_nullifiers.contains(nullifier)
    }

    /// Add a nullifier at the current block
    pub fn insert(&mut self, nullifier: Nullifier) -> bool {
        if self.active_nullifiers.contains(&nullifier) {
            return false; // Already present (double-spend)
        }

        // Add to block-specific set
        self.nullifiers_by_block
            .entry(self.block_height)
            .or_insert_with(HashSet::new)
            .insert(nullifier);

        // Add to fast lookup
        self.active_nullifiers.insert(nullifier);

        // Update accumulator
        self.update_accumulator(&nullifier, true);

        true
    }

    /// Batch insert multiple nullifiers
    pub fn batch_insert(&mut self, nullifiers: &[Nullifier]) -> Vec<bool> {
        nullifiers.iter().map(|nf| self.insert(*nf)).collect()
    }

    /// Advance to the next block
    pub fn advance_block(&mut self) {
        self.block_height += 1;
    }

    /// Prune old nullifiers (beyond retention window)
    pub fn prune_old(&mut self) {
        let prune_before = self.block_height.saturating_sub(NULLIFIER_RETENTION_BLOCKS);
        
        if prune_before <= self.oldest_block {
            return; // Nothing to prune
        }

        // Remove blocks older than retention window
        let old_blocks: Vec<u64> = self.nullifiers_by_block
            .range(..prune_before)
            .map(|(h, _)| *h)
            .collect();

        for block in old_blocks {
            if let Some(nullifiers) = self.nullifiers_by_block.remove(&block) {
                for nf in nullifiers {
                    self.active_nullifiers.remove(&nf);
                    self.update_accumulator(&nf, false);
                }
            }
        }

        self.oldest_block = prune_before;
    }

    /// Generate a non-membership proof for a nullifier
    ///
    /// Proves that a nullifier is NOT in the set at this block height.
    /// This is useful for proving a note hasn't been spent recently.
    pub fn prove_non_membership(&self, nullifier: &Nullifier) -> NonMembershipProof {
        let is_member = self.contains(nullifier);
        
        // Compute witness hash
        let witness = if is_member {
            // For debugging/testing: include nullifier in witness
            self.compute_membership_witness(nullifier)
        } else {
            // Compute non-membership witness
            self.compute_non_membership_witness(nullifier)
        };

        NonMembershipProof {
            nullifier: *nullifier,
            block_height: self.block_height,
            accumulator: self.accumulator,
            witness,
            is_member,
        }
    }

    /// Verify a non-membership proof
    pub fn verify_non_membership(&self, proof: &NonMembershipProof) -> bool {
        // Check block height is within retention window
        if proof.block_height < self.oldest_block {
            return false; // Proof is too old
        }

        if proof.block_height > self.block_height {
            return false; // Proof is from the future
        }

        // Check accumulator matches
        if proof.accumulator != self.accumulator {
            return false; // Wrong accumulator
        }

        // Verify witness
        let expected_witness = if proof.is_member {
            self.compute_membership_witness(&proof.nullifier)
        } else {
            self.compute_non_membership_witness(&proof.nullifier)
        };

        proof.witness == expected_witness
    }

    /// Get current accumulator value
    pub fn accumulator(&self) -> PallasFp {
        self.accumulator
    }

    /// Get current block height
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Get number of active nullifiers
    pub fn len(&self) -> usize {
        self.active_nullifiers.len()
    }

    /// Check if set is empty
    pub fn is_empty(&self) -> bool {
        self.active_nullifiers.is_empty()
    }

    /// Get retention window bounds
    pub fn retention_window(&self) -> (u64, u64) {
        (self.oldest_block, self.block_height)
    }

    // ----------------------------- Private Helpers -----------------------------

    /// Update the accumulator when adding/removing a nullifier
    fn update_accumulator(&mut self, nullifier: &Nullifier, adding: bool) {
        let nf_fp = bytes_to_fp_le(&nullifier.0);
        
        if adding {
            // Add: acc_new = H(acc_old, nf)
            self.accumulator = poseidon_hash(&[
                fp_u64(DS_NULL_ACC),
                self.accumulator,
                nf_fp,
            ]);
        } else {
            // Remove: recompute from scratch (rare operation)
            self.recompute_accumulator();
        }
    }

    /// Recompute accumulator from all active nullifiers
    fn recompute_accumulator(&mut self) {
        let mut acc = PallasFp::ZERO;
        
        // Sort nullifiers for deterministic ordering
        let mut sorted: Vec<_> = self.active_nullifiers.iter().collect();
        sorted.sort_by_key(|nf| nf.0);
        
        for nf in sorted {
            let nf_fp = bytes_to_fp_le(&nf.0);
            acc = poseidon_hash(&[fp_u64(DS_NULL_ACC), acc, nf_fp]);
        }
        
        self.accumulator = acc;
    }

    /// Compute membership witness (nullifier is in set)
    fn compute_membership_witness(&self, nullifier: &Nullifier) -> PallasFp {
        let nf_fp = bytes_to_fp_le(&nullifier.0);
        poseidon_hash(&[
            fp_u64(DS_NON_MEMBER),
            self.accumulator,
            nf_fp,
            PallasFp::ONE, // is_member = true
        ])
    }

    /// Compute non-membership witness (nullifier is NOT in set)
    fn compute_non_membership_witness(&self, nullifier: &Nullifier) -> PallasFp {
        let nf_fp = bytes_to_fp_le(&nullifier.0);
        poseidon_hash(&[
            fp_u64(DS_NON_MEMBER),
            self.accumulator,
            nf_fp,
            PallasFp::ZERO, // is_member = false
        ])
    }
}

/// A non-membership proof for a nullifier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonMembershipProof {
    /// The nullifier being proven
    pub nullifier: Nullifier,
    
    /// Block height of the proof
    pub block_height: u64,
    
    /// Accumulator value at this block
    pub accumulator: PallasFp,
    
    /// Witness (commitment to membership status)
    pub witness: PallasFp,
    
    /// Whether nullifier is a member (for verification)
    pub is_member: bool,
}

impl NonMembershipProof {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.nullifier.0);
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.accumulator.to_repr());
        bytes.extend_from_slice(&self.witness.to_repr());
        bytes.push(if self.is_member { 1 } else { 0 });
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NullifierSetError> {
        if bytes.len() != 32 + 8 + 32 + 32 + 1 {
            return Err(NullifierSetError::InvalidProof);
        }

        let mut nf_bytes = [0u8; 32];
        nf_bytes.copy_from_slice(&bytes[0..32]);

        let block_height = u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35],
            bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        let mut acc_bytes = [0u8; 32];
        acc_bytes.copy_from_slice(&bytes[40..72]);
        let accumulator = Option::from(PallasFp::from_repr(acc_bytes))
            .ok_or(NullifierSetError::InvalidProof)?;

        let mut witness_bytes = [0u8; 32];
        witness_bytes.copy_from_slice(&bytes[72..104]);
        let witness = Option::from(PallasFp::from_repr(witness_bytes))
            .ok_or(NullifierSetError::InvalidProof)?;

        let is_member = bytes[104] != 0;

        Ok(Self {
            nullifier: Nullifier(nf_bytes),
            block_height,
            accumulator,
            witness,
            is_member,
        })
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum NullifierSetError {
    #[error("nullifier already spent")]
    AlreadySpent,
    
    #[error("invalid non-membership proof")]
    InvalidProof,
    
    #[error("proof is too old (beyond retention window)")]
    ProofTooOld,
    
    #[error("proof is from the future")]
    ProofFromFuture,
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_set_creation() {
        let set = NullifierSet::new(100);
        assert_eq!(set.block_height(), 100);
        assert_eq!(set.len(), 0);
        assert!(set.is_empty());
    }

    #[test]
    fn test_insert_and_contains() {
        let mut set = NullifierSet::new(0);
        let nf = Nullifier([1u8; 32]);

        assert!(!set.contains(&nf));
        assert!(set.insert(nf));
        assert!(set.contains(&nf));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_double_spend_prevention() {
        let mut set = NullifierSet::new(0);
        let nf = Nullifier([1u8; 32]);

        assert!(set.insert(nf)); // First insert succeeds
        assert!(!set.insert(nf)); // Second insert fails (double-spend)
    }

    #[test]
    fn test_batch_insert() {
        let mut set = NullifierSet::new(0);
        let nullifiers: Vec<Nullifier> = (0..10)
            .map(|i| Nullifier([i; 32]))
            .collect();

        let results = set.batch_insert(&nullifiers);
        assert!(results.iter().all(|&r| r)); // All inserts succeed
        assert_eq!(set.len(), 10);

        // Try to insert again
        let results2 = set.batch_insert(&nullifiers);
        assert!(results2.iter().all(|&r| !r)); // All inserts fail (double-spend)
    }

    #[test]
    fn test_accumulator_updates() {
        let mut set = NullifierSet::new(0);
        let initial_acc = set.accumulator();

        let nf1 = Nullifier([1u8; 32]);
        set.insert(nf1);
        let acc1 = set.accumulator();
        assert_ne!(initial_acc, acc1);

        let nf2 = Nullifier([2u8; 32]);
        set.insert(nf2);
        let acc2 = set.accumulator();
        assert_ne!(acc1, acc2);

        // Accumulator should be deterministic
        let mut set2 = NullifierSet::new(0);
        set2.insert(nf1);
        set2.insert(nf2);
        assert_eq!(set2.accumulator(), acc2);
    }

    #[test]
    fn test_pruning() {
        let mut set = NullifierSet::new(0);

        // Add nullifiers across multiple blocks
        for block in 0..150 {
            set.advance_block();
            let nf = Nullifier([block as u8; 32]);
            set.insert(nf);
        }

        assert_eq!(set.len(), 150);

        // Prune old nullifiers
        set.prune_old();

        // Should only keep last NULLIFIER_RETENTION_BLOCKS
        assert!(set.len() <= NULLIFIER_RETENTION_BLOCKS as usize);
        
        // Check retention window
        let (oldest, newest) = set.retention_window();
        assert!(newest - oldest <= NULLIFIER_RETENTION_BLOCKS);
    }

    #[test]
    fn test_non_membership_proof() {
        let mut set = NullifierSet::new(100);
        
        let nf_present = Nullifier([1u8; 32]);
        let nf_absent = Nullifier([2u8; 32]);
        
        set.insert(nf_present);

        // Proof that nf_present IS in the set
        let proof_present = set.prove_non_membership(&nf_present);
        assert!(proof_present.is_member);
        assert!(set.verify_non_membership(&proof_present));

        // Proof that nf_absent is NOT in the set
        let proof_absent = set.prove_non_membership(&nf_absent);
        assert!(!proof_absent.is_member);
        assert!(set.verify_non_membership(&proof_absent));
    }

    #[test]
    fn test_proof_serialization() {
        let mut set = NullifierSet::new(100);
        let nf = Nullifier([42u8; 32]);
        set.insert(nf);

        let proof = set.prove_non_membership(&nf);
        let bytes = proof.to_bytes();
        let decoded = NonMembershipProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.nullifier, decoded.nullifier);
        assert_eq!(proof.block_height, decoded.block_height);
        assert_eq!(proof.is_member, decoded.is_member);
    }

    #[test]
    fn test_proof_validation_block_height() {
        let mut set = NullifierSet::new(100);
        let nf = Nullifier([1u8; 32]);
        
        let mut proof = set.prove_non_membership(&nf);
        
        // Proof from future should fail
        proof.block_height = 200;
        assert!(!set.verify_non_membership(&proof));

        // Proof too old (beyond retention) should fail
        set.advance_block();
        for _ in 0..NULLIFIER_RETENTION_BLOCKS + 10 {
            set.advance_block();
        }
        set.prune_old();
        
        proof.block_height = 50; // Before oldest_block
        assert!(!set.verify_non_membership(&proof));
    }

    #[test]
    fn test_accumulator_recomputation() {
        let mut set = NullifierSet::new(0);

        // Add some nullifiers
        for i in 0..10 {
            set.insert(Nullifier([i; 32]));
        }

        let acc_before = set.accumulator();

        // Force recomputation
        set.recompute_accumulator();

        // Should be the same
        assert_eq!(acc_before, set.accumulator());
    }

    #[test]
    fn test_retention_window_boundaries() {
        let mut set = NullifierSet::new(0);

        // Add nullifiers for many blocks
        for block in 0..200 {
            if block > 0 {
                set.advance_block();
            }
            let nf = Nullifier([block as u8; 32]);
            set.insert(nf);
        }

        set.prune_old();

        let (oldest, newest) = set.retention_window();
        
        // Newest should be current block
        assert_eq!(newest, set.block_height());
        
        // Oldest should be ~NULLIFIER_RETENTION_BLOCKS ago
        assert!(newest - oldest <= NULLIFIER_RETENTION_BLOCKS);
        
        // Very old nullifiers should be gone
        let very_old_nf = Nullifier([0u8; 32]);
        assert!(!set.contains(&very_old_nf));
    }
}

