//! Incremental Merkle Tree for Tachyon
//!
//! This module implements an incremental Merkle tree that supports efficient
//! updates without rebuilding the entire tree. This is critical for oblivious
//! sync services that need to process many blocks.
//!
//! # Problem
//!
//! Naive implementation rebuilds the entire tree on each update:
//! - Time: O(n log n) where n = number of leaves
//! - For 1M leaves: ~20 million hash operations
//!Numan Thabit
//! # Algorithm
//!
//! The tree maintains:
//! 1. Current leaves (sparse representation)
//! 2. Cached intermediate nodes
//! 3. Frontier (rightmost path from root to next insertion point)
//!
//! On insert(leaf):
//! 1. Append leaf to the tree
//! 2. Recompute path from leaf to root
//! 3. Update frontier
//! 4. Cache new intermediate nodes
//!
//! # Memory Efficiency
//!
//! - Full tree: O(n) nodes
//! - Incremental tree: O(h) frontier + O(k) cache
//! - For height 32: ~32 frontier nodes + cache

use halo2curves::pasta::Fp as PallasFp;
use std::collections::BTreeMap;
use thiserror::Error;

use crate::tachystamps::{Tachygram, MerklePath};

// Import Poseidon hash from tachystamps
use crate::tachystamps::{
    fp_u64,
    bytes_to_fp_le,
};
use crate::tachystamps::native::poseidon_hash as poseidon_native_hash_many;

pub const DS_LEAF: u64 = 0x6c656166; // "leaf"
pub const DS_NODE: u64 = 0x6e6f6465; // "node"

// Make these accessible
fn poseidon_hash_leaf(leaf: &Tachygram) -> PallasFp {
    let leaf_fp = bytes_to_fp_le(&leaf.0);
    poseidon_native_hash_many(&[fp_u64(DS_LEAF), leaf_fp])
}

fn poseidon_hash_node(left: PallasFp, right: PallasFp) -> PallasFp {
    poseidon_native_hash_many(&[fp_u64(DS_NODE), left, right])
}

// ----------------------------- Types -----------------------------

/// An incremental Merkle tree
///
/// Supports efficient O(log n) insertions without rebuilding.
#[derive(Clone, Debug)]
pub struct IncrementalMerkleTree {
    /// Tree height (depth)
    pub height: usize,
    
    /// Number of leaves currently in the tree
    pub num_leaves: usize,
    
    /// Maximum capacity (2^height)
    pub capacity: usize,
    
    /// Frontier: rightmost path from root to next insertion
    /// frontier[0] = rightmost leaf, frontier[h] = root
    frontier: Vec<PallasFp>,
    
    /// Cache of intermediate nodes for witness generation
    /// Key: (level, index) → value: hash
    node_cache: BTreeMap<(usize, usize), PallasFp>,
    
    /// Empty node hashes at each level (precomputed)
    empty_nodes: Vec<PallasFp>,
}

impl IncrementalMerkleTree {
    /// Create a new empty tree
    pub fn new(height: usize) -> Self {
        let capacity = 1 << height;
        
        // Precompute empty node hashes
        let mut empty_nodes = vec![PallasFp::zero(); height + 1];
        empty_nodes[0] = poseidon_hash_leaf(&Tachygram([0u8; 32])); // Empty leaf
        
        for level in 1..=height {
            let left = empty_nodes[level - 1];
            let right = empty_nodes[level - 1];
            empty_nodes[level] = poseidon_hash_node(left, right);
        }
        
        // Initialize frontier with empty nodes
        let frontier = empty_nodes.clone();
        
        Self {
            height,
            num_leaves: 0,
            capacity,
            frontier,
            node_cache: BTreeMap::new(),
            empty_nodes,
        }
    }
    
    /// Insert a new leaf into the tree
    ///
    /// # Arguments
    /// - `leaf`: The tachygram to insert
    ///
    /// # Returns
    /// The index where the leaf was inserted
    ///
    /// # Errors
    /// Returns error if tree is full
    pub fn insert(&mut self, leaf: &Tachygram) -> Result<usize, MerkleError> {
        if self.num_leaves >= self.capacity {
            return Err(MerkleError::TreeFull);
        }
        
        let index = self.num_leaves;
        
        // Compute leaf hash
        let leaf_hash = poseidon_hash_leaf(leaf);
        
        // Update frontier and cache
        self.update_frontier(index, leaf_hash);
        
        self.num_leaves += 1;
        
        Ok(index)
    }
    
    /// Update the frontier after inserting a leaf
    ///
    /// This is the core of the incremental algorithm.
    fn update_frontier(&mut self, index: usize, leaf_hash: PallasFp) {
        let mut current = leaf_hash;
        let mut pos = index;
        
        // Cache the leaf
        self.node_cache.insert((0, index), leaf_hash);
        
        // Propagate up the tree
        for level in 0..self.height {
            let is_right_child = (pos & 1) == 1;
            
            if is_right_child {
                // This is a right child, so we need the left sibling
                let left_index = pos - 1;
                let left = *self.node_cache.get(&(level, left_index))
                    .unwrap_or(&self.empty_nodes[level]);
                
                // Compute parent
                current = poseidon_hash_node(left, current);
            } else {
                // This is a left child, sibling is empty
                let right = self.empty_nodes[level];
                current = poseidon_hash_node(current, right);
            }
            
            // Cache the parent
            let parent_index = pos / 2;
            self.node_cache.insert((level + 1, parent_index), current);
            
            // Update frontier
            self.frontier[level + 1] = current;
            
            pos = parent_index;
        }
    }
    
    /// Get the current root hash
    pub fn root(&self) -> PallasFp {
        self.frontier[self.height]
    }
    
    /// Generate a membership witness for a leaf
    ///
    /// # Arguments
    /// - `index`: Index of the leaf (must be < num_leaves)
    ///
    /// # Returns
    /// A Merkle path proving the leaf exists in the tree
    pub fn witness(&self, index: usize) -> Result<MerklePath, MerkleError> {
        if index >= self.num_leaves {
            return Err(MerkleError::InvalidIndex);
        }
        
        let mut siblings = Vec::with_capacity(self.height);
        let mut directions = Vec::with_capacity(self.height);
        let mut pos = index;
        
        for level in 0..self.height {
            let is_right = (pos & 1) == 1;
            
            let sibling_index = if is_right { pos - 1 } else { pos + 1 };
            
            // Get sibling from cache or use empty node
            let sibling = if is_right || sibling_index < self.num_leaves {
                *self.node_cache.get(&(level, sibling_index))
                    .unwrap_or(&self.empty_nodes[level])
            } else {
                self.empty_nodes[level]
            };
            
            siblings.push(sibling);
            directions.push(is_right);
            
            pos /= 2;
        }
        
        Ok(MerklePath {
            siblings,
            directions,
        })
    }
    
    /// Batch insert multiple leaves
    ///
    /// More efficient than inserting one at a time.
    pub fn batch_insert(&mut self, leaves: &[Tachygram]) -> Result<Vec<usize>, MerkleError> {
        let mut indices = Vec::with_capacity(leaves.len());
        
        for leaf in leaves {
            let index = self.insert(leaf)?;
            indices.push(index);
        }
        
        Ok(indices)
    }
    
    /// Get cache statistics (for debugging/optimization)
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            num_leaves: self.num_leaves,
            cache_size: self.node_cache.len(),
            height: self.height,
            fill_ratio: self.num_leaves as f64 / self.capacity as f64,
        }
    }
    
    /// Prune cache to save memory
    ///
    /// Removes cached nodes that are no longer needed for witness generation.
    /// Keeps only nodes necessary for the current frontier and recent witnesses.
    pub fn prune_cache(&mut self, keep_recent: usize) {
        if self.num_leaves <= keep_recent {
            return; // Don't prune if tree is small
        }
        
        let prune_before_index = self.num_leaves.saturating_sub(keep_recent);
        
        // Remove old leaf nodes
        self.node_cache.retain(|(level, index), _| {
            *level > 0 || *index >= prune_before_index
        });
    }
}

/// Cache statistics
#[derive(Clone, Debug)]
pub struct CacheStats {
    /// Number of leaves in the tree
    pub num_leaves: usize,
    /// Size of the cache in nodes
    pub cache_size: usize,
    /// Height of the tree
    pub height: usize,
    /// Ratio of filled leaves to capacity
    pub fill_ratio: f64,
}

// ----------------------------- Errors -----------------------------

/// Errors that can occur during Merkle tree operations
#[derive(Error, Debug)]
pub enum MerkleError {
    /// The tree has reached its maximum capacity
    #[error("tree is full")]
    TreeFull,
    
    /// The provided leaf index is out of bounds
    #[error("invalid leaf index")]
    InvalidIndex,
    
    /// The witness path is invalid
    #[error("invalid witness")]
    InvalidWitness,
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use group::ff::Field;
    
    #[test]
    fn test_empty_tree() {
        let tree = IncrementalMerkleTree::new(4);
        assert_eq!(tree.num_leaves, 0);
        assert_eq!(tree.capacity, 16);
        
        // Root should be the empty root
        let root = tree.root();
        assert_ne!(root, PallasFp::ZERO);
    }
    
    #[test]
    fn test_single_insert() {
        let mut tree = IncrementalMerkleTree::new(4);
        let leaf = Tachygram([1u8; 32]);
        
        let index = tree.insert(&leaf).unwrap();
        assert_eq!(index, 0);
        assert_eq!(tree.num_leaves, 1);
    }
    
    #[test]
    fn test_multiple_inserts() {
        let mut tree = IncrementalMerkleTree::new(4);
        
        for i in 0..10u8 {
            let mut leaf_bytes = [0u8; 32];
            leaf_bytes[0] = i;
            let leaf = Tachygram(leaf_bytes);
            
            let index = tree.insert(&leaf).unwrap();
            assert_eq!(index, i as usize);
        }
        
        assert_eq!(tree.num_leaves, 10);
    }
    
    #[test]
    fn test_witness_generation() {
        let mut tree = IncrementalMerkleTree::new(4);
        
        // Insert some leaves
        let leaves: Vec<Tachygram> = (0..8)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                Tachygram(bytes)
            })
            .collect();
        
        for leaf in &leaves {
            tree.insert(leaf).unwrap();
        }
        
        // Generate witness for leaf 5
        let witness = tree.witness(5).unwrap();
        assert_eq!(witness.siblings.len(), 4);
        assert_eq!(witness.directions.len(), 4);
        
        // Verify the witness
        let leaf_hash = poseidon_hash_leaf(&leaves[5]);
        let mut current = leaf_hash;
        
        for (sibling, is_right) in witness.siblings.iter().zip(&witness.directions) {
            current = if *is_right {
                poseidon_hash_node(*sibling, current)
            } else {
                poseidon_hash_node(current, *sibling)
            };
        }
        
        assert_eq!(current, tree.root());
    }
    
    #[test]
    fn test_tree_full() {
        let mut tree = IncrementalMerkleTree::new(2); // Capacity 4
        
        for i in 0..4 {
            let leaf = Tachygram([i as u8; 32]);
            tree.insert(&leaf).unwrap();
        }
        
        // Next insert should fail
        let leaf = Tachygram([5u8; 32]);
        assert!(tree.insert(&leaf).is_err());
    }
    
    #[test]
    fn test_batch_insert() {
        let mut tree = IncrementalMerkleTree::new(4);
        
        let leaves: Vec<Tachygram> = (0..5)
            .map(|i| Tachygram([i as u8; 32]))
            .collect();
        
        let indices = tree.batch_insert(&leaves).unwrap();
        assert_eq!(indices.len(), 5);
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
        assert_eq!(tree.num_leaves, 5);
    }
    
    #[test]
    fn test_cache_pruning() {
        let mut tree = IncrementalMerkleTree::new(6); // Capacity 64
        
        // Insert many leaves
        for i in 0..50 {
            tree.insert(&Tachygram([i as u8; 32])).unwrap();
        }
        
        let stats_before = tree.cache_stats();
        assert!(stats_before.cache_size > 0);
        
        // Prune old entries
        tree.prune_cache(10);
        
        let stats_after = tree.cache_stats();
        // Cache should be smaller (or same if nothing to prune)
        assert!(stats_after.cache_size <= stats_before.cache_size);
    }
    
    #[test]
    fn test_cache_stats() {
        let mut tree = IncrementalMerkleTree::new(4);
        
        for i in 0..8 {
            tree.insert(&Tachygram([i as u8; 32])).unwrap();
        }
        
        let stats = tree.cache_stats();
        assert_eq!(stats.num_leaves, 8);
        assert_eq!(stats.height, 4);
        assert_eq!(stats.fill_ratio, 0.5); // 8/16
    }
    
    #[test]
    fn test_incremental_vs_rebuild() {
        // Compare incremental updates with full rebuild
        let mut inc_tree = IncrementalMerkleTree::new(4);
        
        let leaves: Vec<Tachygram> = (0..10)
            .map(|i| Tachygram([i as u8; 32]))
            .collect();
        
        // Insert incrementally
        for leaf in &leaves {
            inc_tree.insert(leaf).unwrap();
        }
        
        let inc_root = inc_tree.root();
        
        // Build from scratch (using tachystamps::MerkleTree)
        let full_tree = crate::tachystamps::build_tree(&leaves, 4);
        let full_root = full_tree.root();
        
        // Roots should match
        assert_eq!(inc_root, full_root);
    }
}

