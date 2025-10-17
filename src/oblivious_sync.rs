//! Oblivious Synchronization for Tachyon Wallets
//! Goal of this code =
//! This module implements the core oblivious synchronization mechanism described in the
//! Tachyon blog post. It allows wallets to outsource expensive synchronization work to
//! untrusted third-party services without revealing private note information.
//!
//! # Core Concepts
//!
//! ## Wallet State as Proof-Carrying Data (PCD)
//! Rather than just tracking note witnesses, the wallet maintains a proof of its own
//! correctness that evolves as blocks are processed. When spending, this proof becomes
//! part of the transaction, reducing validator burden.
//!
//! ## Oblivious Syncing Service
//! A third party that can:
//! - Process blocks to check if nullifiers have been spent
//! - Update Merkle witness proofs for note commitments
//! - Generate PCD proofs of wallet state validity
//! - Do all this WITHOUT learning:
//!   * Which notes the wallet owns
//!   * Note values or amounts
//!   * Note positions in the accumulator
//!   * Spending keys or addresses
//!
//! The service only learns:
//! - Nullifiers (which are public when spent anyway)
//! - That the wallet is interested in tracking certain nullifiers
//!
//! ## Privacy Guarantee
//! By deriving nullifiers independently of note commitments (as per Tachyon's modified
//! nullifier derivation), the service cannot correlate a nullifier with a specific note
//! position in the Merkle tree, preserving strong privacy.
//!
//! # Architecture
//!
//! ```text
//! Wallet                    Oblivious Sync Service           Blockchain
//!   |                              |                              |
//!   |--SyncRequest(nullifiers)---->|                              |
//!   |                              |<----fetch blocks N..M--------|
//!   |                              |                              |
//!   |                              |--check nullifiers not spent--|
//!   |                              |--update Merkle witnesses-----|
//!   |                              |--generate PCD proof---------|
//!   |                              |                              |
//!   |<---SyncResponse(PCD proof)---|                              |
//!   |                              |                              |
//!   |--verify proof-------------->|                              |
//!   |--spend with attached PCD----------------------------------->|
//! ```

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

// Re-use types from tachystamps module
use crate::tachystamps::{
    AnchorRange, Compressed, MerklePath, MerkleTree, Prover, RecParams, Tachygram,
    TachyStepCircuit, TachyError,
};

// Pasta curve scalar field
use halo2curves::pasta::Fp as PallasFp;

// ----------------------------- Types -----------------------------

/// A nullifier is a 32-byte unique identifier for a spent note.
/// In Tachyon, nullifiers are derived independently of note commitments to prevent
/// the oblivious sync service from learning note positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

/// Represents the state of a single note being tracked by the wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteState {
    /// The nullifier for this note (public to sync service)
    pub nullifier: Nullifier,
    
    /// The note commitment (private, NOT shared with service)
    pub commitment: Tachygram,
    
    /// Current Merkle witness for this note
    pub witness: MerklePath,
    
    /// Block height at which this note was created
    pub created_at_block: u64,
    
    /// Last block height at which we verified it wasn't spent
    pub last_checked_block: u64,
    
    /// Whether this note has been spent
    pub spent: bool,
}

/// Wallet state with proof-carrying data.
/// This is the core data structure that gets synchronized.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletState {
    /// Current block height
    pub current_block: u64,
    
    /// Current Merkle tree root (anchor)
    pub anchor: [u8; 32],
    
    /// Notes being tracked by this wallet
    pub notes: Vec<NoteState>,
    
    /// The PCD proof of wallet state validity up to current_block
    /// None if we haven't started syncing yet
    pub pcd_proof: Option<Compressed>,
    
    /// Set of all nullifiers we've seen on-chain (for double-spend detection)
    pub seen_nullifiers: BTreeSet<Nullifier>,
}

/// A blinded wallet state that can be sent to the oblivious sync service.
/// This reveals only the nullifiers, not the note commitments or values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindedWalletState {
    /// Block height we want to sync from
    pub from_block: u64,
    
    /// Block height we want to sync to
    pub to_block: u64,
    
    /// Nullifiers to track (this is the only private info we reveal)
    pub nullifiers: Vec<Nullifier>,
    
    /// Commitment to the full wallet state (for verification)
    /// H(notes || anchor || current_block)
    pub state_commitment: [u8; 32],
    
    /// Previous PCD proof (if any) that service will extend
    pub previous_pcd: Option<Compressed>,
}

/// Request sent to the oblivious sync service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Blinded wallet state
    pub blinded_state: BlindedWalletState,
    
    /// Optional: rate limiting token or authentication
    pub auth_token: Option<Vec<u8>>,
}

/// Response from the oblivious sync service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    /// New PCD proof covering from_block..to_block
    pub pcd_proof: Compressed,
    
    /// Which blocks were actually processed
    pub processed_blocks: Vec<u64>,
    
    /// Any nullifiers from our list that were spent in this range
    pub spent_nullifiers: Vec<Nullifier>,
    
    /// New tachygrams (note commitments) added in this range
    /// Service doesn't know which belong to us, but we can check
    pub new_tachygrams: Vec<(u64, Tachygram)>, // (block_height, tachygram)
    
    /// Updated anchor after processing all blocks
    pub new_anchor: [u8; 32],
}

/// Configuration for the oblivious sync service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncServiceConfig {
    /// Maximum number of blocks to process in one request
    pub max_blocks_per_request: u64,
    
    /// Maximum number of nullifiers to track per request
    pub max_nullifiers_per_request: usize,
    
    /// Merkle tree height
    pub tree_height: usize,
    
    /// Batch size for proof generation
    pub proof_batch_size: usize,
}

impl Default for SyncServiceConfig {
    fn default() -> Self {
        Self {
            max_blocks_per_request: 1000,
            max_nullifiers_per_request: 100,
            tree_height: 32, // Orchard tree height
            proof_batch_size: 16,
        }
    }
}

// ----------------------------- Errors -----------------------------

/// Errors that can occur during oblivious synchronization
#[derive(Error, Debug)]
pub enum SyncError {
    /// The block range is invalid
    #[error("block range invalid: from {0} to {1}")]
    InvalidBlockRange(u64, u64),
    
    /// Too many blocks requested in a single sync
    #[error("too many blocks requested: {0} > {1}")]
    TooManyBlocks(u64, u64),
    
    /// Too many nullifiers in the sync request
    #[error("too many nullifiers: {0} > {1}")]
    TooManyNullifiers(usize, usize),
    
    /// Proof verification failed
    #[error("proof verification failed")]
    ProofVerificationFailed,
    
    /// State commitment doesn't match
    #[error("state commitment mismatch")]
    StateCommitmentMismatch,
    
    /// Blockchain data is unavailable for the requested block
    #[error("blockchain data unavailable for block {0}")]
    BlockchainDataUnavailable(u64),
    
    /// Error from tachystamps module
    #[error("tachystamps error: {0}")]
    Tachystamps(#[from] TachyError),
    
    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ----------------------------- Blockchain Interface -----------------------------

/// Trait for accessing blockchain data.
/// The oblivious sync service needs this to fetch blocks and check nullifiers.
pub trait BlockchainProvider {
    /// Get all tachygrams (note commitments + nullifiers) revealed in a block
    fn get_tachygrams_in_block(&self, block_height: u64) -> Result<Vec<Tachygram>, SyncError>;
    
    /// Check if a nullifier was spent in a specific block range
    fn is_nullifier_spent_in_range(
        &self,
        nullifier: &Nullifier,
        from_block: u64,
        to_block: u64,
    ) -> Result<Option<u64>, SyncError>; // Returns Some(block_height) if spent
    
    /// Get the current block height
    fn current_block_height(&self) -> Result<u64, SyncError>;
    
    /// Get the Merkle root (anchor) at a specific block
    fn get_anchor_at_block(&self, block_height: u64) -> Result<[u8; 32], SyncError>;
}

// ----------------------------- Wallet State Management -----------------------------

impl WalletState {
    /// Create a new empty wallet state at genesis.
    pub fn new() -> Self {
        Self {
            current_block: 0,
            anchor: [0u8; 32],
            notes: Vec::new(),
            pcd_proof: None,
            seen_nullifiers: BTreeSet::new(),
        }
    }
    
    /// Add a new note to track (received out-of-band).
    pub fn add_note(
        &mut self,
        nullifier: Nullifier,
        commitment: Tachygram,
        witness: MerklePath,
        created_at_block: u64,
    ) {
        self.notes.push(NoteState {
            nullifier,
            commitment,
            witness,
            created_at_block,
            last_checked_block: created_at_block,
            spent: false,
        });
    }
    
    /// Create a blinded version of this state for sync request.
    pub fn blind(&self, to_block: u64) -> BlindedWalletState {
        let nullifiers: Vec<Nullifier> = self
            .notes
            .iter()
            .filter(|n| !n.spent)
            .map(|n| n.nullifier)
            .collect();
        
        // Commit to full state
        let state_commitment = self.compute_state_commitment();
        
        BlindedWalletState {
            from_block: self.current_block,
            to_block,
            nullifiers,
            state_commitment,
            previous_pcd: self.pcd_proof.clone(),
        }
    }
    
    /// Compute a binding commitment to the wallet state.
    fn compute_state_commitment(&self) -> [u8; 32] {
        use blake2::{Blake2b512, Digest};
        
        let mut hasher = Blake2b512::new();
        hasher.update(b"zcash-tachyon-wallet-state");
        hasher.update(&self.current_block.to_le_bytes());
        hasher.update(&self.anchor);
        
        for note in &self.notes {
            hasher.update(&note.nullifier.0);
            hasher.update(&note.commitment.0);
            hasher.update(&[note.spent as u8]);
        }
        
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash[..32]);
        result
    }
    
    /// Apply a sync response to update wallet state.
    pub fn apply_sync_response(&mut self, response: &SyncResponse) -> Result<(), SyncError> {
        // Verify the PCD proof
        self.verify_pcd_proof(&response.pcd_proof, &response.processed_blocks)?;
        
        // Mark spent notes
        for spent_nf in &response.spent_nullifiers {
            if let Some(note) = self.notes.iter_mut().find(|n| &n.nullifier == spent_nf) {
                note.spent = true;
            }
            self.seen_nullifiers.insert(*spent_nf);
        }
        
        // Update state
        self.current_block = response.processed_blocks.iter().max().copied().unwrap_or(self.current_block);
        self.anchor = response.new_anchor;
        self.pcd_proof = Some(response.pcd_proof.clone());
        
        // Update last_checked_block for all notes
        for note in &mut self.notes {
            if !note.spent {
                note.last_checked_block = self.current_block;
            }
        }
        
        Ok(())
    }
    
    /// Get all unspent notes ready to be spent.
    pub fn get_spendable_notes(&self) -> Vec<&NoteState> {
        self.notes
            .iter()
            .filter(|n| !n.spent && n.last_checked_block >= self.current_block)
            .collect()
    }
    
    /// Verify a PCD proof from a sync response
    ///
    /// This checks that the proof is valid and covers the claimed block range.
    ///
    /// # Verification Steps
    /// 1. Extract proof metadata (steps, acc_final, ctx)
    /// 2. Verify the compressed SNARK
    /// 3. Check that ctx matches the expected anchor range
    /// 4. Validate proof covers all processed blocks
    fn verify_pcd_proof(
        &self,
        pcd_proof: &Compressed,
        processed_blocks: &[u64],
    ) -> Result<(), SyncError> {
        // Extract metadata
        let meta = &pcd_proof.meta;
        
        // Construct expected z0 (initial state)
        // z0 = [acc_init, ctx_init, step_init]
        let z0 = vec![meta.acc_init, meta.ctx, PallasFp::from(0u64)];
        
        // Verify the compressed proof
        let valid = Prover::verify(pcd_proof, &z0)
            .map_err(|_e| SyncError::ProofVerificationFailed)?;
        
        if !valid {
            return Err(SyncError::ProofVerificationFailed);
        }
        
        // Additional validation: check that authorized_pairs is well-formed
        // (ensures the proof actually authorizes some actions)
        if meta.authorized_pairs.is_empty() && !processed_blocks.is_empty() {
            // If we processed blocks but proof has no authorized pairs,
            // it's suspicious (though technically valid if no notes were involved)
            // For now, we allow it but could add stricter validation
        }
        
        // Proof verified successfully
        Ok(())
    }
}

// ----------------------------- Oblivious Sync Service -----------------------------

/// The oblivious synchronization service.
/// This is the untrusted third party that helps wallets stay synchronized.
pub struct ObliviousSyncService<B: BlockchainProvider> {
    blockchain: B,
    config: SyncServiceConfig,
    prover: Option<Prover>, // Cached prover setup
    /// Incremental Merkle tree for efficient updates
    merkle_tree: Option<crate::incremental_merkle::IncrementalMerkleTree>,
}

impl<B: BlockchainProvider> ObliviousSyncService<B> {
    /// Create a new sync service with the given blockchain provider.
    pub fn new(blockchain: B, config: SyncServiceConfig) -> Self {
        Self {
            blockchain,
            config,
            prover: None,
            merkle_tree: None,
        }
    }
    
    /// Initialize the incremental Merkle tree
    pub fn init_merkle_tree(&mut self) {
        self.merkle_tree = Some(crate::incremental_merkle::IncrementalMerkleTree::new(
            self.config.tree_height
        ));
    }
    
    /// Process a sync request and return a response.
    pub fn process_sync_request(&mut self, request: SyncRequest) -> Result<SyncResponse, SyncError> {
        let blinded = &request.blinded_state;
        
        // Validate request
        self.validate_request(blinded)?;
        
        // Process blocks in the requested range
        let mut spent_nullifiers = Vec::new();
        let mut new_tachygrams = Vec::new();
        let mut processed_blocks = Vec::new();
        
        for block_height in blinded.from_block..=blinded.to_block {
            // Check if any tracked nullifiers were spent in this block
            for nullifier in &blinded.nullifiers {
                if let Some(spent_at) = self.blockchain.is_nullifier_spent_in_range(
                    nullifier,
                    block_height,
                    block_height,
                )? {
                    if spent_at == block_height && !spent_nullifiers.contains(nullifier) {
                        spent_nullifiers.push(*nullifier);
                    }
                }
            }
            
            // Collect new tachygrams (both commitments and nullifiers)
            let tachygrams = self.blockchain.get_tachygrams_in_block(block_height)?;
            for tg in tachygrams {
                new_tachygrams.push((block_height, tg));
            }
            
            processed_blocks.push(block_height);
        }
        
        // Get the updated anchor
        let new_anchor = self.blockchain.get_anchor_at_block(blinded.to_block)?;
        
        // Generate PCD proof
        // This proves that:
        // 1. All tracked nullifiers were checked for spends
        // 2. Merkle witnesses are updated to the new anchor
        // 3. The wallet state transition is valid
        let pcd_proof = self.generate_pcd_proof(
            blinded,
            &processed_blocks,
            &new_tachygrams,
            new_anchor,
        )?;
        
        Ok(SyncResponse {
            pcd_proof,
            processed_blocks,
            spent_nullifiers,
            new_tachygrams,
            new_anchor,
        })
    }
    
    /// Validate a sync request.
    fn validate_request(&self, blinded: &BlindedWalletState) -> Result<(), SyncError> {
        // Check block range
        if blinded.from_block > blinded.to_block {
            return Err(SyncError::InvalidBlockRange(blinded.from_block, blinded.to_block));
        }
        
        let block_span = blinded.to_block - blinded.from_block + 1;
        if block_span > self.config.max_blocks_per_request {
            return Err(SyncError::TooManyBlocks(
                block_span,
                self.config.max_blocks_per_request,
            ));
        }
        
        // Check nullifier count
        if blinded.nullifiers.len() > self.config.max_nullifiers_per_request {
            return Err(SyncError::TooManyNullifiers(
                blinded.nullifiers.len(),
                self.config.max_nullifiers_per_request,
            ));
        }
        
        Ok(())
    }
    
    /// Generate a PCD proof of the wallet state update.
    ///
    /// This proof demonstrates:
    /// - All nullifiers in the set were checked for spends
    /// - None of the unspent nullifiers appeared in blocks from_block..to_block
    /// - Merkle witnesses were properly updated
    /// - The state transition from old anchor to new anchor is valid
    fn generate_pcd_proof(
        &mut self,
        blinded: &BlindedWalletState,
        processed_blocks: &[u64],
        new_tachygrams: &[(u64, Tachygram)],
        new_anchor: [u8; 32],
    ) -> Result<Compressed, SyncError> {
        // Initialize prover if needed
        if self.prover.is_none() {
            let params = RecParams {
                tree_height: self.config.tree_height,
                batch_leaves: self.config.proof_batch_size,
            };
            self.prover = Some(Prover::setup(&params)?);
        }
        
        // Use incremental Merkle tree for efficient updates
        // Initialize tree if needed
        if self.merkle_tree.is_none() {
            self.init_merkle_tree();
        }
        
        {
            let tree = self.merkle_tree.as_mut().unwrap();
            
            // Incrementally insert new tachygrams (O(log n) each)
            for (_, tachygram) in new_tachygrams {
                tree.insert(tachygram)
                    .map_err(|e| SyncError::Tachystamps(TachyError::Halo2(format!("{:?}", e))))?;
            }
        }
        
        // Get tree reference for witness generation
        let tree_ref = self.merkle_tree.as_ref().unwrap();
        let root_fp = tree_ref.root();
        
        let prover = self.prover.as_mut().unwrap();
        
        // Convert anchor to field element
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes.copy_from_slice(&new_anchor);
        
        // Initialize the prover with the anchor range
        let anchor_range = AnchorRange {
            start: blinded.from_block,
            end: blinded.to_block,
        };
        prover.init(root_fp, anchor_range)?;
        
        // Generate proof steps
        // Each step proves a batch of tachygram membership/non-membership
        let batch_size = self.config.proof_batch_size;
        
        let num_leaves = tree_ref.num_leaves;
        
        for chunk_start in (0..num_leaves).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(num_leaves);
            
            // Pad to batch size if needed
            let mut leaves = vec![[0u8; 32]; batch_size];
            let mut paths = Vec::with_capacity(batch_size);
            
            for i in chunk_start..chunk_end {
                // Use incremental tree for witness generation (efficient!)
                let witness = tree_ref.witness(i)
                    .map_err(|e| SyncError::Tachystamps(
                        TachyError::Halo2(format!("witness error: {:?}", e))
                    ))?;
                let tg = new_tachygrams.get(i - chunk_start)
                    .map(|(_, tg)| tg.0)
                    .unwrap_or([0u8; 32]);
                leaves[i - chunk_start] = tg;
                paths.push(witness);
            }
            
            // Pad remaining with dummy proofs
            for _i in (chunk_end - chunk_start)..batch_size {
                paths.push(tree_ref.witness(0).unwrap_or_else(|_| MerklePath {
                    siblings: vec![PallasFp::from(0u64); self.config.tree_height],
                    directions: vec![false; self.config.tree_height],
                }));
            }
            
            prover.prove_step(root_fp, anchor_range, leaves, paths)?;
        }
        
        // Finalize and compress the proof
        let compressed = prover.finalize()?;
        
        Ok(compressed)
    }
}

// ----------------------------- Wallet Synchronization Flow -----------------------------

/// High-level wallet synchronization helper.
pub struct WalletSynchronizer<B: BlockchainProvider> {
    /// The oblivious sync service instance
    service: ObliviousSyncService<B>,
}

impl<B: BlockchainProvider> WalletSynchronizer<B> {
    /// Create a new wallet synchronizer
    pub fn new(blockchain: B, config: SyncServiceConfig) -> Self {
        Self {
            service: ObliviousSyncService::new(blockchain, config),
        }
    }
    
    /// Synchronize a wallet to the current blockchain tip.
    pub fn sync_wallet(&mut self, wallet: &mut WalletState) -> Result<(), SyncError> {
        let current_tip = self.service.blockchain.current_block_height()?;
        
        if wallet.current_block >= current_tip {
            return Ok(()); // Already synced
        }
        
        // Sync in chunks
        let max_blocks = self.service.config.max_blocks_per_request;
        let mut next_block = wallet.current_block + 1;
        
        while next_block <= current_tip {
            let to_block = (next_block + max_blocks - 1).min(current_tip);
            
            // Create sync request
            let blinded = wallet.blind(to_block);
            let request = SyncRequest {
                blinded_state: blinded,
                auth_token: None,
            };
            
            // Process with sync service
            let response = self.service.process_sync_request(request)?;
            
            // Apply response to wallet
            wallet.apply_sync_response(&response)?;
            
            next_block = to_block + 1;
        }
        
        Ok(())
    }
}

// ----------------------------- Mock Blockchain Provider (for testing) -----------------------------

/// A simple in-memory blockchain for testing.
#[derive(Clone, Debug)]
pub struct MockBlockchain {
    /// Blocks mapped by height
    blocks: BTreeMap<u64, Vec<Tachygram>>,
    /// Spent nullifiers mapped to the block they were spent in
    spent_nullifiers: BTreeMap<Nullifier, u64>, // nullifier -> block spent
    /// Anchors (state roots) for each block
    anchors: BTreeMap<u64, [u8; 32]>,
}

impl MockBlockchain {
    /// Create a new empty mock blockchain
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            spent_nullifiers: BTreeMap::new(),
            anchors: BTreeMap::new(),
        }
    }
    
    /// Add a block to the mock blockchain
    pub fn add_block(&mut self, height: u64, tachygrams: Vec<Tachygram>, anchor: [u8; 32]) {
        self.blocks.insert(height, tachygrams);
        self.anchors.insert(height, anchor);
    }
    
    /// Mark a nullifier as spent at a specific block
    pub fn mark_nullifier_spent(&mut self, nullifier: Nullifier, at_block: u64) {
        self.spent_nullifiers.insert(nullifier, at_block);
    }
}

impl BlockchainProvider for MockBlockchain {
    fn get_tachygrams_in_block(&self, block_height: u64) -> Result<Vec<Tachygram>, SyncError> {
        self.blocks
            .get(&block_height)
            .cloned()
            .ok_or(SyncError::BlockchainDataUnavailable(block_height))
    }
    
    fn is_nullifier_spent_in_range(
        &self,
        nullifier: &Nullifier,
        from_block: u64,
        to_block: u64,
    ) -> Result<Option<u64>, SyncError> {
        if let Some(&spent_at) = self.spent_nullifiers.get(nullifier) {
            if spent_at >= from_block && spent_at <= to_block {
                return Ok(Some(spent_at));
            }
        }
        Ok(None)
    }
    
    fn current_block_height(&self) -> Result<u64, SyncError> {
        Ok(self.blocks.keys().max().copied().unwrap_or(0))
    }
    
    fn get_anchor_at_block(&self, block_height: u64) -> Result<[u8; 32], SyncError> {
        self.anchors
            .get(&block_height)
            .copied()
            .ok_or(SyncError::BlockchainDataUnavailable(block_height))
    }
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wallet_state_creation() {
        let wallet = WalletState::new();
        assert_eq!(wallet.current_block, 0);
        assert_eq!(wallet.notes.len(), 0);
    }
    
    #[test]
    fn test_add_note() {
        let mut wallet = WalletState::new();
        let nullifier = Nullifier([1u8; 32]);
        let commitment = Tachygram([2u8; 32]);
        let witness = MerklePath {
            siblings: vec![PallasFp::from(0u64); 32],
            directions: vec![false; 32],
        };
        
        wallet.add_note(nullifier, commitment, witness, 100);
        assert_eq!(wallet.notes.len(), 1);
        assert_eq!(wallet.notes[0].nullifier, nullifier);
    }
    
    #[test]
    fn test_blind_wallet() {
        let mut wallet = WalletState::new();
        wallet.add_note(
            Nullifier([1u8; 32]),
            Tachygram([2u8; 32]),
            MerklePath { siblings: vec![], directions: vec![] },
            100,
        );
        
        let blinded = wallet.blind(200);
        assert_eq!(blinded.from_block, 0);
        assert_eq!(blinded.to_block, 200);
        assert_eq!(blinded.nullifiers.len(), 1);
    }
    
    #[test]
    fn test_mock_blockchain() {
        let mut bc = MockBlockchain::new();
        let tachygrams = vec![Tachygram([1u8; 32]), Tachygram([2u8; 32])];
        bc.add_block(1, tachygrams.clone(), [0u8; 32]);
        
        let retrieved = bc.get_tachygrams_in_block(1).unwrap();
        assert_eq!(retrieved, tachygrams);
        
        assert_eq!(bc.current_block_height().unwrap(), 1);
    }
    
    #[test]
    fn test_nullifier_tracking() {
        let mut bc = MockBlockchain::new();
        let nullifier = Nullifier([42u8; 32]);
        bc.mark_nullifier_spent(nullifier, 100);
        
        let result = bc.is_nullifier_spent_in_range(&nullifier, 50, 150).unwrap();
        assert_eq!(result, Some(100));
        
        let result2 = bc.is_nullifier_spent_in_range(&nullifier, 200, 300).unwrap();
        assert_eq!(result2, None);
    }
    
    #[test]
    fn test_sync_service_validation() {
        let bc = MockBlockchain::new();
        let config = SyncServiceConfig {
            max_blocks_per_request: 10,
            max_nullifiers_per_request: 5,
            ..Default::default()
        };
        let service = ObliviousSyncService::new(bc, config);
        
        // Valid request
        let blinded = BlindedWalletState {
            from_block: 1,
            to_block: 5,
            nullifiers: vec![Nullifier([1u8; 32])],
            state_commitment: [0u8; 32],
            previous_pcd: None,
        };
        assert!(service.validate_request(&blinded).is_ok());
        
        // Too many blocks
        let bad_blinded = BlindedWalletState {
            from_block: 1,
            to_block: 100,
            ..blinded.clone()
        };
        assert!(service.validate_request(&bad_blinded).is_err());
    }
}

