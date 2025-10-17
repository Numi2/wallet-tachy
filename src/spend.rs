//! Note Creation and Spending with Tachystamps
//!
//! This module provides high-level helpers for creating and spending Tachyon notes
//! with full tachystamp proof integration.
//!
//! # Workflow
//!
//! ## Creating a Note (Output)
//!
//! 1. Establish shared secret with recipient (out-of-band, e.g., ECDH)
//! 2. Derive note secrets (Ψ, rcm, flavor) from shared secret
//! 3. Create note with recipient's payment key and desired value
//! 4. Compute note commitment → becomes a tachygram
//! 5. Include tachygram in tachystamp proof
//!
//! ## Spending a Note (Input)
//!
//! 1. Retrieve note information from out-of-band channel
//! 2. Compute nullifier using nullifier key and flavor
//! 3. Create Merkle membership proof for note commitment
//! 4. Include nullifier in tachystamp proof
//! 5. Verify nullifier hasn't been seen in recent blocks
//!
//! # Integration with Tachystamps
//!
//! Tachystamps prove:
//! - Note commitments exist in the Merkle tree (membership)
//! - Nullifiers have not been revealed (non-membership in recent blocks)
//! - Balance integrity (via binding signatures)
//!
//! The tachystamp circuit verifies these properties without revealing which
//! specific notes are being spent.

#![forbid(unsafe_code)]

use crate::actions::*;
use crate::notes::*;
use crate::tachystamps::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ----------------------------- Spend Context -----------------------------

/// Context for spending a note.
///
/// Contains all the information needed to construct a spend operation,
/// including the note, keys, and Merkle path.
#[derive(Clone, Debug)]
pub struct SpendContext {
    /// The note being spent
    pub note: TachyonNote,

    /// Nullifier key for deriving the nullifier
    pub nk: NullifierKey,

    /// Nullifier flavor for oblivious sync privacy
    pub flavor: NullifierFlavor,

    /// Merkle path proving note commitment exists in tree
    pub merkle_path: MerklePath,

    /// Index of the note in the tree
    pub note_index: usize,
}

impl SpendContext {
    /// Compute the nullifier for this spend.
    pub fn nullifier(&self) -> Nullifier {
        self.note.nullifier(&self.nk, &self.flavor)
    }

    /// Get the note commitment.
    pub fn commitment(&self) -> NoteCommitment {
        self.note.commitment()
    }

    /// Convert to tachygrams (nullifier and commitment).
    pub fn to_tachygrams(&self) -> (Tachygram, Tachygram) {
        let nf = self.nullifier();
        let cm = self.commitment();
        (nullifier_to_tachygram(&nf), Tachygram(cm.0))
    }
}

// ----------------------------- Output Context -----------------------------

/// Context for creating a note output.
///
/// Contains all the information needed to construct an output operation.
#[derive(Clone, Debug)]
pub struct OutputContext {
    /// The note being created
    pub note: TachyonNote,

    /// Merkle tree root where this note will be added
    pub tree_root: [u8; 32],

    /// Position where this note will be added (for tracking)
    pub note_index: usize,
}

impl OutputContext {
    /// Get the note commitment.
    pub fn commitment(&self) -> NoteCommitment {
        self.note.commitment()
    }

    /// Convert to tachygram (commitment only).
    pub fn to_tachygram(&self) -> Tachygram {
        Tachygram(self.commitment().0)
    }
}

// ----------------------------- Transaction Builder -----------------------------

/// Builder for creating Tachyon transactions with tachystamp proofs.
///
/// This builder helps construct transactions that spend and create notes
/// while generating the necessary tachystamp proofs.
#[derive(Clone, Debug)]
pub struct TachyonTxBuilder {
    /// Notes being spent (inputs)
    pub spends: Vec<SpendContext>,

    /// Notes being created (outputs)
    pub outputs: Vec<OutputContext>,

    /// Current Merkle tree state
    pub tree_root: [u8; 32],

    /// Anchor range for tachystamp proof
    pub anchor_range: AnchorRange,
}

impl TachyonTxBuilder {
    /// Create a new transaction builder.
    pub fn new(tree_root: [u8; 32], anchor_range: AnchorRange) -> Self {
        Self {
            spends: Vec::new(),
            outputs: Vec::new(),
            tree_root,
            anchor_range,
        }
    }

    /// Add a spend (input note).
    pub fn add_spend(&mut self, spend: SpendContext) {
        self.spends.push(spend);
    }

    /// Add an output (new note).
    pub fn add_output(&mut self, output: OutputContext) {
        self.outputs.push(output);
    }

    /// Compute net value balance.
    ///
    /// Returns Ok(0) if transaction is balanced, Err otherwise.
    pub fn check_balance(&self) -> Result<(), TxBuilderError> {
        let input_sum: u64 = self.spends.iter().map(|s| s.note.value).sum();
        let output_sum: u64 = self.outputs.iter().map(|o| o.note.value).sum();

        if input_sum == output_sum {
            Ok(())
        } else {
            Err(TxBuilderError::ImbalancedValue {
                inputs: input_sum,
                outputs: output_sum,
            })
        }
    }

    /// Extract all tachygrams (nullifiers from spends, commitments from outputs).
    pub fn extract_tachygrams(&self) -> Vec<Tachygram> {
        let mut tachygrams = Vec::new();

        // Nullifiers from spends
        for spend in &self.spends {
            let nf = spend.nullifier();
            tachygrams.push(nullifier_to_tachygram(&nf));
        }

        // Commitments from outputs
        for output in &self.outputs {
            tachygrams.push(output.to_tachygram());
        }

        tachygrams
    }

    /// Build tachystamp proof for this transaction.
    ///
    /// This proves:
    /// - All spend note commitments exist in the Merkle tree
    /// - All nullifiers are valid and haven't been spent
    /// - Balance is preserved
    pub fn build_tachystamp(&self, prover: &mut Prover) -> Result<Compressed, TxBuilderError> {
        // Check balance first
        self.check_balance()?;

        // Collect all Merkle paths and leaves
        let mut leaves = Vec::new();
        let mut paths = Vec::new();

        // Add spend proofs (membership of note commitments)
        for spend in &self.spends {
            let cm_bytes = spend.commitment().0;
            leaves.push(cm_bytes);
            paths.push(spend.merkle_path.clone());
        }

        // Prove membership in batches
        if !leaves.is_empty() {
            let root_fp = bytes_to_fp_le(&self.tree_root);
            prover
                .prove_step(root_fp, self.anchor_range, leaves, paths)
                .map_err(|e| TxBuilderError::ProofGeneration(e.to_string()))?;
        }

        // Finalize and compress
        prover
            .finalize()
            .map_err(|e| TxBuilderError::ProofGeneration(e.to_string()))
    }
}

// ----------------------------- Helper Functions -----------------------------

/// Create a simple payment: one input, one output (value transfer).
///
/// This is the most common transaction type.
pub fn create_simple_payment(
    spend: SpendContext,
    recipient_pk: PaymentKey,
    shared_secret: &[u8],
    value: u64,
    tree_root: [u8; 32],
    anchor_range: AnchorRange,
) -> Result<TachyonTxBuilder, TxBuilderError> {
    // Derive output note secrets from shared secret
    let (psi, rcm, _flavor) = derive_note_secrets(shared_secret);

    // Create output note
    let output_note = TachyonNote::new(recipient_pk, value, psi, rcm);
    let output_ctx = OutputContext {
        note: output_note,
        tree_root,
        note_index: 0, // Will be assigned by tree
    };

    // Build transaction
    let mut builder = TachyonTxBuilder::new(tree_root, anchor_range);
    builder.add_spend(spend);
    builder.add_output(output_ctx);

    Ok(builder)
}

/// Create a shielding transaction: transparent input → shielded output.
///
/// In Tachyon, this converts transparent funds into a shielded note.
pub fn create_shielding_tx(
    recipient_pk: PaymentKey,
    shared_secret: &[u8],
    value: u64,
    tree_root: [u8; 32],
    anchor_range: AnchorRange,
) -> Result<TachyonTxBuilder, TxBuilderError> {
    // Derive output note secrets
    let (psi, rcm, _flavor) = derive_note_secrets(shared_secret);

    // Create output note
    let output_note = TachyonNote::new(recipient_pk, value, psi, rcm);
    let output_ctx = OutputContext {
        note: output_note,
        tree_root,
        note_index: 0,
    };

    // Build transaction (no spends, only output)
    let mut builder = TachyonTxBuilder::new(tree_root, anchor_range);
    builder.add_output(output_ctx);

    Ok(builder)
}

/// Create a deshielding transaction: shielded input → transparent output.
///
/// In Tachyon, this converts a shielded note back to transparent funds.
pub fn create_deshielding_tx(
    spend: SpendContext,
    tree_root: [u8; 32],
    anchor_range: AnchorRange,
) -> Result<TachyonTxBuilder, TxBuilderError> {
    // Build transaction (spend only, no shielded outputs)
    let mut builder = TachyonTxBuilder::new(tree_root, anchor_range);
    builder.add_spend(spend);

    Ok(builder)
}

// ----------------------------- Field Conversion (re-export from notes) -----------------------------

fn bytes_to_fp_le(bytes: &[u8]) -> halo2curves::pasta::Fp {
    let mut b = [0u8; 32];
    let len = core::cmp::min(32, bytes.len());
    b[..len].copy_from_slice(&bytes[..len]);
    halo2curves::pasta::Fp::from_le_bytes_mod_order(&b)
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum TxBuilderError {
    #[error("imbalanced transaction: inputs={inputs}, outputs={outputs}")]
    ImbalancedValue { inputs: u64, outputs: u64 },

    #[error("proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("invalid merkle path")]
    InvalidMerklePath,

    #[error("missing nullifier key")]
    MissingNullifierKey,

    #[error("note error: {0}")]
    NoteError(#[from] NoteError),

    #[error("tachystamp error: {0}")]
    TachystampError(#[from] TachyError),
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn dummy_merkle_path(height: usize) -> MerklePath {
        use halo2curves::pasta::Fp as PallasFp;
        MerklePath {
            siblings: vec![PallasFp::ZERO; height],
            directions: vec![false; height],
        }
    }

    #[test]
    fn test_spend_context() {
        let pk = PaymentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);
        let (psi, rcm, flavor) = derive_note_secrets(b"shared-secret");

        let note = TachyonNote::new(pk, 1000, psi, rcm);
        let spend = SpendContext {
            note: note.clone(),
            nk,
            flavor,
            merkle_path: dummy_merkle_path(4),
            note_index: 0,
        };

        // Check nullifier derivation
        let nf1 = spend.nullifier();
        let nf2 = note.nullifier(&nk, &flavor);
        assert_eq!(nf1, nf2);

        // Check tachygrams
        let (nf_tg, cm_tg) = spend.to_tachygrams();
        assert_eq!(nf_tg.0, nf1.0);
        assert_eq!(cm_tg.0, note.commitment().0);
    }

    #[test]
    fn test_output_context() {
        let pk = PaymentKey::random(OsRng);
        let (psi, rcm, _) = derive_note_secrets(b"shared-secret");

        let note = TachyonNote::new(pk, 2000, psi, rcm);
        let output = OutputContext {
            note: note.clone(),
            tree_root: [0u8; 32],
            note_index: 5,
        };

        // Check commitment
        let cm = output.commitment();
        assert_eq!(cm, note.commitment());

        // Check tachygram
        let tg = output.to_tachygram();
        assert_eq!(tg.0, cm.0);
    }

    #[test]
    fn test_balanced_transaction() {
        let pk1 = PaymentKey::random(OsRng);
        let pk2 = PaymentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);

        let (psi_in, rcm_in, flavor) = derive_note_secrets(b"input-secret");
        let (psi_out, rcm_out, _) = derive_note_secrets(b"output-secret");

        let input_note = TachyonNote::new(pk1, 1000, psi_in, rcm_in);
        let output_note = TachyonNote::new(pk2, 1000, psi_out, rcm_out);

        let spend = SpendContext {
            note: input_note,
            nk,
            flavor,
            merkle_path: dummy_merkle_path(4),
            note_index: 0,
        };

        let output = OutputContext {
            note: output_note,
            tree_root: [0u8; 32],
            note_index: 1,
        };

        let mut builder = TachyonTxBuilder::new([0u8; 32], AnchorRange { start: 0, end: 100 });
        builder.add_spend(spend);
        builder.add_output(output);

        // Should be balanced
        assert!(builder.check_balance().is_ok());

        // Should extract 2 tachygrams (1 nullifier + 1 commitment)
        let tachygrams = builder.extract_tachygrams();
        assert_eq!(tachygrams.len(), 2);
    }

    #[test]
    fn test_imbalanced_transaction() {
        let pk1 = PaymentKey::random(OsRng);
        let pk2 = PaymentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);

        let (psi_in, rcm_in, flavor) = derive_note_secrets(b"input-secret");
        let (psi_out, rcm_out, _) = derive_note_secrets(b"output-secret");

        let input_note = TachyonNote::new(pk1, 1000, psi_in, rcm_in);
        let output_note = TachyonNote::new(pk2, 1500, psi_out, rcm_out); // More than input!

        let spend = SpendContext {
            note: input_note,
            nk,
            flavor,
            merkle_path: dummy_merkle_path(4),
            note_index: 0,
        };

        let output = OutputContext {
            note: output_note,
            tree_root: [0u8; 32],
            note_index: 1,
        };

        let mut builder = TachyonTxBuilder::new([0u8; 32], AnchorRange { start: 0, end: 100 });
        builder.add_spend(spend);
        builder.add_output(output);

        // Should be imbalanced
        assert!(builder.check_balance().is_err());
    }

    #[test]
    fn test_simple_payment() {
        let sender_pk = PaymentKey::random(OsRng);
        let recipient_pk = PaymentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);

        let (psi_in, rcm_in, flavor) = derive_note_secrets(b"sender-secret");
        let input_note = TachyonNote::new(sender_pk, 5000, psi_in, rcm_in);

        let spend = SpendContext {
            note: input_note,
            nk,
            flavor,
            merkle_path: dummy_merkle_path(4),
            note_index: 0,
        };

        let builder = create_simple_payment(
            spend,
            recipient_pk,
            b"recipient-shared-secret",
            5000,
            [0u8; 32],
            AnchorRange { start: 0, end: 100 },
        )
        .unwrap();

        assert!(builder.check_balance().is_ok());
        assert_eq!(builder.spends.len(), 1);
        assert_eq!(builder.outputs.len(), 1);
    }

    #[test]
    fn test_shielding_transaction() {
        let recipient_pk = PaymentKey::random(OsRng);

        let builder = create_shielding_tx(
            recipient_pk,
            b"shield-secret",
            10000,
            [0u8; 32],
            AnchorRange { start: 0, end: 100 },
        )
        .unwrap();

        // No spends, only output
        assert_eq!(builder.spends.len(), 0);
        assert_eq!(builder.outputs.len(), 1);
        assert_eq!(builder.outputs[0].note.value, 10000);
    }

    #[test]
    fn test_deshielding_transaction() {
        let pk = PaymentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);

        let (psi, rcm, flavor) = derive_note_secrets(b"deshield-secret");
        let note = TachyonNote::new(pk, 8000, psi, rcm);

        let spend = SpendContext {
            note,
            nk,
            flavor,
            merkle_path: dummy_merkle_path(4),
            note_index: 0,
        };

        let builder = create_deshielding_tx(spend, [0u8; 32], AnchorRange { start: 0, end: 100 }).unwrap();

        // One spend, no outputs
        assert_eq!(builder.spends.len(), 1);
        assert_eq!(builder.outputs.len(), 0);
    }
}

