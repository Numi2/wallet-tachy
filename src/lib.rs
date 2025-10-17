//! Tachy-Wallet: A Tachyon Protocol Implementation
//! Goals = 
//! - Traditional Actions and Tachyactions (core protocol primitives)
//! - Transaction bundles with proof aggregation
//! - Oblivious synchronization for privacy-preserving wallet sync
//! - Recovery capsules for threshold-based wallet recovery
//! - Out-of-band payment envelopes
//! - ZIP-321 and ZIP-324 payment URI handling
//!
//! # Core Concepts
//
//! ## Tachygrams
//! Unified 32-byte blobs representing either nullifiers or note commitments.
//! The protocol treats them identically, simplifying the accumulator design.
//!
//! ## Proof-Carrying Data (PCD)
//! Wallet state carries its own validity proof, reducing validator burden and
//! enabling state pruning.
//!
//! ## Oblivious Synchronization
//! Wallets can outsource expensive sync work to untrusted services without
//! revealing private information.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::too_many_arguments)]

// Core protocol modules (fully implemented)
pub mod actions;
pub mod bundle;
pub mod value_commit;
pub mod key_randomization;
pub mod note_encryption;
pub mod batch_verify;

// Poseidon chip for Halo2
pub mod poseidon_chip;

// Tachystamps with Halo2 (always enabled)
pub mod tachystamps;

// Proof aggregation (needs rewrite for current nova-snark version)
// pub mod proof_aggregation;

// Core tachystamp modules (always enabled)
pub mod incremental_merkle;
pub mod notes;
pub mod spend;

// Oblivious synchronization (always enabled)
pub mod oblivious_sync;
pub mod blockchain_provider;

/// Recovery mechanisms for wallet state including threshold guardians
pub mod recovery;

// Out-of-band payments (needs full orchard integration - temporarily disabled)
// pub mod oob;

// Persistence layer
pub mod persistence;
pub mod status_db;

// ZIP modules (mostly working)
/// ZIP-321 Payment Request URI encoding and decoding
pub mod zip321;

/// ZIP-324 Ephemeral payment capabilities
pub mod zip324;

// Re-export commonly used types
pub use actions::{
    Nullifier,
    NoteCommitment,
    ValueCommitment,
    RandomizedVerifyingKey,
    RedPallasSignature,
    EphemeralPublicKey,
    TraditionalAction,
    Tachyaction,
    VerificationError,
    verify_traditional_action,
    verify_tachyaction,
};

pub use bundle::{
    TachyBundle,
    TachystampReference,
    BindingSignature,
    verify_bundle,
};

pub use key_randomization::{
    SpendAuthorizationKey,
    SpendAuthorizationVerifyingKey,
    Randomizer,
    RandomizedSigningKey,
    create_randomized_keypair,
    verify_with_randomized_key,
};

pub use note_encryption::{
    NotePlaintext,
    IncomingViewingKey,
    DiversifiedTransmissionKey,
    EphemeralSecretKey,
    encrypt_note,
    decrypt_note,
    NOTE_PLAINTEXT_SIZE,
    ENCRYPTED_NOTE_SIZE,
    MEMO_SIZE,
};

pub use batch_verify::{
    BatchVerifier,
    batch_verify_signatures,
};

// Tachystamps (always enabled)
pub use tachystamps::{
    Tachygram,
    TachyStepCircuit,
    Prover,
    Compressed,
    AnchorRange,
};

// Notes (always enabled)
pub use notes::{
    TachyonNote,
    PaymentKey,
    NullifierKey,
    Nonce,
    CommitmentKey,
    NullifierFlavor,
    derive_nullifier,
    nullifier_to_tachygram,
    derive_note_secrets,
};

// Spend (always enabled)
pub use spend::{
    SpendContext,
    OutputContext,
    TachyonTxBuilder,
    create_simple_payment,
    create_shielding_tx,
    create_deshielding_tx,
};

// Oblivious sync (always enabled)
pub use oblivious_sync::{
    WalletState,
    NoteState,
    WalletSynchronizer,
    SyncRequest,
    SyncResponse,
    BlockchainProvider,
};

// Blockchain provider (always enabled)
pub use blockchain_provider::{
    RpcBlockchainProvider,
    CachedBlockchainProvider,
    RpcConfig,
};

