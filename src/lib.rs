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

// Tachystamps and note structures (require Nova)
#[cfg(feature = "tachystamps")]
pub mod tachystamps;

#[cfg(feature = "tachystamps")]
pub mod proof_aggregation;

#[cfg(feature = "tachystamps")]
pub mod incremental_merkle;

#[cfg(feature = "tachystamps")]
pub mod notes;

#[cfg(feature = "tachystamps")]
pub mod spend;

#[cfg(feature = "oblivious-sync")]
pub mod oblivious_sync;

#[cfg(feature = "oblivious-sync")]
pub mod blockchain_provider;

#[cfg(feature = "recovery")]
pub mod recovery;

#[cfg(feature = "oob")]
pub mod oob;

// Persistence layer
pub mod persistence;
pub mod status_db;

// ZIP modules (mostly working)
pub mod zip321;

#[cfg(feature = "zip324-full")]
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

#[cfg(feature = "tachystamps")]
pub use tachystamps::{
    Tachygram,
    TachyStepCircuit,
    Prover,
    Compressed,
    AnchorRange,
};

#[cfg(feature = "tachystamps")]
pub use proof_aggregation::{
    AggregateProof,
    ProofBatch,
    TransactionMetadata,
    ContextPolicy,
    ProofVerifier,
    NoopVerifier,
    CryptographicVerifier,
    AggregationError,
    aggregate_proofs,
    aggregate_proofs_with_verifier,
    aggregate_proofs_with_verifier_and_policy,
    verify_aggregate,
    verify_aggregate_full,
    get_tx_authorized_pairs,
};

#[cfg(feature = "tachystamps")]
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

#[cfg(feature = "tachystamps")]
pub use spend::{
    SpendContext,
    OutputContext,
    TachyonTxBuilder,
    create_simple_payment,
    create_shielding_tx,
    create_deshielding_tx,
};

#[cfg(feature = "oblivious-sync")]
pub use oblivious_sync::{
    WalletState,
    NoteState,
    WalletSynchronizer,
    SyncRequest,
    SyncResponse,
    BlockchainProvider,
};

#[cfg(feature = "oblivious-sync")]
pub use blockchain_provider::{
    RpcBlockchainProvider,
    CachedBlockchainProvider,
    RpcConfig,
};

