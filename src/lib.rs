//! Tachy-Wallet: A Tachyon Protocol Implementation
//!
//! This library implements the Tachyon scaling protocol for Zcash, including:
//! - Traditional Actions and Tachyactions (core protocol primitives)
//! - Transaction bundles with proof aggregation
//! - Oblivious synchronization for privacy-preserving wallet sync
//! - Recovery capsules for threshold-based wallet recovery
//! - Out-of-band payment envelopes
//! - ZIP-321 and ZIP-324 payment URI handling
//!
//! # Core Concepts
//!
//! ## Actions
//! Tachyon defines two action types:
//! - **Traditional Action**: Full Orchard-style action with on-chain ciphertext
//! - **Tachyaction**: Minimal authorization-only action for out-of-band payments
//!
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

// Tachystamps and note structures (require Nova)
#[cfg(feature = "tachystamps")]
pub mod tachystamps;

#[cfg(feature = "tachystamps")]
pub mod notes;

#[cfg(feature = "tachystamps")]
pub mod spend;

#[cfg(feature = "oblivious-sync")]
pub mod oblivious_sync;

#[cfg(feature = "recovery")]
pub mod recovery;

#[cfg(feature = "oob")]
pub mod oob;

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

#[cfg(feature = "tachystamps")]
pub use tachystamps::{
    Tachygram,
    TachyStepCircuit,
    Prover,
    Compressed,
    AnchorRange,
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

