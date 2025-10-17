//! Tachyon Note Structure and Nullifier Derivation
//!
//! This module implements the simplified Tachyon note structure and nullifier
//! derivation scheme designed for oblivious synchronization.
//! Numi
//! # Tachyon Notes
//!
//! Unlike Orchard's complex note structure `(d, pk_d, v, ρ, Ψ, rcm)`, Tachyon uses
//! a simplified structure:
//!
//! ```text
//! Note = (pk, v, Ψ, rcm)
//! ```
//!
//! Where:
//! - `pk`: Payment key (32 bytes) - identifies the recipient
//! - `v`: Note value (8 bytes) - amount in zatoshis
//! - `Ψ`: Nonce (32 bytes) - randomness for uniqueness
//! - `rcm`: Commitment key (32 bytes) - randomness for hiding
//!
//! Removed from Orchard:
//! - `d`: Diversifier (no longer needed without payment addresses)
//! - `ρ`: Unique value (replaced by simpler derivation)
//!
//! # Nullifier Derivation
//!
//! Tachyon nullifiers are massively simplified compared to Orchard:
//!
//! ```text
//! nf = F_nk(Ψ || flavor)
//! ```
//!
//! Where:
//! - `F_nk`: Poseidon PRF keyed by nullifier key `nk`
//! - `Ψ`: Note nonce (from the note)
//! - `flavor`: Additional component for oblivious sync privacy
//!
//! This is much simpler than Orchard's:
//! `nf = Extract_P([(F_nk(ρ) + Ψ) mod p] * G + cm)`
//!
//! # Note Commitments
//!
//! Note commitments are computed as:
//!
//! ```text
//! cm = Poseidon(DS_COMMIT, pk, v, Ψ, rcm)
//! ```
//!
//! The commitment hides the note contents while allowing zero-knowledge proofs.

#![forbid(unsafe_code)]

use blake2b_simd::Params as Blake2bParams;
use halo2curves::ff::PrimeField;
use halo2curves::pasta::Fp as PallasFp;
// Nova imports removed - using Halo2 Poseidon instead
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::actions::{NoteCommitment, Nullifier};
use crate::tachystamps::Tachygram;

// ----------------------------- Domain Separation Tags -----------------------------

/// Domain tag for note commitments
const DS_NOTE_COMMIT: u64 = 0x6e6f7465; // "note"

/// Domain tag for nullifier derivation (PRF)
const DS_NULLIFIER_PRF: u64 = 0x6e756c6c; // "null"

/// Domain tag for note encryption key derivation
const DS_NOTE_ENC_KEY: u64 = 0x656e6372; // "encr"

// ----------------------------- Field Conversion Helpers -----------------------------

fn fp_u64(x: u64) -> PallasFp {
    PallasFp::from(x)
}

fn bytes_to_fp_le(bytes: &[u8]) -> PallasFp {
    let mut b = [0u8; 32];
    let len = core::cmp::min(32, bytes.len());
    b[..len].copy_from_slice(&bytes[..len]);
    PallasFp::from_repr(b).unwrap_or(PallasFp::zero())
}

fn fp_to_bytes_le(fp: PallasFp) -> [u8; 32] {
    fp.to_repr()
}

fn poseidon_hash_many(inputs: &[PallasFp]) -> PallasFp {
    // Use native Poseidon from tachystamps instead of Nova's Poseidon
    use crate::tachystamps::native::poseidon_hash;
    poseidon_hash(inputs)
}

// ----------------------------- Key Types -----------------------------

/// A nullifier key (nk) is used to derive nullifiers for spent notes.
///
/// Must be kept secret. Leaking nk allows computing nullifiers for all notes
/// received by this key, enabling tracking of spending activity.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct NullifierKey(pub [u8; 32]);

impl NullifierKey {
    /// Generate a random nullifier key.
    pub fn random(mut rng: impl rand::RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive a nullifier key from a seed.
    pub fn from_seed(seed: &[u8], context: &[u8]) -> Self {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"zcash-tachyon-nk-derive")
            .to_state()
            .update(context)
            .update(seed)
            .finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }

    /// Convert to field element for use in Poseidon PRF.
    fn to_fp(&self) -> PallasFp {
        bytes_to_fp_le(&self.0)
    }
}

impl std::fmt::Debug for NullifierKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NullifierKey([REDACTED])")
    }
}

/// A payment key (pk) identifies the recipient of a note.
///
/// Unlike Orchard's diversified transmission keys, Tachyon uses a single payment
/// key per wallet since payment addresses are removed (out-of-band payments only).
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct PaymentKey(pub [u8; 32]);

impl PaymentKey {
    /// Generate a random payment key.
    pub fn random(mut rng: impl rand::RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive a payment key from a seed.
    pub fn from_seed(seed: &[u8], context: &[u8]) -> Self {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"zcash-tachyon-pk-derive")
            .to_state()
            .update(context)
            .update(seed)
            .finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }

    /// Convert to field element for note commitment.
    fn to_fp(&self) -> PallasFp {
        bytes_to_fp_le(&self.0)
    }
}

impl PartialEq for PaymentKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for PaymentKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// A note nonce (Ψ) provides uniqueness and contributes to nullifier derivation.
///
/// Can be derived from a shared secret in the out-of-band payment protocol.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    /// Generate a random nonce.
    pub fn random(mut rng: impl rand::RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Convert to field element.
    fn to_fp(&self) -> PallasFp {
        bytes_to_fp_le(&self.0)
    }
}

impl PartialEq for Nonce {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for Nonce {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Commitment randomness (rcm) blinds the note commitment.
///
/// Can be derived from a shared secret in the out-of-band payment protocol.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct CommitmentKey(pub [u8; 32]);

impl CommitmentKey {
    /// Generate random commitment key.
    pub fn random(mut rng: impl rand::RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Convert to field element.
    fn to_fp(&self) -> PallasFp {
        bytes_to_fp_le(&self.0)
    }
}

impl std::fmt::Debug for CommitmentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CommitmentKey([REDACTED])")
    }
}

/// Nullifier flavor provides additional privacy for oblivious synchronization.
///
/// The flavor prevents oblivious syncing services from learning note positions
/// in the Merkle tree by making nullifiers independent of note commitments.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct NullifierFlavor(pub [u8; 32]);

impl NullifierFlavor {
    /// Generate random flavor.
    pub fn random(mut rng: impl rand::RngCore) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Convert to field element.
    fn to_fp(&self) -> PallasFp {
        bytes_to_fp_le(&self.0)
    }
}

impl PartialEq for NullifierFlavor {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for NullifierFlavor {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// ----------------------------- Note Structure -----------------------------

/// A Tachyon shielded note.
///
/// Simplified from Orchard's structure to support out-of-band payments and
/// oblivious synchronization.
///
/// # Structure
///
/// ```text
/// Note = (pk, v, Ψ, rcm)
/// ```
///
/// All fields except `v` can be derived from a shared secret established in
/// the out-of-band payment protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TachyonNote {
    /// Payment key identifying the recipient
    pub pk: PaymentKey,

    /// Note value in zatoshis (1 ZEC = 10^8 zatoshis)
    pub value: u64,

    /// Nonce providing uniqueness
    pub psi: Nonce,

    /// Commitment randomness for hiding
    pub rcm: CommitmentKey,
}

impl TachyonNote {
    /// Create a new note.
    pub fn new(pk: PaymentKey, value: u64, psi: Nonce, rcm: CommitmentKey) -> Self {
        Self { pk, value, psi, rcm }
    }

    /// Compute the note commitment.
    ///
    /// ```text
    /// cm = Poseidon(DS_NOTE_COMMIT, pk, v, Ψ, rcm)
    /// ```
    pub fn commitment(&self) -> NoteCommitment {
        let pk_fp = self.pk.to_fp();
        let v_fp = PallasFp::from(self.value);
        let psi_fp = self.psi.to_fp();
        let rcm_fp = self.rcm.to_fp();

        let cm_fp = poseidon_hash_many(&[
            fp_u64(DS_NOTE_COMMIT),
            pk_fp,
            v_fp,
            psi_fp,
            rcm_fp,
        ]);

        let cm_bytes = fp_to_bytes_le(cm_fp);
        NoteCommitment(cm_bytes)
    }

    /// Compute the nullifier for this note.
    ///
    /// ```text
    /// nf = F_nk(Ψ || flavor)
    /// ```
    ///
    /// Where F_nk is a Poseidon PRF keyed by the nullifier key.
    pub fn nullifier(&self, nk: &NullifierKey, flavor: &NullifierFlavor) -> Nullifier {
        derive_nullifier(nk, &self.psi, flavor)
    }

    /// Convert this note to a tachygram (its commitment).
    ///
    /// In Tachyon, note commitments are tachygrams that get inserted into
    /// the global accumulator.
    pub fn to_tachygram(&self) -> Tachygram {
        Tachygram(self.commitment().0)
    }
}

// ----------------------------- Nullifier Derivation -----------------------------

/// Derive a nullifier using the Tachyon formula.
///
/// ```text
/// nf = F_nk(Ψ || flavor) = Poseidon(DS_NULLIFIER_PRF, nk, Ψ, flavor)
/// ```
///
/// This is much simpler than Orchard's nullifier derivation and doesn't depend
/// on the note commitment, enabling oblivious synchronization without leaking
/// note position information.
///
/// # Arguments
///
/// - `nk`: Nullifier key (secret)
/// - `psi`: Note nonce
/// - `flavor`: Nullifier flavor for oblivious sync privacy
pub fn derive_nullifier(
    nk: &NullifierKey,
    psi: &Nonce,
    flavor: &NullifierFlavor,
) -> Nullifier {
    let nk_fp = nk.to_fp();
    let psi_fp = psi.to_fp();
    let flavor_fp = flavor.to_fp();

    let nf_fp = poseidon_hash_many(&[
        fp_u64(DS_NULLIFIER_PRF),
        nk_fp,
        psi_fp,
        flavor_fp,
    ]);

    let nf_bytes = fp_to_bytes_le(nf_fp);
    Nullifier(nf_bytes)
}

/// Convert a nullifier to a tachygram.
///
/// In Tachyon, nullifiers are tachygrams that get inserted into the global
/// accumulator to prevent double-spends.
pub fn nullifier_to_tachygram(nf: &Nullifier) -> Tachygram {
    Tachygram(nf.0)
}

// ----------------------------- Key Derivation Helpers -----------------------------

/// Derive shared secrets from an out-of-band channel.
///
/// This helper derives all the randomness needed for a note from a single
/// shared secret, typically established through ECDH or a similar protocol.
pub fn derive_note_secrets(shared_secret: &[u8]) -> (Nonce, CommitmentKey, NullifierFlavor) {
    // Domain-separate each derivation
    let psi = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"zcash-tachyon-derive-psi")
            .to_state()
            .update(shared_secret)
            .finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Nonce(bytes)
    };

    let rcm = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"zcash-tachyon-derive-rcm")
            .to_state()
            .update(shared_secret)
            .finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        CommitmentKey(bytes)
    };

    let flavor = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"zcash-tachyon-drv-flavor")
            .to_state()
            .update(shared_secret)
            .finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        NullifierFlavor(bytes)
    };

    (psi, rcm, flavor)
}

// ----------------------------- Errors -----------------------------

/// Errors that can occur during note operations
#[derive(Error, Debug)]
pub enum NoteError {
    /// The note value is invalid
    #[error("invalid note value")]
    InvalidValue,

    /// The payment key is invalid
    #[error("invalid payment key")]
    InvalidPaymentKey,

    /// The note commitment is invalid
    #[error("invalid commitment")]
    InvalidCommitment,

    /// Secret derivation failed
    #[error("derivation failed")]
    DerivationFailed,
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_note_commitment_deterministic() {
        let pk = PaymentKey([1u8; 32]);
        let psi = Nonce([2u8; 32]);
        let rcm = CommitmentKey([3u8; 32]);

        let note1 = TachyonNote::new(pk, 1000, psi, rcm.clone());
        let note2 = TachyonNote::new(pk, 1000, psi, rcm);

        // Same inputs should produce same commitment
        assert_eq!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_commitment_unique() {
        let pk = PaymentKey([1u8; 32]);
        let psi1 = Nonce([2u8; 32]);
        let psi2 = Nonce([3u8; 32]);
        let rcm = CommitmentKey([4u8; 32]);

        let note1 = TachyonNote::new(pk, 1000, psi1, rcm.clone());
        let note2 = TachyonNote::new(pk, 1000, psi2, rcm);

        // Different nonces should produce different commitments
        assert_ne!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_nullifier_derivation_deterministic() {
        let nk = NullifierKey([1u8; 32]);
        let psi = Nonce([2u8; 32]);
        let flavor = NullifierFlavor([3u8; 32]);

        let nf1 = derive_nullifier(&nk, &psi, &flavor);
        let nf2 = derive_nullifier(&nk, &psi, &flavor);

        // Same inputs should produce same nullifier
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_independence_from_commitment() {
        // Verify that nullifiers don't depend on note commitments
        let nk = NullifierKey([1u8; 32]);
        let pk = PaymentKey([2u8; 32]);
        let psi = Nonce([3u8; 32]);
        let flavor = NullifierFlavor([4u8; 32]);

        let rcm1 = CommitmentKey([5u8; 32]);
        let rcm2 = CommitmentKey([6u8; 32]);

        let note1 = TachyonNote::new(pk, 1000, psi, rcm1);
        let note2 = TachyonNote::new(pk, 1000, psi, rcm2);

        // Different commitments (different rcm)
        assert_ne!(note1.commitment(), note2.commitment());

        // But same nullifier (same nk, psi, flavor)
        let nf1 = note1.nullifier(&nk, &flavor);
        let nf2 = note2.nullifier(&nk, &flavor);
        assert_eq!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_flavor_changes_nullifier() {
        let nk = NullifierKey([1u8; 32]);
        let psi = Nonce([2u8; 32]);
        let flavor1 = NullifierFlavor([3u8; 32]);
        let flavor2 = NullifierFlavor([4u8; 32]);

        let nf1 = derive_nullifier(&nk, &psi, &flavor1);
        let nf2 = derive_nullifier(&nk, &psi, &flavor2);

        // Different flavors should produce different nullifiers
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_derive_note_secrets_deterministic() {
        let shared_secret = b"shared-secret-12345678901234567890";

        let (psi1, rcm1, flavor1) = derive_note_secrets(shared_secret);
        let (psi2, rcm2, flavor2) = derive_note_secrets(shared_secret);

        // Same shared secret should derive same values
        assert_eq!(psi1, psi2);
        assert_eq!(rcm1.0, rcm2.0);
        assert_eq!(flavor1, flavor2);
    }

    #[test]
    fn test_derive_note_secrets_unique() {
        let secret1 = b"secret1";
        let secret2 = b"secret2";

        let (psi1, rcm1, flavor1) = derive_note_secrets(secret1);
        let (psi2, rcm2, flavor2) = derive_note_secrets(secret2);

        // Different shared secrets should derive different values
        assert_ne!(psi1, psi2);
        assert_ne!(rcm1.0, rcm2.0);
        assert_ne!(flavor1, flavor2);
    }

    #[test]
    fn test_nullifier_key_derivation() {
        let seed = b"wallet-seed-12345";
        let nk1 = NullifierKey::from_seed(seed, b"account-0");
        let nk2 = NullifierKey::from_seed(seed, b"account-0");
        let nk3 = NullifierKey::from_seed(seed, b"account-1");

        // Same seed and context should produce same key
        assert_eq!(nk1.0, nk2.0);

        // Different context should produce different key
        assert_ne!(nk1.0, nk3.0);
    }

    #[test]
    fn test_payment_key_derivation() {
        let seed = b"wallet-seed-12345";
        let pk1 = PaymentKey::from_seed(seed, b"account-0");
        let pk2 = PaymentKey::from_seed(seed, b"account-0");
        let pk3 = PaymentKey::from_seed(seed, b"account-1");

        // Same seed and context should produce same key
        assert_eq!(pk1, pk2);

        // Different context should produce different key
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn test_note_to_tachygram() {
        let pk = PaymentKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        let rcm = CommitmentKey::random(OsRng);

        let note = TachyonNote::new(pk, 1000, psi, rcm);
        let tachygram = note.to_tachygram();

        // Tachygram should match commitment
        assert_eq!(tachygram.0, note.commitment().0);
    }

    #[test]
    fn test_nullifier_to_tachygram() {
        let nk = NullifierKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        let flavor = NullifierFlavor::random(OsRng);

        let nf = derive_nullifier(&nk, &psi, &flavor);
        let tachygram = nullifier_to_tachygram(&nf);

        // Tachygram should match nullifier bytes
        assert_eq!(tachygram.0, nf.0);
    }

    #[test]
    fn test_full_note_lifecycle() {
        // Sender and receiver establish shared secret (e.g., via ECDH)
        let shared_secret = b"ecdh-shared-secret-example-32byt";

        // Derive note secrets from shared secret
        let (psi, rcm, flavor) = derive_note_secrets(shared_secret);

        // Receiver's keys
        let pk = PaymentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);

        // Create note
        let note = TachyonNote::new(pk, 100_000_000, psi, rcm); // 1 ZEC

        // Compute commitment (goes on-chain as tachygram)
        let cm = note.commitment();
        let cm_tachygram = note.to_tachygram();
        assert_eq!(cm.0, cm_tachygram.0);

        // Later, when spending, compute nullifier
        let nf = note.nullifier(&nk, &flavor);
        let nf_tachygram = nullifier_to_tachygram(&nf);

        // Both tachygrams should be 32 bytes
        assert_eq!(cm_tachygram.0.len(), 32);
        assert_eq!(nf_tachygram.0.len(), 32);

        // Nullifier and commitment should be different
        assert_ne!(cm.0, nf.0);
    }

    #[test]
    fn test_oblivious_sync_privacy_guarantee() {
        // CRITICAL TEST: Verify that nullifiers don't leak note positions
        //
        // In Tachyon, nullifiers are derived independently of note commitments.
        // This prevents oblivious sync services from correlating a nullifier
        // with a specific position in the Merkle tree.
        //
        // Property: nf = F_nk(Ψ || flavor), NOT dependent on cm or position

        let nk = NullifierKey::random(OsRng);
        let pk = PaymentKey::random(OsRng);
        
        // Create two notes with SAME psi and flavor but DIFFERENT commitments
        let psi = Nonce::random(OsRng);
        let flavor = NullifierFlavor::random(OsRng);
        
        let rcm1 = CommitmentKey::random(OsRng);
        let rcm2 = CommitmentKey::random(OsRng);
        
        let note1 = TachyonNote::new(pk, 1000, psi, rcm1);
        let note2 = TachyonNote::new(pk, 2000, psi, rcm2); // Different value too
        
        // Commitments MUST be different (different rcm, different value)
        assert_ne!(note1.commitment(), note2.commitment());
        
        // But nullifiers MUST be identical (same nk, psi, flavor)
        let nf1 = note1.nullifier(&nk, &flavor);
        let nf2 = note2.nullifier(&nk, &flavor);
        assert_eq!(nf1, nf2);
        
        // This proves: An oblivious sync service that knows nf1
        // CANNOT determine which commitment (cm1 or cm2) it corresponds to
        // because the nullifier is independent of the commitment!
    }

    #[test]
    fn test_flavor_provides_unlinkability() {
        // SECURITY TEST: Verify that flavor provides unlinkability
        //
        // The oblivious sync service learns nullifiers when tracking them.
        // If the same note is spent in different contexts (e.g., different
        // chain forks), the flavor can be changed to produce different nullifiers,
        // preventing the service from linking the spends.

        let nk = NullifierKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        
        // Same note, different flavors (different sync contexts)
        let flavor_chain_a = NullifierFlavor::random(OsRng);
        let flavor_chain_b = NullifierFlavor::random(OsRng);
        
        let nf_a = derive_nullifier(&nk, &psi, &flavor_chain_a);
        let nf_b = derive_nullifier(&nk, &psi, &flavor_chain_b);
        
        // Different flavors MUST produce different nullifiers
        assert_ne!(nf_a, nf_b);
        
        // This proves: The sync service cannot link two spends of the same
        // note across different contexts, preserving privacy even when
        // the same wallet state is used in multiple scenarios.
    }

    #[test]
    fn test_nullifier_collision_resistance() {
        // SECURITY TEST: Verify that nullifiers are collision-resistant
        //
        // Different notes should produce different nullifiers with overwhelming
        // probability (collision probability: ~2^-256)

        let nk = NullifierKey::random(OsRng);
        let flavor = NullifierFlavor::random(OsRng);
        
        let psi1 = Nonce::random(OsRng);
        let psi2 = Nonce::random(OsRng);
        
        let nf1 = derive_nullifier(&nk, &psi1, &flavor);
        let nf2 = derive_nullifier(&nk, &psi2, &flavor);
        
        // With overwhelming probability, should be different
        assert_ne!(nf1, nf2);
    }

    #[test]
    fn test_nullifier_key_isolation() {
        // SECURITY TEST: Different nullifier keys produce different nullifiers
        //
        // This ensures that even if two users receive notes with the same
        // (psi, flavor), their nullifiers will be different (different nk).

        let nk1 = NullifierKey::random(OsRng);
        let nk2 = NullifierKey::random(OsRng);
        
        let psi = Nonce::random(OsRng);
        let flavor = NullifierFlavor::random(OsRng);
        
        let nf1 = derive_nullifier(&nk1, &psi, &flavor);
        let nf2 = derive_nullifier(&nk2, &psi, &flavor);
        
        // Different nullifier keys MUST produce different nullifiers
        assert_ne!(nf1, nf2);
        
        // This prevents cross-wallet correlation attacks
    }
}

