//! Traditional Actions and Tachyactions
//!
//! This module implements the two action shapes specified in the Tachyon protocol:
//!
//! 1. **Traditional Action**: Compatible with Orchard, includes on-chain ciphertext
//! 2. **Tachyaction**: Minimal authorization-only action for out-of-band payments
//!
//! Both action types produce a `(cv_net, rk)` pair and are authorized by a RedPallas
//! signature. The key difference is that Tachyactions delegate note tracking to
//! proof-carrying data (tachystamps) rather than on-chain commitments.
//!
//! # Security Requirements
//!
//! - Domain-separated signature digests prevent cross-type malleability
//! - Constant-time comparisons for all fixed-size fields
//! - No aliasing of curve types in public APIs
//! - RedPallas signature verification with proper randomization

#![forbid(unsafe_code)]

use blake2b_simd::Params as Blake2bParams;
use reddsa::{Signature, SigningKey, VerificationKey};
use reddsa::orchard::SpendAuth;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

// ----------------------------- Domain Separation Tags -----------------------------

/// Domain tag for Traditional Action signature digests
const DS_TRADITIONAL_ACTION: &[u8] = b"zcash-tachyon-trad-action-v1";

/// Domain tag for Tachyaction signature digests
const DS_TACHYACTION: &[u8] = b"zcash-tachyon-tachyaction-v1";

/// Domain tag for binding signature
const DS_BINDING_SIG: &[u8] = b"zcash-tachyon-binding-sig-v1";

// ----------------------------- Fixed-Size Newtypes -----------------------------

/// A nullifier is a unique 32-byte identifier for a spent note.
///
/// In Tachyon, nullifiers are derived such that they do NOT reveal the note's
/// position in the Merkle tree (unlike traditional Zcash). This enables oblivious
/// synchronization without leaking note locations to sync services.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct Nullifier(pub [u8; 32]);

impl PartialEq for Nullifier {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for Nullifier {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// A note commitment (cmX) is a 32-byte commitment to a shielded note.
///
/// In Tachyon, both note commitments and nullifiers are unified as "tachygrams"
/// and treated identically by the consensus protocol.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub [u8; 32]);

impl PartialEq for NoteCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for NoteCommitment {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// A value commitment (cv_net) is a 32-byte Pedersen commitment to the net value
/// of an action (value_in - value_out).
///
/// Homomorphic properties allow summing commitments to verify balance integrity:
/// Σ cv_net = 0 (modulo binding signature adjustment).
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct ValueCommitment(pub [u8; 32]);

impl PartialEq for ValueCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for ValueCommitment {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// A randomized verifying key (rk) is the public key used to verify the action's
/// authorization signature.
///
/// Derived by re-randomizing the spend authorization key: rk = ak + [α]G
/// This provides unlinkability across transactions while maintaining security.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct RandomizedVerifyingKey(pub [u8; 32]);

impl PartialEq for RandomizedVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for RandomizedVerifyingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// A RedPallas signature over the SpendAuth context.
///
/// 64 bytes: (R, s) where R is a curve point and s is a scalar.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct RedPallasSignature(pub [u8; 64]);

impl PartialEq for RedPallasSignature {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for RedPallasSignature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// An ephemeral public key (epk) used for note encryption in Traditional Actions.
///
/// Derived ephemerally per action to enable ECDH key agreement with the recipient.
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct EphemeralPublicKey(pub [u8; 32]);

impl PartialEq for EphemeralPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for EphemeralPublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// ----------------------------- Errors -----------------------------

/// Errors that can occur during action verification.
#[derive(Error, Debug)]
pub enum VerificationError {
    /// Signature verification failed
    #[error("signature verification failed")]
    InvalidSignature,
    
    /// Nullifier was already seen (double-spend attempt)
    #[error("nullifier already spent")]
    NullifierAlreadySpent,
    
    /// Note commitment is invalid
    #[error("invalid note commitment")]
    InvalidCommitment,
    
    /// Value commitment is invalid
    #[error("invalid value commitment")]
    InvalidValueCommitment,
    
    /// Anchor is not recognized
    #[error("unknown anchor")]
    UnknownAnchor,
    
    /// Tachystamp proof verification failed
    #[error("tachystamp proof invalid")]
    InvalidTachystamp,
    
    /// Field length is incorrect
    #[error("incorrect field length")]
    FieldLength,
    
    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ----------------------------- Traditional Action -----------------------------

/// A Traditional Action represents a complete Orchard-style shielded operation.
///
/// Traditional Actions include on-chain ciphertext for note recovery from the
/// blockchain, making them compatible with legacy Zcash wallets.
///
/// # Fields (Signature Digest)
/// - `nf`: Nullifier of the note being spent
/// - `cmX`: Note commitment being created
/// - `cv_net`: Net value commitment
/// - `rk`: Randomized verifying key
/// - `epk`: Ephemeral public key for note encryption
///
/// # Fields (Authorization)
/// - `sig`: RedPallas signature over the signature digest
///
/// # Fields (Payload)
/// - `ciphertext`: Encrypted note plaintext (not signed)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraditionalAction {
    /// Nullifier of note being spent
    pub nf: Nullifier,
    
    /// Note commitment being created
    pub cmX: NoteCommitment,
    
    /// Net value commitment (homomorphic)
    pub cv_net: ValueCommitment,
    
    /// Randomized verifying key
    pub rk: RandomizedVerifyingKey,
    
    /// Authorization signature
    pub sig: RedPallasSignature,
    
    /// Ephemeral public key for encryption
    pub epk: EphemeralPublicKey,
    
    /// Encrypted note plaintext (for on-chain recovery)
    pub ciphertext: Vec<u8>,
}

impl TraditionalAction {
    /// Compute the signature digest for this action.
    ///
    /// The digest includes all fields except `sig` and `ciphertext`.
    /// Domain-separated with tag "zcash-tachyon-trad-action-v1".
    ///
    /// # Arguments
    /// - `binding_data`: Additional context (e.g., anchor, tx_hash) to bind the signature
    pub fn signature_digest(&self, binding_data: &[u8]) -> [u8; 64] {
        compute_traditional_signature_digest(
            &self.nf,
            &self.cmX,
            &self.cv_net,
            &self.rk,
            &self.epk,
            binding_data,
        )
    }
    
    /// Serialize this action to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 32 + 32 + 64 + 32 + 4 + self.ciphertext.len());
        buf.extend_from_slice(&self.nf.0);
        buf.extend_from_slice(&self.cmX.0);
        buf.extend_from_slice(&self.cv_net.0);
        buf.extend_from_slice(&self.rk.0);
        buf.extend_from_slice(&self.sig.0);
        buf.extend_from_slice(&self.epk.0);
        // Length-prefix ciphertext
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf
    }
    
    /// Deserialize an action from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerificationError> {
        if bytes.len() < 32 + 32 + 32 + 32 + 64 + 32 + 4 {
            return Err(VerificationError::FieldLength);
        }
        
        let mut cursor = 0;
        
        let mut nf = [0u8; 32];
        nf.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        
        let mut cmX = [0u8; 32];
        cmX.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        
        let mut cv_net = [0u8; 32];
        cv_net.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[cursor..cursor + 64]);
        cursor += 64;
        
        let mut epk = [0u8; 32];
        epk.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        
        let ct_len = u32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        cursor += 4;
        
        if bytes.len() < cursor + ct_len {
            return Err(VerificationError::FieldLength);
        }
        
        let ciphertext = bytes[cursor..cursor + ct_len].to_vec();
        
        Ok(Self {
            nf: Nullifier(nf),
            cmX: NoteCommitment(cmX),
            cv_net: ValueCommitment(cv_net),
            rk: RandomizedVerifyingKey(rk),
            sig: RedPallasSignature(sig),
            epk: EphemeralPublicKey(epk),
            ciphertext,
        })
    }
}

// ----------------------------- Tachyaction -----------------------------

/// A Tachyaction is a minimal authorization-only action for out-of-band payments.
///
/// Tachyactions omit on-chain ciphertext and explicit note commitments/nullifiers,
/// delegating note tracking to proof-carrying data (tachystamps). This dramatically
/// reduces transaction size while maintaining privacy and security.
///
/// # Fields (Signature Digest)
/// - `cv_net`: Net value commitment
/// - `rk`: Randomized verifying key
///
/// # Fields (Authorization)
/// - `sig`: RedPallas signature over the signature digest
///
/// The actual note commitments and nullifiers are carried in the tachystamp proof,
/// which is verified separately by checking it against the `(cv_net, rk)` pairs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tachyaction {
    /// Net value commitment (homomorphic)
    pub cv_net: ValueCommitment,
    
    /// Randomized verifying key
    pub rk: RandomizedVerifyingKey,
    
    /// Authorization signature
    pub sig: RedPallasSignature,
}

impl Tachyaction {
    /// Compute the signature digest for this tachyaction.
    ///
    /// The digest includes only `cv_net` and `rk` (minimal authorization context).
    /// Domain-separated with tag "zcash-tachyon-tachyaction-v1".
    ///
    /// # Arguments
    /// - `binding_data`: Additional context to bind the signature
    pub fn signature_digest(&self, binding_data: &[u8]) -> [u8; 64] {
        compute_tachyaction_signature_digest(&self.cv_net, &self.rk, binding_data)
    }
    
    /// Serialize this tachyaction to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 64);
        buf.extend_from_slice(&self.cv_net.0);
        buf.extend_from_slice(&self.rk.0);
        buf.extend_from_slice(&self.sig.0);
        buf
    }
    
    /// Deserialize a tachyaction from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerificationError> {
        if bytes.len() != 32 + 32 + 64 {
            return Err(VerificationError::FieldLength);
        }
        
        let mut cv_net = [0u8; 32];
        cv_net.copy_from_slice(&bytes[0..32]);
        
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&bytes[32..64]);
        
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[64..128]);
        
        Ok(Self {
            cv_net: ValueCommitment(cv_net),
            rk: RandomizedVerifyingKey(rk),
            sig: RedPallasSignature(sig),
        })
    }
}

// ----------------------------- Signature Digest Construction -----------------------------

/// Compute the signature digest for a Traditional Action.
///
/// Uses BLAKE2b-512 with domain separation tag "zcash-tachyon-trad-action-v1".
///
/// # Inputs
/// All fields except `sig` and `ciphertext` are included in the digest.
fn compute_traditional_signature_digest(
    nf: &Nullifier,
    cmX: &NoteCommitment,
    cv_net: &ValueCommitment,
    rk: &RandomizedVerifyingKey,
    epk: &EphemeralPublicKey,
    binding_data: &[u8],
) -> [u8; 64] {
    let mut hasher = Blake2bParams::new()
        .hash_length(64)
        .personal(DS_TRADITIONAL_ACTION)
        .to_state();
    
    hasher.update(&nf.0);
    hasher.update(&cmX.0);
    hasher.update(&cv_net.0);
    hasher.update(&rk.0);
    hasher.update(&epk.0);
    hasher.update(binding_data);
    
    let hash = hasher.finalize();
    let mut result = [0u8; 64];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Compute the signature digest for a Tachyaction.
///
/// Uses BLAKE2b-512 with domain separation tag "zcash-tachyon-tachyaction-v1".
///
/// # Inputs
/// Only `cv_net` and `rk` are included (minimal authorization context).
fn compute_tachyaction_signature_digest(
    cv_net: &ValueCommitment,
    rk: &RandomizedVerifyingKey,
    binding_data: &[u8],
) -> [u8; 64] {
    let mut hasher = Blake2bParams::new()
        .hash_length(64)
        .personal(DS_TACHYACTION)
        .to_state();
    
    hasher.update(&cv_net.0);
    hasher.update(&rk.0);
    hasher.update(binding_data);
    
    let hash = hasher.finalize();
    let mut result = [0u8; 64];
    result.copy_from_slice(hash.as_bytes());
    result
}

// ----------------------------- Verification Pipelines -----------------------------

/// Verify a Traditional Action.
///
/// # Verification Steps
/// 1. Construct signature digest from action fields and binding data
/// 2. Verify RedPallas signature using `rk` and `sig`
/// 3. Enforce consensus rules (caller's responsibility):
///    - Nullifier not previously seen
///    - Note commitment inserted into accumulator
///    - Value commitment contributes to balance
///
/// # Arguments
/// - `action`: The action to verify
/// - `binding_data`: Transaction/aggregate context (e.g., anchor, sighash)
/// - `nullifier_set`: Set of all seen nullifiers (for double-spend check)
///
/// # Returns
/// - `Ok(())` if signature is valid
/// - `Err(VerificationError)` otherwise
pub fn verify_traditional_action(
    action: &TraditionalAction,
    binding_data: &[u8],
    nullifier_set: &std::collections::HashSet<Nullifier>,
) -> Result<(), VerificationError> {
    // Check for double-spend
    if nullifier_set.contains(&action.nf) {
        return Err(VerificationError::NullifierAlreadySpent);
    }
    
    // Compute signature digest
    let digest = action.signature_digest(binding_data);
    
    // Verify RedPallas signature
    verify_redpallas_signature(&action.rk, &action.sig, &digest)?;
    
    // Additional consensus checks (value commitment, note commitment validity)
    // are the responsibility of the caller, as they require blockchain state.
    
    Ok(())
}

/// Verify a Tachyaction.
///
/// # Verification Steps
/// 1. Construct signature digest from `cv_net`, `rk`, and binding data
/// 2. Verify RedPallas signature
/// 3. Verify tachystamp proof (caller must provide and check):
///    - Proof includes this action's `(cv_net, rk)` pair
///    - Proof demonstrates note existence and non-double-spend
///
/// # Arguments
/// - `action`: The tachyaction to verify
/// - `binding_data`: Transaction/aggregate context
///
/// # Returns
/// - `Ok(())` if signature is valid
/// - `Err(VerificationError)` otherwise
///
/// # Note
/// The caller MUST also verify the associated tachystamp proof and ensure
/// it binds to this action's `(cv_net, rk)` pair. This function only checks
/// the authorization signature.
pub fn verify_tachyaction(
    action: &Tachyaction,
    binding_data: &[u8],
) -> Result<(), VerificationError> {
    // Compute signature digest
    let digest = action.signature_digest(binding_data);
    
    // Verify RedPallas signature
    verify_redpallas_signature(&action.rk, &action.sig, &digest)?;
    
    // The tachystamp proof must be verified separately by the caller.
    // That proof will bind to (cv_net, rk) and demonstrate:
    // - Note commitments exist in accumulator
    // - Nullifiers have not been spent
    // - Merkle witnesses are valid
    
    Ok(())
}

/// Verify a RedPallas signature.
///
/// # Arguments
/// - `rk`: Randomized verifying key
/// - `sig`: Signature bytes
/// - `message`: Message digest (64 bytes)
fn verify_redpallas_signature(
    rk: &RandomizedVerifyingKey,
    sig: &RedPallasSignature,
    message: &[u8; 64],
) -> Result<(), VerificationError> {
    // Parse verification key
    let vk = VerificationKey::<SpendAuth>::try_from(rk.0)
        .map_err(|_| VerificationError::InvalidSignature)?;
    
    // Parse signature
    let signature = Signature::<SpendAuth>::try_from(sig.0)
        .map_err(|_| VerificationError::InvalidSignature)?;
    
    // Verify signature
    vk.verify(message, &signature)
        .map_err(|_| VerificationError::InvalidSignature)?;
    
    Ok(())
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_nullifier_constant_time_eq() {
        let nf1 = Nullifier([1u8; 32]);
        let nf2 = Nullifier([1u8; 32]);
        let nf3 = Nullifier([2u8; 32]);
        
        assert_eq!(nf1, nf2);
        assert_ne!(nf1, nf3);
    }
    
    #[test]
    fn test_traditional_action_serialization() {
        let action = TraditionalAction {
            nf: Nullifier([1u8; 32]),
            cmX: NoteCommitment([2u8; 32]),
            cv_net: ValueCommitment([3u8; 32]),
            rk: RandomizedVerifyingKey([4u8; 32]),
            sig: RedPallasSignature([5u8; 64]),
            epk: EphemeralPublicKey([6u8; 32]),
            ciphertext: vec![7, 8, 9],
        };
        
        let bytes = action.to_bytes();
        let decoded = TraditionalAction::from_bytes(&bytes).unwrap();
        
        assert_eq!(action.nf, decoded.nf);
        assert_eq!(action.cmX, decoded.cmX);
        assert_eq!(action.cv_net, decoded.cv_net);
        assert_eq!(action.ciphertext, decoded.ciphertext);
    }
    
    #[test]
    fn test_tachyaction_serialization() {
        let action = Tachyaction {
            cv_net: ValueCommitment([1u8; 32]),
            rk: RandomizedVerifyingKey([2u8; 32]),
            sig: RedPallasSignature([3u8; 64]),
        };
        
        let bytes = action.to_bytes();
        let decoded = Tachyaction::from_bytes(&bytes).unwrap();
        
        assert_eq!(action.cv_net, decoded.cv_net);
        assert_eq!(action.rk, decoded.rk);
        assert_eq!(action.sig, decoded.sig);
    }
    
    #[test]
    fn test_signature_digest_domain_separation() {
        let nf = Nullifier([0u8; 32]);
        let cmX = NoteCommitment([0u8; 32]);
        let cv_net = ValueCommitment([0u8; 32]);
        let rk = RandomizedVerifyingKey([0u8; 32]);
        let epk = EphemeralPublicKey([0u8; 32]);
        
        let trad_digest = compute_traditional_signature_digest(&nf, &cmX, &cv_net, &rk, &epk, b"");
        let tachy_digest = compute_tachyaction_signature_digest(&cv_net, &rk, b"");
        
        // Different domain tags should produce different digests
        assert_ne!(trad_digest, tachy_digest);
    }
    
    #[test]
    fn test_redpallas_signature_roundtrip() {
        // Generate a real signing key
        let sk = SigningKey::<SpendAuth>::new(OsRng);
        let vk = VerificationKey::from(&sk);
        
        let message = [42u8; 64];
        let sig = sk.sign(OsRng, &message);
        
        let rk = RandomizedVerifyingKey(vk.into());
        let sig_bytes = RedPallasSignature(sig.into());
        
        // Verify should succeed
        assert!(verify_redpallas_signature(&rk, &sig_bytes, &message).is_ok());
        
        // Wrong message should fail
        let wrong_message = [99u8; 64];
        assert!(verify_redpallas_signature(&rk, &sig_bytes, &wrong_message).is_err());
    }
    
    #[test]
    fn test_traditional_action_verification() {
        // Generate a real key and signature
        let sk = SigningKey::<SpendAuth>::new(OsRng);
        let vk = VerificationKey::from(&sk);
        
        let action = TraditionalAction {
            nf: Nullifier([1u8; 32]),
            cmX: NoteCommitment([2u8; 32]),
            cv_net: ValueCommitment([3u8; 32]),
            rk: RandomizedVerifyingKey(vk.into()),
            sig: RedPallasSignature([0u8; 64]), // Placeholder, will replace
            epk: EphemeralPublicKey([4u8; 32]),
            ciphertext: vec![],
        };
        
        let binding_data = b"test-binding";
        let digest = action.signature_digest(binding_data);
        let sig = sk.sign(OsRng, &digest);
        
        let mut action_signed = action.clone();
        action_signed.sig = RedPallasSignature(sig.into());
        
        let nullifier_set = std::collections::HashSet::new();
        
        // Should verify successfully
        assert!(verify_traditional_action(&action_signed, binding_data, &nullifier_set).is_ok());
        
        // Double-spend should fail
        let mut spent_set = std::collections::HashSet::new();
        spent_set.insert(action_signed.nf);
        assert!(verify_traditional_action(&action_signed, binding_data, &spent_set).is_err());
    }
}

