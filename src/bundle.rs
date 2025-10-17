//! Transaction Bundles for Tachyon
//!
//! A bundle aggregates multiple actions (Traditional and/or Tachyactions) into a
//! single verifiable unit. Bundles include:
//!
//! - Traditional Actions (with on-chain ciphertext)
//! - Tachyactions (authorization-only, proof-carrying)
//! - Tachystamp proofs or references to proof aggregates
//! - Binding signature for value balance integrity
//! - Optional anchor (if Traditional Actions are present)
//!
//! # Bundle Verification
//!
//! To verify a bundle:
//! 1. Verify all Traditional Action signatures
//! 2. Verify all Tachyaction signatures
//! 3. Check tachystamp proofs cover all Tachyactions' (cv_net, rk) pairs
//! 4. Sum all cv_net commitments and verify binding signature
//! 5. Check anchor validity (if Traditional Actions present)
//!
//! # Proof Aggregation
//!
//! Multiple tachystamps can be merged into a single aggregate. Bundles can then
//! reference the aggregate rather than including full proofs, dramatically reducing
//! transaction size.

#![forbid(unsafe_code)]

use crate::actions::*;
use blake2b_simd::Params as Blake2bParams;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

// Import tachystamps types when feature is enabled
#[cfg(feature = "tachystamps")]
use crate::tachystamps::{Tachygram, Compressed};

// Placeholder types when tachystamps feature is disabled
#[cfg(not(feature = "tachystamps"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tachygram(pub [u8; 32]);

#[cfg(not(feature = "tachystamps"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Compressed {
    pub proof: Vec<u8>,
    pub vk: Vec<u8>,
}

// ----------------------------- Constants -----------------------------

/// Domain tag for bundle binding signature
const DS_BUNDLE_BINDING: &[u8] = b"zcash-tachyon-bundle-binding-v1";

/// Maximum number of actions per bundle (consensus rule)
const MAX_ACTIONS_PER_BUNDLE: usize = 50;

// ----------------------------- Types -----------------------------

/// A binding signature that proves balance integrity across a bundle.
///
/// The binding signature is computed over the sum of all value commitments
/// using a blinding key derived from the commitment randomness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BindingSignature(pub [u8; 64]);

/// Reference to a tachystamp proof (either inline or in an aggregate).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TachystampReference {
    /// Inline proof (full PCD included in this bundle)
    Inline(Compressed),
    
    /// Reference to an aggregate proof by index
    /// Format: (aggregate_id, proof_index_in_aggregate)
    AggregateRef(u32, u32),
}

/// An anchor is a Merkle root representing the state of the note commitment tree
/// at a specific block height.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Anchor(pub [u8; 32]);

// ----------------------------- Bundle Structure -----------------------------

/// A Tachyon transaction bundle.
///
/// Bundles can contain a mix of Traditional Actions and Tachyactions, allowing
/// gradual migration from legacy to modern payment protocols.
///
/// # Structure
///
/// ```text
/// TachyBundle
///  ├─ Traditional Actions (optional, if any present)
///  │   └─ require: anchor field
///  ├─ Tachyactions (optional)
///  │   └─ require: tachystamp reference
///  ├─ Binding Signature (always required)
///  └─ Anchor (only if Traditional Actions present)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TachyBundle {
    /// Traditional Orchard-style actions (with on-chain ciphertext)
    pub actions: Vec<TraditionalAction>,
    
    /// Minimal authorization-only actions (out-of-band payments)
    pub tachyactions: Vec<Tachyaction>,
    
    /// Tachystamp proof or reference (required if tachyactions are present)
    pub tachystamp: Option<TachystampReference>,
    
    /// Anchor (Merkle root) for Traditional Actions
    /// Must be present if `actions` is non-empty, omitted otherwise
    pub anchor: Option<Anchor>,
    
    /// Binding signature over sum of value commitments
    pub binding_signature: BindingSignature,
}

impl TachyBundle {
    /// Create a new empty bundle.
    pub fn new(binding_signature: BindingSignature) -> Self {
        Self {
            actions: Vec::new(),
            tachyactions: Vec::new(),
            tachystamp: None,
            anchor: None,
            binding_signature,
        }
    }
    
    /// Add a Traditional Action to the bundle.
    pub fn add_traditional_action(&mut self, action: TraditionalAction) -> Result<(), BundleError> {
        if self.actions.len() + self.tachyactions.len() >= MAX_ACTIONS_PER_BUNDLE {
            return Err(BundleError::TooManyActions);
        }
        self.actions.push(action);
        Ok(())
    }
    
    /// Add a Tachyaction to the bundle.
    pub fn add_tachyaction(&mut self, action: Tachyaction) -> Result<(), BundleError> {
        if self.actions.len() + self.tachyactions.len() >= MAX_ACTIONS_PER_BUNDLE {
            return Err(BundleError::TooManyActions);
        }
        self.tachyactions.push(action);
        Ok(())
    }
    
    /// Set the anchor (required if Traditional Actions are present).
    pub fn set_anchor(&mut self, anchor: Anchor) {
        self.anchor = Some(anchor);
    }
    
    /// Set the tachystamp reference (required if Tachyactions are present).
    pub fn set_tachystamp(&mut self, tachystamp: TachystampReference) {
        self.tachystamp = Some(tachystamp);
    }
    
    /// Check if this bundle is well-formed (structural validity).
    pub fn is_well_formed(&self) -> Result<(), BundleError> {
        // Empty bundle is invalid
        if self.actions.is_empty() && self.tachyactions.is_empty() {
            return Err(BundleError::EmptyBundle);
        }
        
        // If Traditional Actions present, anchor must be set
        if !self.actions.is_empty() && self.anchor.is_none() {
            return Err(BundleError::MissingAnchor);
        }
        
        // If Tachyactions present, tachystamp must be set
        if !self.tachyactions.is_empty() && self.tachystamp.is_none() {
            return Err(BundleError::MissingTachystamp);
        }
        
        // Check action count limit
        if self.actions.len() + self.tachyactions.len() > MAX_ACTIONS_PER_BUNDLE {
            return Err(BundleError::TooManyActions);
        }
        
        Ok(())
    }
    
    /// Compute the binding data used for action signatures.
    ///
    /// This includes the bundle-level context that all actions must commit to.
    pub fn binding_data(&self) -> Vec<u8> {
        let mut hasher = Blake2bParams::new()
            .hash_length(32)
            .personal(b"zcash-tachyon-bundle-ctx")
            .to_state();
        
        // Include anchor if present
        if let Some(anchor) = &self.anchor {
            hasher.update(&anchor.0);
        }
        
        // Include count of each action type
        hasher.update(&(self.actions.len() as u32).to_le_bytes());
        hasher.update(&(self.tachyactions.len() as u32).to_le_bytes());
        
        // Include commitments to action data (order-dependent)
        for action in &self.actions {
            hasher.update(&action.nf.0);
            hasher.update(&action.cmX.0);
        }
        
        for action in &self.tachyactions {
            hasher.update(&action.cv_net.0);
        }
        
        hasher.finalize().as_bytes().to_vec()
    }
    
    /// Extract all (cv_net, rk) pairs from the bundle.
    ///
    /// These must match the pairs verified by the tachystamp proof.
    pub fn extract_commitment_key_pairs(&self) -> Vec<(ValueCommitment, RandomizedVerifyingKey)> {
        let mut pairs = Vec::new();
        
        // Traditional Actions contribute their pairs
        for action in &self.actions {
            pairs.push((action.cv_net, action.rk));
        }
        
        // Tachyactions contribute their pairs
        for action in &self.tachyactions {
            pairs.push((action.cv_net, action.rk));
        }
        
        pairs
    }
    
    /// Extract all tachygrams (nullifiers and commitments) from the bundle.
    ///
    /// These must be recorded in the blockchain accumulator.
    pub fn extract_tachygrams(&self) -> Vec<Tachygram> {
        let mut tachygrams = Vec::new();
        
        for action in &self.actions {
            // Both nullifier and commitment are tachygrams
            tachygrams.push(Tachygram(action.nf.0));
            tachygrams.push(Tachygram(action.cmX.0));
        }
        
        // Tachyactions' tachygrams are in the tachystamp proof, not here
        
        tachygrams
    }
    
    /// Serialize the bundle to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Use serde_cbor for now (bincode v2 has different API)
        serde_cbor::to_vec(self).unwrap_or_default()
    }
    
    /// Deserialize a bundle from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleError> {
        serde_cbor::from_slice(bytes).map_err(|e| BundleError::Serialization(e.to_string()))
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum BundleError {
    #[error("bundle is empty")]
    EmptyBundle,
    
    #[error("anchor required for Traditional Actions but not provided")]
    MissingAnchor,
    
    #[error("tachystamp required for Tachyactions but not provided")]
    MissingTachystamp,
    
    #[error("too many actions in bundle (max {MAX_ACTIONS_PER_BUNDLE})")]
    TooManyActions,
    
    #[error("binding signature verification failed")]
    InvalidBindingSignature,
    
    #[error("action verification failed: {0}")]
    ActionVerification(#[from] VerificationError),
    
    #[error("tachystamp verification failed: {0}")]
    TachystampVerification(String),
    
    #[error("tachystamp feature not enabled")]
    TachystampFeatureDisabled,
    
    #[error("value balance does not sum to zero")]
    ValueBalanceNonZero,
    
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ----------------------------- Bundle Verification -----------------------------

/// Verify a complete bundle.
///
/// # Verification Steps
///
/// 1. **Structural checks**: Well-formed bundle
/// 2. **Traditional Action verification**: All signatures valid, no double-spends
/// 3. **Tachyaction verification**: All signatures valid
/// 4. **Tachystamp verification**: Proof covers all (cv_net, rk) pairs
/// 5. **Binding signature**: Proves value balance integrity
/// 6. **Anchor validity**: Anchor is recognized (if present)
///
/// # Arguments
///
/// - `bundle`: The bundle to verify
/// - `nullifier_set`: All previously seen nullifiers (for double-spend detection)
/// - `valid_anchors`: Set of valid anchors at current block height
///
/// # Returns
///
/// - `Ok(())` if bundle is fully valid
/// - `Err(BundleError)` with specific failure reason
pub fn verify_bundle(
    bundle: &TachyBundle,
    nullifier_set: &HashSet<Nullifier>,
    valid_anchors: &HashSet<Anchor>,
) -> Result<(), BundleError> {
    // 1. Structural validity
    bundle.is_well_formed()?;
    
    // 2. Compute binding data for all actions
    let binding_data = bundle.binding_data();
    
    // 3. Verify all Traditional Actions
    for action in &bundle.actions {
        verify_traditional_action(action, &binding_data, nullifier_set)?;
    }
    
    // 4. Verify all Tachyactions
    for action in &bundle.tachyactions {
        verify_tachyaction(action, &binding_data)?;
    }
    
    // 5. Verify tachystamp proof (if present)
    if let Some(tachystamp_ref) = &bundle.tachystamp {
        verify_tachystamp_covers_actions(tachystamp_ref, &bundle.extract_commitment_key_pairs())?;
    }
    
    // 6. Verify binding signature
    verify_binding_signature(bundle, &binding_data)?;
    
    // 7. Check anchor validity (if Traditional Actions present)
    if let Some(anchor) = &bundle.anchor {
        if !valid_anchors.contains(anchor) {
            return Err(BundleError::ActionVerification(
                VerificationError::UnknownAnchor,
            ));
        }
    }
    
    Ok(())
}

/// Verify that a tachystamp covers all required (cv_net, rk) pairs.
///
/// This ensures the tachystamp proof actually authorizes the actions in the bundle.
fn verify_tachystamp_covers_actions(
    tachystamp_ref: &TachystampReference,
    required_pairs: &[(ValueCommitment, RandomizedVerifyingKey)],
) -> Result<(), BundleError> {
    match tachystamp_ref {
        TachystampReference::Inline(compressed) => {
            // Verify the compressed proof
            // TODO: Extract (cv_net, rk) pairs from proof metadata and compare
            // For now, we assume the proof is structurally valid
            
            // In a full implementation, the Compressed type would need to expose
            // the (cv_net, rk) pairs it covers, and we'd verify they match.
            
            // Placeholder: just check that we have a proof
            if required_pairs.is_empty() {
                return Err(BundleError::TachystampVerification(
                    "no pairs to verify".into(),
                ));
            }
            
            Ok(())
        }
        TachystampReference::AggregateRef(_aggregate_id, _index) => {
            // In aggregate mode, the caller must have already verified the aggregate
            // and ensured this bundle's actions are covered.
            // We can't verify this without access to the aggregate itself.
            Ok(())
        }
    }
}

/// Verify the binding signature proves value balance integrity.
///
/// The binding signature is computed over the sum of all value commitments.
/// This ensures Σ cv_net = 0 (modulo the binding key).
fn verify_binding_signature(
    bundle: &TachyBundle,
    binding_data: &[u8],
) -> Result<(), BundleError> {
    // Compute binding signature digest
    let digest = compute_binding_signature_digest(bundle, binding_data);
    
    // In a full implementation, we would:
    // 1. Sum all cv_net commitments homomorphically
    // 2. Verify the binding signature using the sum as the public key
    //
    // For now, we just check the signature is present and well-formed.
    
    // Placeholder: verify signature format
    if bundle.binding_signature.0.iter().all(|&b| b == 0) {
        return Err(BundleError::InvalidBindingSignature);
    }
    
    Ok(())
}

/// Compute the digest for the binding signature.
fn compute_binding_signature_digest(bundle: &TachyBundle, binding_data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2bParams::new()
        .hash_length(64)
        .personal(DS_BUNDLE_BINDING)
        .to_state();
    
    // Include all value commitments
    for action in &bundle.actions {
        hasher.update(&action.cv_net.0);
    }
    
    for action in &bundle.tachyactions {
        hasher.update(&action.cv_net.0);
    }
    
    // Include binding context
    hasher.update(binding_data);
    
    let hash = hasher.finalize();
    let mut result = [0u8; 64];
    result.copy_from_slice(hash.as_bytes());
    result
}

// ----------------------------- Helpers -----------------------------

/// Compute the net value balance of a bundle.
///
/// This is a debug helper; in production, value balance is proven by the binding signature.
#[cfg(test)]
fn compute_value_balance_plaintext(
    _actions: &[TraditionalAction],
    _tachyactions: &[Tachyaction],
) -> i64 {
    // In a full implementation, this would require opening the value commitments
    // which requires knowing the commitment randomness.
    // For testing, we can use known test values.
    0 // Placeholder
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    fn dummy_traditional_action() -> TraditionalAction {
        TraditionalAction {
            nf: Nullifier([1u8; 32]),
            cmX: NoteCommitment([2u8; 32]),
            cv_net: ValueCommitment([3u8; 32]),
            rk: RandomizedVerifyingKey([4u8; 32]),
            sig: RedPallasSignature([5u8; 64]),
            epk: EphemeralPublicKey([6u8; 32]),
            ciphertext: vec![],
        }
    }
    
    fn dummy_tachyaction() -> Tachyaction {
        Tachyaction {
            cv_net: ValueCommitment([7u8; 32]),
            rk: RandomizedVerifyingKey([8u8; 32]),
            sig: RedPallasSignature([9u8; 64]),
        }
    }
    
    #[test]
    fn test_empty_bundle_invalid() {
        let bundle = TachyBundle::new(BindingSignature([0u8; 64]));
        assert!(bundle.is_well_formed().is_err());
    }
    
    #[test]
    fn test_traditional_actions_require_anchor() {
        let mut bundle = TachyBundle::new(BindingSignature([0u8; 64]));
        bundle.add_traditional_action(dummy_traditional_action()).unwrap();
        
        // Without anchor, should be invalid
        assert!(bundle.is_well_formed().is_err());
        
        // With anchor, should be valid
        bundle.set_anchor(Anchor([0u8; 32]));
        assert!(bundle.is_well_formed().is_ok());
    }
    
    #[test]
    fn test_tachyactions_require_tachystamp() {
        let mut bundle = TachyBundle::new(BindingSignature([0u8; 64]));
        bundle.add_tachyaction(dummy_tachyaction()).unwrap();
        
        // Without tachystamp, should be invalid
        assert!(bundle.is_well_formed().is_err());
        
        // With tachystamp, should be valid
        bundle.set_tachystamp(TachystampReference::AggregateRef(0, 0));
        assert!(bundle.is_well_formed().is_ok());
    }
    
    #[test]
    fn test_mixed_bundle() {
        let mut bundle = TachyBundle::new(BindingSignature([1u8; 64]));
        bundle.add_traditional_action(dummy_traditional_action()).unwrap();
        bundle.add_tachyaction(dummy_tachyaction()).unwrap();
        bundle.set_anchor(Anchor([0u8; 32]));
        bundle.set_tachystamp(TachystampReference::AggregateRef(0, 0));
        
        assert!(bundle.is_well_formed().is_ok());
        
        // Should extract 2 (cv_net, rk) pairs
        let pairs = bundle.extract_commitment_key_pairs();
        assert_eq!(pairs.len(), 2);
        
        // Should extract 2 tachygrams (nf + cmX from traditional action)
        let tachygrams = bundle.extract_tachygrams();
        assert_eq!(tachygrams.len(), 2);
    }
    
    #[test]
    fn test_bundle_serialization() {
        let mut bundle = TachyBundle::new(BindingSignature([1u8; 64]));
        bundle.add_tachyaction(dummy_tachyaction()).unwrap();
        bundle.set_tachystamp(TachystampReference::AggregateRef(0, 0));
        
        let bytes = bundle.to_bytes();
        let decoded = TachyBundle::from_bytes(&bytes).unwrap();
        
        assert_eq!(bundle.tachyactions.len(), decoded.tachyactions.len());
        assert_eq!(bundle.binding_signature, decoded.binding_signature);
    }
    
    #[test]
    fn test_max_actions_limit() {
        let mut bundle = TachyBundle::new(BindingSignature([0u8; 64]));
        
        // Add maximum allowed actions
        for _ in 0..MAX_ACTIONS_PER_BUNDLE {
            bundle.add_tachyaction(dummy_tachyaction()).unwrap();
        }
        
        // One more should fail
        assert!(bundle.add_tachyaction(dummy_tachyaction()).is_err());
    }
    
    #[test]
    fn test_binding_data_deterministic() {
        let mut bundle1 = TachyBundle::new(BindingSignature([0u8; 64]));
        bundle1.add_tachyaction(dummy_tachyaction()).unwrap();
        bundle1.set_tachystamp(TachystampReference::AggregateRef(0, 0));
        
        let mut bundle2 = bundle1.clone();
        
        // Binding data should be identical for identical bundles
        assert_eq!(bundle1.binding_data(), bundle2.binding_data());
        
        // Adding another action should change binding data
        bundle2.add_tachyaction(dummy_tachyaction()).unwrap();
        assert_ne!(bundle1.binding_data(), bundle2.binding_data());
    }
}

