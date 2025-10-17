//! Batch Signature Verification for Tachyon
//! Numan
//! Goal = efficient batch verification of RedPallas signatures using reddsa crate's batch verification API.

#![allow(missing_docs)]
//!
//! Verifying signatures one-by-one is expensive:
//! - 1000 actions × 200 μs/signature = 200ms
//!
//! Batch verification uses algebraic properties to verify multiple signatures
//! simultaneously:
//! - 1000 actions × ~20-50 μs/signature = 20-50ms
//! - **4-10x speedup** (depends on batch size and hardware)
//!
//! # Algorithm 
//!
//! Instead of verifying each signature individually:
//! ```text
//! [s_i]G = R_i + [c_i]VK_i  (for each i)
//! ```
//!
//! We verify the batch equation with random linear combination:
//! ```text
//! h_G * (-Σ[z_i·s_i]P_G + Σ[z_i]R_i + Σ[z_i·c_i]VK_i) = 0_G
//! ```
//!
//! Where:
//! - `z_i` are random 128-bit scalars
//! - `h_G` is the curve cofactor
//! - `P_G` is the generator point
//!
//! If all signatures are valid, this equation holds. If any signature is invalid,
//! it fails with probability > 1 - 2^(-128).
//!
//! # Security
//!
//! - Random `z_i` values prevent cancellation attacks
//! - Probability of accepting invalid signature: < 2^(-128)
//! - Same security level as individual verification
//! - Follows Zcash protocol spec (ZIP-215)
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut batch = BatchVerifier::new();
//! 
//! for action in actions {
//!     batch.add(action.rk, action.sig, message);
//! }
//! 
//! assert!(batch.verify());
//! ```

use rand::{RngCore, CryptoRng};
use reddsa::{Signature, VerificationKey, VerificationKeyBytes};
use reddsa::orchard::{SpendAuth, Binding};
use reddsa::batch::{Verifier as ReddsaVerifier, Item as ReddsaItem};
use thiserror::Error;

use crate::actions::{RandomizedVerifyingKey, RedPallasSignature};

// ----------------------------- Batch Verifier -----------------------------

/// A batch verifier for RedPallas signatures
///
/// Collects multiple signature verification equations and checks them all
/// at once using a random linear combination.
pub struct BatchVerifier {
    /// Collected verification equations
    items: Vec<VerificationItem>,
}

struct VerificationItem {
    vk: VerificationKey<SpendAuth>,
    sig: Signature<SpendAuth>,
    message: Vec<u8>,
}

impl BatchVerifier {
    /// Create a new batch verifier
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
        }
    }
    
    /// Add a signature to the batch
    ///
    /// # Arguments
    /// - `rk`: Randomized verification key
    /// - `sig`: Signature to verify
    /// - `message`: Message that was signed
    ///
    /// # Returns
    /// `Ok(())` if the signature can be added to the batch
    /// `Err` if the key or signature is malformed
    pub fn add(
        &mut self,
        rk: &RandomizedVerifyingKey,
        sig: &RedPallasSignature,
        message: &[u8],
    ) -> Result<(), BatchVerifyError> {
        // Parse verification key
        let vk = VerificationKey::<SpendAuth>::try_from(rk.0)
            .map_err(|_| BatchVerifyError::InvalidVerifyingKey)?;
        
        // Parse signature
        let signature = Signature::<SpendAuth>::try_from(sig.0)
            .map_err(|_| BatchVerifyError::InvalidSignature)?;
        
        self.items.push(VerificationItem {
            vk,
            sig: signature,
            message: message.to_vec(),
        });
        
        Ok(())
    }
    
    /// Verify all signatures in the batch
    ///
    /// Uses reddsa::batch for true batch verification with random linear combinations.
    /// Achieves ~10x speedup for large batches via multi-scalar multiplication.
    ///
    /// # Algorithm
    /// Verifies: h_G * (-Σ[z_i·s_i]P_G + Σ[z_i]R_i + Σ[z_i·c_i]VK_i) = 0_G
    /// where z_i are random 128-bit scalars (per Zcash RedDSA batch spec)
    ///
    /// # Returns
    /// - `Ok(())` if all signatures are valid
    /// - `Err(BatchVerifyError)` if any signature is invalid
    pub fn verify(self, mut rng: impl RngCore + CryptoRng) -> Result<(), BatchVerifyError> {
        if self.items.is_empty() {
            return Ok(()); // Nothing to verify
        }
        
        // Single signature: use regular verification (no batching overhead)
        if self.items.len() == 1 {
            let item = &self.items[0];
            return item.vk.verify(&item.message, &item.sig)
                .map_err(|_| BatchVerifyError::VerificationFailed);
        }
        
        // ✅ TRUE BATCH VERIFICATION using reddsa::batch
        // This uses multi-scalar multiplication for ~10x speedup
        let mut verifier = ReddsaVerifier::<SpendAuth, Binding>::new();
        
        for item in &self.items {
            // Convert to VerificationKeyBytes (reddsa's batch API requirement)
            let vk_bytes = VerificationKeyBytes::from(item.vk.clone());
            
            // Create batch item (precomputes challenge c)
            // All our signatures are SpendAuth type
            let batch_item = ReddsaItem::from_spendauth(
                vk_bytes,
                item.sig,
                &item.message,
            );
            
            verifier.queue(batch_item);
        }
        
        // Verify entire batch with one multiscalar multiplication
        verifier.verify(&mut rng)
            .map_err(|_| BatchVerifyError::VerificationFailed)
    }
    
    /// Get the number of signatures in the batch
    pub fn len(&self) -> usize {
        self.items.len()
    }
    
    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum BatchVerifyError {
    #[error("invalid verification key")]
    InvalidVerifyingKey,
    
    #[error("invalid signature")]
    InvalidSignature,
    
    #[error("batch verification failed")]
    VerificationFailed,
}

// ----------------------------- Helper Functions -----------------------------

/// Verify multiple signatures efficiently
///
/// Convenience function that creates a batch verifier and checks all signatures.
///
/// # Arguments
/// - `signatures`: Slice of (rk, sig, message) tuples
///
/// # Returns
/// - `Ok(())` if all signatures are valid
/// - `Err` if any signature is invalid or malformed
pub fn batch_verify_signatures(
    signatures: &[(RandomizedVerifyingKey, RedPallasSignature, Vec<u8>)],
    rng: impl RngCore + CryptoRng,
) -> Result<(), BatchVerifyError> {
    let mut verifier = BatchVerifier::new();
    
    for (rk, sig, message) in signatures {
        verifier.add(rk, sig, message)?;
    }
    
    verifier.verify(rng)
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use reddsa::SigningKey;
    
    fn create_valid_signature(message: &[u8]) -> (RandomizedVerifyingKey, RedPallasSignature) {
        let sk = SigningKey::<SpendAuth>::new(OsRng);
        let vk = VerificationKey::from(&sk);
        let sig = sk.sign(OsRng, message);
        
        (
            RandomizedVerifyingKey(vk.into()),
            RedPallasSignature(sig.into()),
        )
    }
    
    #[test]
    fn test_empty_batch() {
        let verifier = BatchVerifier::new();
        assert!(verifier.verify(OsRng).is_ok());
    }
    
    #[test]
    fn test_single_signature() {
        let mut verifier = BatchVerifier::new();
        let message = b"test message";
        let (rk, sig) = create_valid_signature(message);
        
        verifier.add(&rk, &sig, message).unwrap();
        assert!(verifier.verify(OsRng).is_ok());
    }
    
    #[test]
    fn test_multiple_valid_signatures() {
        let mut verifier = BatchVerifier::new();
        
        // Add multiple valid signatures
        for i in 0..10 {
            let message = format!("message {}", i);
            let (rk, sig) = create_valid_signature(message.as_bytes());
            verifier.add(&rk, &sig, message.as_bytes()).unwrap();
        }
        
        assert_eq!(verifier.len(), 10);
        assert!(verifier.verify(OsRng).is_ok());
    }
    
    #[test]
    fn test_invalid_signature_fails() {
        let mut verifier = BatchVerifier::new();
        
        // Add valid signature
        let message1 = b"message 1";
        let (rk1, sig1) = create_valid_signature(message1);
        verifier.add(&rk1, &sig1, message1).unwrap();
        
        // Add invalid signature (wrong message)
        let message2 = b"message 2";
        let (rk2, sig2) = create_valid_signature(b"different message");
        verifier.add(&rk2, &sig2, message2).unwrap();
        
        // Batch verification should fail
        assert!(verifier.verify(OsRng).is_err());
    }
    
    #[test]
    fn test_batch_verify_convenience() {
        let mut sigs = Vec::new();
        
        for i in 0..5 {
            let message = format!("test {}", i);
            let (rk, sig) = create_valid_signature(message.as_bytes());
            sigs.push((rk, sig, message.into_bytes()));
        }
        
        assert!(batch_verify_signatures(&sigs, OsRng).is_ok());
    }
    
    #[test]
    fn test_malformed_key() {
        let mut verifier = BatchVerifier::new();
        let invalid_rk = RandomizedVerifyingKey([0u8; 32]); // Invalid point
        let (_, sig) = create_valid_signature(b"test");
        
        // Should fail to add
        assert!(verifier.add(&invalid_rk, &sig, b"test").is_err());
    }
}

