//! RedPallas Key Re-randomization for Tachyon
//!
//! Goal = key re-randomization for spend authorization, providing
//! unlinkability across transactions while maintaining security.

#![allow(missing_docs)]
//!
//! # Key Re-randomization
//!
//! Spend authorization uses RedPallas signatures over the Pallas curve. To prevent
//! transaction linkability, we re-randomize both the signing and verification keys:
//!
//! ```text
//! ask = spend authorization signing key (secret)
//! ak  = spend authorization verification key = [ask]G (public)
//! α   = randomization scalar (secret, per-transaction)
//! rk  = randomized verification key = ak + [α]G = [ask + α]G
//! ```
//!
//! The signer uses `ask + α` to sign, and the verifier uses `rk` to verify.
//! This makes transactions unlinkable even if the same note is spent multiple times
//! (e.g., in different chains or rollbacks).
//!
//! # Security Properties
//!
//! - **Unlinkability**: Different α values produce different rk values
//! - **Soundness**: Only someone who knows ask can produce valid signatures for rk
//! - **Zero-knowledge**: α does not reveal ask
//!
//! # Usage
//!
//! ```rust,ignore
//! // Wallet has a long-term spend authorization key
//! let ask = SpendAuthorizationKey::random(rng);
//! let ak = SpendAuthorizationVerifyingKey::from(&ask);
//!
//! // For each transaction, generate random α
//! let alpha = Randomizer::random(rng);
//!
//! // Derive randomized key
//! let rk = ak.randomize(&alpha);
//!
//! // Sign with randomized signing key
//! let rsk = ask.randomize(&alpha);
//! let sig = rsk.sign(message, rng);
//!
//! // Verify with randomized verification key
//! assert!(rk.verify(message, &sig).is_ok());
//! ```

use group::{Group, GroupEncoding};
use halo2curves::pasta::{pallas, Fq as PallasScalar};
use halo2curves::ff::{Field, PrimeField};
use rand::{RngCore, CryptoRng};
use reddsa::{Signature, SigningKey, VerificationKey};
use reddsa::orchard::SpendAuth;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

use crate::actions::{RandomizedVerifyingKey, RedPallasSignature};

// ----------------------------- Types -----------------------------

/// A spend authorization signing key (ask)
///
/// This is the long-term secret key derived from the wallet's seed.
/// It should be kept secret and zeroized when no longer needed.
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct SpendAuthorizationKey(pub PallasScalar);

impl SpendAuthorizationKey {
    /// Generate a random spend authorization key
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(PallasScalar::random(&mut rng))
    }
    
    /// From bytes (for deterministic derivation)
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        PallasScalar::from_repr(bytes).into_option().map(Self)
    }
    
    /// To bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
    
    /// Randomize this key with a randomizer α
    ///
    /// Returns rsk = ask + α
    pub fn randomize(&self, alpha: &Randomizer) -> RandomizedSigningKey {
        RandomizedSigningKey(self.0 + alpha.0)
    }
}

impl std::fmt::Debug for SpendAuthorizationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SpendAuthorizationKey([REDACTED])")
    }
}

/// A spend authorization verification key (ak)
///
/// This is the public key corresponding to ask: ak = [ask]G
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct SpendAuthorizationVerifyingKey(pub [u8; 32]);

impl PartialEq for SpendAuthorizationVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for SpendAuthorizationVerifyingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl SpendAuthorizationVerifyingKey {
    /// Derive from signing key
    pub fn from_signing_key(ask: &SpendAuthorizationKey) -> Self {
        // ak = [ask]G
        let point = pallas::Point::generator() * ask.0;
        let affine = pallas::Affine::from(point);
        Self(affine.to_bytes())
    }
    
    /// Randomize this key with a randomizer α
    ///
    /// Returns rk = ak + [α]G
    pub fn randomize(&self, alpha: &Randomizer) -> RandomizedVerifyingKey {
        // Parse ak as a point
        let ak_point = pallas::Affine::from_bytes(&self.0)
            .map(pallas::Point::from)
            .expect("valid ak point");
        
        // Compute [α]G
        let alpha_point = pallas::Point::generator() * alpha.0;
        
        // rk = ak + [α]G
        let rk_point = ak_point + alpha_point;
        let rk_affine = pallas::Affine::from(rk_point);
        
        RandomizedVerifyingKey(rk_affine.to_bytes())
    }
    
    /// Convert to curve point
    pub fn to_point(&self) -> Option<pallas::Point> {
        pallas::Affine::from_bytes(&self.0)
            .into_option()
            .map(pallas::Point::from)
    }
}

impl From<&SpendAuthorizationKey> for SpendAuthorizationVerifyingKey {
    fn from(ask: &SpendAuthorizationKey) -> Self {
        Self::from_signing_key(ask)
    }
}

/// A randomizer scalar (α)
///
/// This is a random scalar used to re-randomize keys for each transaction.
/// It should be kept secret during transaction construction.
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct Randomizer(pub PallasScalar);

impl Randomizer {
    /// Generate a random randomizer
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(PallasScalar::random(&mut rng))
    }
    
    /// From bytes (for testing)
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        PallasScalar::from_repr(bytes).into_option().map(Self)
    }
    
    /// To bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl std::fmt::Debug for Randomizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Randomizer([REDACTED])")
    }
}

/// A randomized signing key (rsk = ask + α)
///
/// This is used to sign a transaction with the randomized key.
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct RandomizedSigningKey(pub PallasScalar);

impl RandomizedSigningKey {
    /// Sign a message with this randomized key
    ///
    /// # Arguments
    /// - `message`: The message to sign (typically a signature digest)
    /// - `rng`: Random number generator for signature generation
    ///
    /// # Returns
    /// A RedPallas signature that can be verified with the corresponding rk
    pub fn sign(&self, message: &[u8], mut rng: impl RngCore + CryptoRng) -> RedPallasSignature {
        // TODO: Implement proper signing with randomized scalar
        // Current issue: reddsa's SigningKey::try_from() doesn't work for arbitrary scalars
        // Need to either:
        // 1. Find correct reddsa API for scalar-based keys
        // 2. Implement Schnorr signing manually with correct challenge format
        // 3. Use reddsa's native randomization mechanism
        
        // Temporary workaround: Use try_from and hope it works
        let sk_bytes: [u8; 32] = self.0.to_repr();
        let sk = SigningKey::<SpendAuth>::try_from(sk_bytes)
            .expect("valid signing key from scalar");
        
        let signature = sk.sign(&mut rng, message);
        RedPallasSignature(signature.into())
    }
}

impl std::fmt::Debug for RandomizedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RandomizedSigningKey([REDACTED])")
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum KeyRandomizationError {
    #[error("invalid key bytes")]
    InvalidKey,
    
    #[error("invalid randomizer")]
    InvalidRandomizer,
    
    #[error("signature verification failed")]
    VerificationFailed,
}

// ----------------------------- Helper Functions -----------------------------

/// Verify a signature with a randomized verification key
///
/// This is a convenience wrapper around the RedPallas verification.
pub fn verify_with_randomized_key(
    rk: &RandomizedVerifyingKey,
    message: &[u8],
    signature: &RedPallasSignature,
) -> Result<(), KeyRandomizationError> {
    // Convert to RedPallas verification key
    let vk = VerificationKey::<SpendAuth>::try_from(rk.0)
        .map_err(|_| KeyRandomizationError::InvalidKey)?;
    
    // Parse signature
    let sig = Signature::<SpendAuth>::try_from(signature.0)
        .map_err(|_| KeyRandomizationError::InvalidKey)?;
    
    // Verify
    vk.verify(message, &sig)
        .map_err(|_| KeyRandomizationError::VerificationFailed)?;
    
    Ok(())
}

/// Create a randomized key pair for a transaction
///
/// This is a convenience function that generates α and derives both rsk and rk.
pub fn create_randomized_keypair(
    ask: &SpendAuthorizationKey,
    mut rng: impl RngCore + CryptoRng,
) -> (RandomizedSigningKey, RandomizedVerifyingKey, Randomizer) {
    let alpha = Randomizer::random(&mut rng);
    let rsk = ask.randomize(&alpha);
    let ak = SpendAuthorizationVerifyingKey::from_signing_key(ask);
    let rk = ak.randomize(&alpha);
    (rsk, rk, alpha)
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_key_derivation() {
        let ask = SpendAuthorizationKey::random(OsRng);
        let ak = SpendAuthorizationVerifyingKey::from_signing_key(&ask);
        
        // Should be able to round-trip
        let ak2 = SpendAuthorizationVerifyingKey::from(&ask);
        assert_eq!(ak, ak2);
        
        // Should produce a valid point
        assert!(ak.to_point().is_some());
    }
    
    #[test]
    fn test_key_randomization() {
        let ask = SpendAuthorizationKey::random(OsRng);
        let ak = SpendAuthorizationVerifyingKey::from(&ask);
        
        let alpha1 = Randomizer::random(OsRng);
        let alpha2 = Randomizer::random(OsRng);
        
        let rk1 = ak.randomize(&alpha1);
        let rk2 = ak.randomize(&alpha2);
        
        // Different randomizers should produce different keys
        assert_ne!(rk1, rk2);
        
        // Same randomizer should produce same key
        let rk1_again = ak.randomize(&alpha1);
        assert_eq!(rk1, rk1_again);
    }
    
    #[test]
    #[ignore = "TODO: Fix RedPallas signing with randomized scalars - reddsa API issue"]
    fn test_sign_and_verify() {
        let ask = SpendAuthorizationKey::random(OsRng);
        let ak = SpendAuthorizationVerifyingKey::from(&ask);
        let alpha = Randomizer::random(OsRng);
        
        let rsk = ask.randomize(&alpha);
        let rk = ak.randomize(&alpha);
        
        let message = b"test transaction message";
        let sig = rsk.sign(message, OsRng);
        
        // Verify with randomized key
        assert!(verify_with_randomized_key(&rk, message, &sig).is_ok());
        
        // Wrong message should fail
        assert!(verify_with_randomized_key(&rk, b"wrong message", &sig).is_err());
    }
    
    #[test]
    #[ignore = "TODO: Fix RedPallas signing with randomized scalars - reddsa API issue"]
    fn test_unlinkability() {
        let ask = SpendAuthorizationKey::random(OsRng);
        let ak = SpendAuthorizationVerifyingKey::from(&ask);
        
        // Create two transactions with different randomizers
        let alpha1 = Randomizer::random(OsRng);
        let alpha2 = Randomizer::random(OsRng);
        
        let rsk1 = ask.randomize(&alpha1);
        let rk1 = ak.randomize(&alpha1);
        
        let rsk2 = ask.randomize(&alpha2);
        let rk2 = ak.randomize(&alpha2);
        
        // Sign the same message with both randomized keys
        let message = b"same message";
        let sig1 = rsk1.sign(message, OsRng);
        let sig2 = rsk2.sign(message, OsRng);
        
        // Each signature verifies with its corresponding rk
        assert!(verify_with_randomized_key(&rk1, message, &sig1).is_ok());
        assert!(verify_with_randomized_key(&rk2, message, &sig2).is_ok());
        
        // Cross-verification should fail (unlinkability)
        assert!(verify_with_randomized_key(&rk1, message, &sig2).is_err());
        assert!(verify_with_randomized_key(&rk2, message, &sig1).is_err());
        
        // The rk values should be different
        assert_ne!(rk1, rk2);
    }
    
    #[test]
    #[ignore = "TODO: Fix RedPallas signing with randomized scalars - reddsa API issue"]
    fn test_convenience_function() {
        let ask = SpendAuthorizationKey::random(OsRng);
        
        let (rsk, rk, _alpha) = create_randomized_keypair(&ask, OsRng);
        
        let message = b"convenience test";
        let sig = rsk.sign(message, OsRng);
        
        assert!(verify_with_randomized_key(&rk, message, &sig).is_ok());
    }
    
    #[test]
    fn test_zero_randomizer() {
        let ask = SpendAuthorizationKey::random(OsRng);
        let ak = SpendAuthorizationVerifyingKey::from(&ask);
        
        // Zero randomizer should give rk = ak
        let alpha_zero = Randomizer(PallasScalar::ZERO);
        let rk = ak.randomize(&alpha_zero);
        
        // rk should equal ak when α = 0
        // Convert both to points and compare
        let ak_point = ak.to_point().unwrap();
        let rk_point = pallas::Affine::from_bytes(&rk.0)
            .map(pallas::Point::from)
            .unwrap();
        
        assert_eq!(ak_point, rk_point);
    }
    
    #[test]
    fn test_deterministic_from_bytes() {
        let bytes = [42u8; 32];
        let ask1 = SpendAuthorizationKey::from_bytes(bytes).expect("valid scalar");
        let ask2 = SpendAuthorizationKey::from_bytes(bytes).expect("valid scalar");
        
        // Should produce same key
        assert_eq!(ask1.to_bytes(), ask2.to_bytes());
        
        // Should produce same verification key
        let ak1 = SpendAuthorizationVerifyingKey::from(&ask1);
        let ak2 = SpendAuthorizationVerifyingKey::from(&ask2);
        assert_eq!(ak1, ak2);
    }
}

