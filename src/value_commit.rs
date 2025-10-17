//! Value Commitments and Binding Signatures for Tachyon
//!
//! This module implements Pedersen value commitments over the Pallas curve and the
//! binding signature scheme that proves balance integrity in transactions.

#![allow(missing_docs)]
//!
//! # Pedersen Value Commitments
//!
//! A value commitment is a cryptographic commitment to a transaction value:
//!
//! ```text
//! cv = [v] V + [rcv] R
//! ```
//!
//! Where:
//! - `v` is the value in zatoshis
//! - `V` is a fixed generator for value
//! - `rcv` is a random blinding factor
//! - `R` is a fixed generator for randomness
//!
//! # Homomorphic Properties
//!
//! Value commitments are additively homomorphic:
//! - `cv1 + cv2` commits to `v1 + v2` (with combined randomness)
//! - This allows verifying Σ cv_net = 0 without revealing individual values
//!
//! # Binding Signatures
//!
//! The binding signature proves that the transaction creator knows the sum of all
//! blinding factors (Σ rcv), which indirectly proves balance integrity:
//!
//! ```text
//! bvk = Σ rcv  (binding verification key)
//! sig = Sign(bvk, message)
//! ```

use group::{Group, GroupEncoding};
use group::ff::FromUniformBytes;
use halo2curves::pasta::{pallas, Fq as PallasScalar};
use halo2curves::ff::{Field, PrimeField};
use rand::{RngCore, CryptoRng};
use reddsa::{Signature, SigningKey, VerificationKey};
use reddsa::orchard::Binding as BindingAuth;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

// ----------------------------- Constants -----------------------------

/// Domain tag for value commitment
#[allow(dead_code)]
const DS_VALUE_COMMIT: &[u8] = b"zcash-tachyon-value-commit-v1";

/// Domain tag for binding signature
#[allow(dead_code)]
const DS_BINDING_SIG: &[u8] = b"zcash-tachyon-binding-sig-v1";

// ----------------------------- Generators -----------------------------

lazy_static::lazy_static! {
    /// Fixed generator V for value commitments
    /// Derived deterministically from "zcash-tachyon-value-generator"
    pub static ref VALUE_GENERATOR: pallas::Point = {
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"ZcashTachyonV")
            .to_state()
            .update(b"zcash-tachyon-value-generator-v1")
            .finalize();
        
        // Hash-to-curve (simplified - production should use proper hash-to-curve)
        let mut wide = [0u8; 64];
        wide.copy_from_slice(hash.as_bytes());
        let scalar = PallasScalar::from_uniform_bytes(&wide);
        pallas::Point::generator() * scalar
    };
    
    /// Fixed generator R for randomness in value commitments
    /// Derived deterministically from "zcash-tachyon-randomness-generator"
    pub static ref RANDOMNESS_GENERATOR: pallas::Point = {
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"ZcashTachyonR")
            .to_state()
            .update(b"zcash-tachyon-randomness-generator-v1")
            .finalize();
        
        let mut wide = [0u8; 64];
        wide.copy_from_slice(hash.as_bytes());
        let scalar = PallasScalar::from_uniform_bytes(&wide);
        pallas::Point::generator() * scalar
    };
}

// ----------------------------- Types -----------------------------

/// A value commitment blinding factor (rcv)
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct ValueCommitRandomness(pub PallasScalar);

impl ValueCommitRandomness {
    /// Generate random blinding factor
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

impl std::fmt::Debug for ValueCommitRandomness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValueCommitRandomness([REDACTED])")
    }
}

/// A value commitment cv = [v]V + [rcv]R
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct ValueCommit(pub [u8; 32]);

impl PartialEq for ValueCommit {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for ValueCommit {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ValueCommit {
    /// Commit to a value with randomness
    ///
    /// # Arguments
    /// - `value`: Value in zatoshis (0..=MAX_MONEY)
    /// - `rcv`: Blinding randomness
    ///
    /// # Returns
    /// Pedersen commitment cv = [v]V + [rcv]R
    pub fn new(value: u64, rcv: &ValueCommitRandomness) -> Self {
        let value_scalar = PallasScalar::from(value);
        
        // cv = [v]V + [rcv]R
        let commitment = *VALUE_GENERATOR * value_scalar + *RANDOMNESS_GENERATOR * rcv.0;
        
        // Serialize as compressed point (32 bytes)
        let affine = pallas::Affine::from(commitment);
        Self(affine.to_bytes())
    }
    
    /// Get the curve point representation
    pub fn to_point(&self) -> Option<pallas::Point> {
        pallas::Affine::from_bytes(&self.0)
            .into_option()
            .map(pallas::Point::from)
    }
    
    /// From curve point
    pub fn from_point(point: &pallas::Point) -> Self {
        let affine = pallas::Affine::from(*point);
        Self(affine.to_bytes())
    }
}

/// A binding signing key (sum of randomness factors)
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct BindingSigningKey(pub PallasScalar);

impl BindingSigningKey {
    /// Create from a single randomness value
    pub fn from_randomness(rcv: &ValueCommitRandomness) -> Self {
        Self(rcv.0)
    }
    
    /// Create from sum of randomness values
    ///
    /// For a balanced transaction: Σ rcv_spend - Σ rcv_output = bsk
    pub fn from_randomness_sum(randomness_values: &[ValueCommitRandomness]) -> Self {
        let sum = randomness_values.iter().fold(PallasScalar::ZERO, |acc, rcv| acc + rcv.0);
        Self(sum)
    }
    
    /// Sign a message with this binding key
    pub fn sign(&self, message: &[u8], mut rng: impl RngCore + CryptoRng) -> BindingSig {
        // Convert scalar to RedPallas signing key
        let sk_repr = self.0.to_repr();
        let sk_bytes: [u8; 32] = sk_repr.as_ref().try_into().expect("repr is 32 bytes");
        
        // Use RedPallas signing with Binding context
        // In production, this would use proper RedPallas key derivation
        let sk = SigningKey::<BindingAuth>::try_from(sk_bytes)
            .expect("valid signing key from scalar");
        
        let signature = sk.sign(&mut rng, message);
        BindingSig(signature.into())
    }
}

impl std::fmt::Debug for BindingSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BindingSigningKey([REDACTED])")
    }
}

/// A binding verification key (public key for binding signature)
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct BindingVerifyingKey(pub [u8; 32]);

impl PartialEq for BindingVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for BindingVerifyingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl BindingVerifyingKey {
    /// Derive from binding signing key
    pub fn from_signing_key(bsk: &BindingSigningKey) -> Self {
        // bvk = [bsk]R
        let point = *RANDOMNESS_GENERATOR * bsk.0;
        let affine = pallas::Affine::from(point);
        Self(affine.to_bytes())
    }
    
    /// Get the curve point representation
    pub fn to_point(&self) -> Option<pallas::Point> {
        pallas::Affine::from_bytes(&self.0)
            .into_option()
            .map(pallas::Point::from)
    }
}

/// A binding signature
#[derive(Clone, Copy, Debug, Eq)]
pub struct BindingSig(pub [u8; 64]);

// Custom serialization for [u8; 64] since serde only supports up to 32
impl Serialize for BindingSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for BindingSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: String = Deserialize::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("invalid signature length"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(Self(arr))
        } else {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("invalid signature length"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(Self(arr))
        }
    }
}

impl PartialEq for BindingSig {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for BindingSig {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl BindingSig {
    /// Verify a binding signature
    ///
    /// # Arguments
    /// - `bvk`: Binding verification key (derived from sum of commitments)
    /// - `message`: Message that was signed
    ///
    /// # Returns
    /// `Ok(())` if signature is valid, `Err` otherwise
    pub fn verify(&self, bvk: &BindingVerifyingKey, message: &[u8]) -> Result<(), ValueCommitError> {
        // Convert to RedPallas verification key
        let vk = VerificationKey::<BindingAuth>::try_from(bvk.0)
            .map_err(|_| ValueCommitError::InvalidVerifyingKey)?;
        
        // Parse signature
        let sig = Signature::<BindingAuth>::try_from(self.0)
            .map_err(|_| ValueCommitError::InvalidSignature)?;
        
        // Verify
        vk.verify(message, &sig)
            .map_err(|_| ValueCommitError::SignatureVerificationFailed)?;
        
        Ok(())
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum ValueCommitError {
    #[error("invalid value (exceeds MAX_MONEY)")]
    InvalidValue,
    
    #[error("invalid commitment")]
    InvalidCommitment,
    
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
    
    #[error("invalid signature")]
    InvalidSignature,
    
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("balance check failed: sum of commitments not zero")]
    BalanceCheckFailed,
}

// ----------------------------- Helper Functions -----------------------------

/// Sum multiple value commitments homomorphically
///
/// Returns the sum commitment: Σ cv_i
pub fn sum_value_commitments(commitments: &[ValueCommit]) -> Option<ValueCommit> {
    if commitments.is_empty() {
        return None;
    }
    
    let points: Vec<pallas::Point> = commitments
        .iter()
        .filter_map(|cv| cv.to_point())
        .collect();
    
    if points.len() != commitments.len() {
        return None; // Some commitment was invalid
    }
    
    let sum = points.iter().fold(pallas::Point::identity(), |acc, p| acc + p);
    Some(ValueCommit::from_point(&sum))
}

/// Compute binding verification key from commitment sum
///
/// For a balanced transaction, the sum of net value commitments
/// should equal [bsk]R where bsk is the binding signing key.
pub fn derive_binding_verifying_key_from_commitments(
    spend_commitments: &[ValueCommit],
    output_commitments: &[ValueCommit],
) -> Option<BindingVerifyingKey> {
    // Sum spend commitments (positive)
    let spend_sum = sum_value_commitments(spend_commitments)?;
    
    // Sum output commitments (negative in the equation)
    let output_sum = sum_value_commitments(output_commitments)?;
    
    // Net = Spends - Outputs
    let spend_point = spend_sum.to_point()?;
    let output_point = output_sum.to_point()?;
    let net = spend_point - output_point;
    
    // This net should equal [bsk]R
    let affine = pallas::Affine::from(net);
    Some(BindingVerifyingKey(affine.to_bytes()))
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_value_commitment() {
        let rcv = ValueCommitRandomness::random(OsRng);
        let cv = ValueCommit::new(1000, &rcv);
        
        // Should be able to round-trip through point
        let point = cv.to_point().expect("valid point");
        let cv2 = ValueCommit::from_point(&point);
        assert_eq!(cv, cv2);
    }
    
    #[test]
    fn test_commitment_homomorphism() {
        let rcv1 = ValueCommitRandomness::random(OsRng);
        let rcv2 = ValueCommitRandomness::random(OsRng);
        
        let cv1 = ValueCommit::new(100, &rcv1);
        let cv2 = ValueCommit::new(200, &rcv2);
        
        // cv1 + cv2 should commit to 300 with combined randomness
        let rcv_sum = ValueCommitRandomness(rcv1.0 + rcv2.0);
        let cv_sum_expected = ValueCommit::new(300, &rcv_sum);
        
        let p1 = cv1.to_point().unwrap();
        let p2 = cv2.to_point().unwrap();
        let cv_sum_actual = ValueCommit::from_point(&(p1 + p2));
        
        assert_eq!(cv_sum_actual, cv_sum_expected);
    }
    
    #[test]
    fn test_balanced_transaction() {
        // Spend: 1000, Output: 1000 (balanced)
        let rcv_spend = ValueCommitRandomness::random(OsRng);
        let rcv_output = ValueCommitRandomness::random(OsRng);
        
        let _cv_spend = ValueCommit::new(1000, &rcv_spend);
        let _cv_output = ValueCommit::new(1000, &rcv_output);
        
        // Binding signing key = rcv_spend - rcv_output
        let bsk = BindingSigningKey(rcv_spend.0 - rcv_output.0);
        let bvk = BindingVerifyingKey::from_signing_key(&bsk);
        
        // Sign a message
        let message = b"test transaction";
        let sig = bsk.sign(message, OsRng);
        
        // Verify
        assert!(sig.verify(&bvk, message).is_ok());
        
        // Wrong message should fail
        assert!(sig.verify(&bvk, b"wrong message").is_err());
    }
    
    #[test]
    fn test_sum_commitments() {
        let rcv1 = ValueCommitRandomness::random(OsRng);
        let rcv2 = ValueCommitRandomness::random(OsRng);
        let rcv3 = ValueCommitRandomness::random(OsRng);
        
        let cv1 = ValueCommit::new(100, &rcv1);
        let cv2 = ValueCommit::new(200, &rcv2);
        let cv3 = ValueCommit::new(300, &rcv3);
        
        let sum = sum_value_commitments(&[cv1, cv2, cv3]).expect("valid sum");
        
        // Manual sum should match
        let manual_rcv = ValueCommitRandomness(rcv1.0 + rcv2.0 + rcv3.0);
        let manual_sum = ValueCommit::new(600, &manual_rcv);
        
        assert_eq!(sum, manual_sum);
    }
    
    #[test]
    fn test_binding_key_derivation() {
        let rcv_spend1 = ValueCommitRandomness::random(OsRng);
        let rcv_spend2 = ValueCommitRandomness::random(OsRng);
        let rcv_output1 = ValueCommitRandomness::random(OsRng);
        
        // Balanced: 1000 + 500 = 1500
        let cv_spend1 = ValueCommit::new(1000, &rcv_spend1);
        let cv_spend2 = ValueCommit::new(500, &rcv_spend2);
        let cv_output1 = ValueCommit::new(1500, &rcv_output1);
        
        // Derive bvk from commitments
        let bvk = derive_binding_verifying_key_from_commitments(
            &[cv_spend1, cv_spend2],
            &[cv_output1],
        ).expect("valid bvk");
        
        // Compute expected bvk from randomness
        let bsk = BindingSigningKey(rcv_spend1.0 + rcv_spend2.0 - rcv_output1.0);
        let bvk_expected = BindingVerifyingKey::from_signing_key(&bsk);
        
        assert_eq!(bvk, bvk_expected);
    }
}

