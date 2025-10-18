//! Field implementations for common curves
//!
//! # ⚠️ SECURITY WARNING: Constant-Time Operations ⚠️
//!
//! This module implements field arithmetic for use in zero-knowledge proofs.
//! **Timing side-channel attacks are a CRITICAL security concern.**
//!
//! ## Current Status:
//! - **TestField**: NOT constant-time (testing only, never use with secrets)
//! - **PallasField/VestaField**: Depend on halo2curves implementation
//!
//! ## Requirements for Production:
//! 1. All field operations on secret data MUST be constant-time
//! 2. Comparisons (is_zero, invert) MUST NOT branch on secret values
//! 3. Use `subtle` crate or similar for conditional operations
//! 4. Regular timing analysis and audits required
//!
//! ## Known Issues:
//! - TestField::invert() uses variable-time Extended Euclidean Algorithm
//! - Early returns in conditional logic leak timing information
//! - Loop iterations may vary based on input values
//!
//! **ACTION REQUIRED**: Audit halo2curves for constant-time guarantees before
//! deploying with secret witness data (spending keys, note values, etc.)

use super::*;

// Import halo2curves for Pallas/Vesta field implementations
use halo2curves::pasta::{Fp as PallasFp, Fq as VestaFq};
use halo2curves::ff::Field as Halo2Field;

// Constant-time operations
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

// ============================================================================
// Wrapper for Pallas/Vesta Fields
// ============================================================================

/// Wrapper for halo2curves Pallas base field (Fp)
/// 
/// halo2curves is already a dependency, so these wrappers are always available.
/// 
/// # Security: Constant-Time Operations
/// 
/// The underlying halo2curves::pasta::Fp implementation uses constant-time
/// arithmetic operations. The is_zero() and invert() methods use subtle::Choice
/// internally for conditional logic, making them timing-safe for secret data.
#[derive(Clone, Copy, Debug)]
pub struct PallasField(pub PallasFp);

impl Field for PallasField {
    fn zero() -> Self {
        PallasField(Halo2Field::ZERO)
    }
    
    fn one() -> Self {
        PallasField(Halo2Field::ONE)
    }
    
    fn add(&self, other: &Self) -> Self {
        PallasField(self.0 + other.0)
    }
    
    fn sub(&self, other: &Self) -> Self {
        PallasField(self.0 - other.0)
    }
    
    fn mul(&self, other: &Self) -> Self {
        PallasField(self.0 * other.0)
    }
    
    fn neg(&self) -> Self {
        PallasField(-self.0)
    }
    
    fn invert(&self) -> Option<Self> {
        // SECURITY: halo2curves uses constant-time inversion via Fermat's little theorem
        // This avoids timing leaks from Extended Euclidean Algorithm
        self.0.invert().into_option().map(PallasField)
    }
    
    fn is_zero(&self) -> bool {
        // SECURITY: halo2curves implements is_zero() using subtle::Choice
        // This is constant-time and doesn't leak via branches
        bool::from(self.0.is_zero())
    }
}

// Implement constant-time equality
impl ConstantTimeEq for PallasField {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for PallasField {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        PallasField(PallasFp::conditional_select(&a.0, &b.0, choice))
    }
}

impl Zeroize for PallasField {
    fn zeroize(&mut self) {
        // PallasFp implements Zeroize via repr bytes clearing is not available; best-effort set to zero
        self.0 = Halo2Field::ZERO;
    }
}

/// Wrapper for halo2curves Vesta base field (Fq)
/// 
/// # Security: Constant-Time Operations
/// 
/// Same security guarantees as PallasField - uses constant-time arithmetic.
#[derive(Clone, Copy, Debug)]
pub struct VestaField(pub VestaFq);

impl Field for VestaField {
    fn zero() -> Self {
        VestaField(Halo2Field::ZERO)
    }
    
    fn one() -> Self {
        VestaField(Halo2Field::ONE)
    }
    
    fn add(&self, other: &Self) -> Self {
        VestaField(self.0 + other.0)
    }
    
    fn sub(&self, other: &Self) -> Self {
        VestaField(self.0 - other.0)
    }
    
    fn mul(&self, other: &Self) -> Self {
        VestaField(self.0 * other.0)
    }
    
    fn neg(&self) -> Self {
        VestaField(-self.0)
    }
    
    fn invert(&self) -> Option<Self> {
        // SECURITY: Constant-time inversion via Fermat's little theorem
        self.0.invert().into_option().map(VestaField)
    }
    
    fn is_zero(&self) -> bool {
        // SECURITY: Constant-time zero check using subtle::Choice
        bool::from(self.0.is_zero())
    }
}

// Implement constant-time equality
impl ConstantTimeEq for VestaField {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for VestaField {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        VestaField(VestaFq::conditional_select(&a.0, &b.0, choice))
    }
}

impl Zeroize for VestaField {
    fn zeroize(&mut self) {
        self.0 = Halo2Field::ZERO;
    }
}

// ============================================================================
// Simple test field (u64 mod p for testing)
// ============================================================================

/// Simple field implementation for testing (u64 mod small prime)
/// 
/// # ⚠️ SECURITY WARNING: NOT CONSTANT-TIME ⚠️
/// 
/// **DO NOT USE WITH SECRET DATA**
/// 
/// This field is for testing and development only. It contains multiple
/// timing side-channels:
/// - Variable-time modular reduction
/// - Branch-based subtraction
/// - Extended Euclidean Algorithm in invert()
/// - Early returns based on values
/// 
/// **Use PallasField or VestaField for production code with secrets.**
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestField(pub u64);

impl TestField {
    // Use a small prime for testing: 2^31 - 1
    const MODULUS: u64 = 2147483647;
    
    /// Create from u64
    pub fn new(value: u64) -> Self {
        TestField(value % Self::MODULUS)
    }
    
    /// Get raw value
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl Field for TestField {
    fn zero() -> Self {
        TestField(0)
    }
    
    fn one() -> Self {
        TestField(1)
    }
    
    fn add(&self, other: &Self) -> Self {
        // Use checked arithmetic to prevent overflow
        let sum = (self.0 as u128 + other.0 as u128) % Self::MODULUS as u128;
        TestField(sum as u64)
    }
    
    fn sub(&self, other: &Self) -> Self {
        // SECURITY: Fixed overflow issue by using safer calculation order
        // Old: MODULUS - (other.0 - self.0) could overflow
        // New: (MODULUS - other.0) + self.0 is safe
        let result = if self.0 >= other.0 {
            self.0 - other.0
        } else {
            // Calculate in safe order: (MODULUS - other) + self
            let diff_from_mod = Self::MODULUS - other.0;
            (diff_from_mod + self.0) % Self::MODULUS
        };
        TestField(result)
    }
    
    fn mul(&self, other: &Self) -> Self {
        TestField(((self.0 as u128 * other.0 as u128) % Self::MODULUS as u128) as u64)
    }
    
    fn neg(&self) -> Self {
        if self.0 == 0 {
            TestField(0)
        } else {
            TestField(Self::MODULUS - self.0)
        }
    }
    
    fn invert(&self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        
        // Extended Euclidean algorithm for modular inverse
        let mut t = 0i128;
        let mut new_t = 1i128;
        let mut r = Self::MODULUS as i128;
        let mut new_r = self.0 as i128;
        
        while new_r != 0 {
            let quotient = r / new_r;
            let temp_t = t;
            t = new_t;
            new_t = temp_t - quotient * new_t;
            
            let temp_r = r;
            r = new_r;
            new_r = temp_r - quotient * new_r;
        }
        
        if r > 1 {
            return None; // Not invertible
        }
        
        if t < 0 {
            t += Self::MODULUS as i128;
        }
        
        Some(TestField(t as u64))
    }
    
    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl Zeroize for TestField {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_arithmetic() {
        let a = TestField::new(5);
        let b = TestField::new(3);
        
        // Addition
        assert_eq!(a.add(&b).value(), 8);
        
        // Subtraction
        assert_eq!(a.sub(&b).value(), 2);
        
        // Multiplication
        assert_eq!(a.mul(&b).value(), 15);
        
        // Negation
        let neg_a = a.neg();
        assert_eq!(a.add(&neg_a).value(), 0);
    }
    
    #[test]
    fn test_field_inverse() {
        let a = TestField::new(7);
        let a_inv = a.invert().expect("Should be invertible");
        
        // a * a^-1 = 1
        assert_eq!(a.mul(&a_inv).value(), 1);
    }
    
    #[test]
    fn test_field_zero_one() {
        let zero = TestField::zero();
        let one = TestField::one();
        
        assert!(zero.is_zero());
        assert!(!one.is_zero());
        
        let a = TestField::new(42);
        assert_eq!(a.add(&zero).value(), a.value());
        assert_eq!(a.mul(&one).value(), a.value());
    }
}

