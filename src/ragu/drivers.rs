//! Concrete Driver implementations for different contexts

use super::*;
use zeroize::Zeroize;

// ============================================================================
// Wire Types
// ============================================================================

/// A wire in the proving context (has witness value)
#[derive(Clone, Debug)]
pub struct ProverWire<F: Field> {
    /// Variable index in the constraint system
    pub index: usize,
    /// The witness value
    pub value: F,
}

/// A wire in the verification context (no witness value)
#[derive(Clone, Debug)]
pub struct VerifierWire {
    /// Variable index in the constraint system
    pub index: usize,
}

/// A wire for public input computation
#[derive(Clone, Debug)]
pub struct PublicInputWire<F: Field> {
    /// Variable index
    pub index: usize,
    /// Value (if known)
    pub value: Option<F>,
}

// ============================================================================
// Prover Driver
// ============================================================================

/// Driver for proof generation context.
///
/// Maintains both the constraint system structure and witness values.
pub struct ProverDriver<F: Field> {
    /// The constraint system being built
    pub cs: ConstraintSystem<F>,
    /// Witness assignments for all variables
    pub assignments: Vec<F>,
}

impl<F: Field> ProverDriver<F> {
    /// Create a new prover driver
    pub fn new() -> Self {
        let mut cs = ConstraintSystem::new();
        let mut assignments = Vec::new();
        
        // Allocate variable 0 as constant 1
        // This is a standard R1CS convention
        let _one_var = cs.alloc_variable();
        assignments.push(F::one());
        
        Self {
            cs,
            assignments,
        }
    }
    
    /// Get the witness value for a wire
    fn get_value(&self, wire: &ProverWire<F>) -> F {
        wire.value
    }
}

impl<F: Field> Default for ProverDriver<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> Driver for ProverDriver<F> {
    type F = F;
    type W = ProverWire<F>;
    type MaybeKind = WithWitness;
    type IO = VecSink<Self::W>;
    
    fn alloc(&mut self, value: Witness<Self, F>) -> Result<Self::W, Error> {
        let val = value
            .get()
            .copied()
            .ok_or_else(|| Error::InvalidWitness("Expected witness value".to_string()))?;
        
        let index = self.cs.alloc_variable();
        self.assignments.push(val);
        
        Ok(ProverWire { index, value: val })
    }
    
    fn alloc_const(&mut self, value: F) -> Result<Self::W, Error> {
        let index = self.cs.alloc_variable();
        self.assignments.push(value);
        
        Ok(ProverWire { index, value })
    }
    
    fn add(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let result_value = a.value.add(&b.value);
        let result_index = self.cs.alloc_variable();
        self.assignments.push(result_value);
        
        // Add constraint: a + b = result
        // This can be encoded as: (1, a+b, result) constraint
        // For R1CS: 1 * (a + b) = result
        let mut lc_ab = LinearCombination::zero();
        lc_ab.add_term(F::one(), a.index);
        lc_ab.add_term(F::one(), b.index);
        
        let one = LinearCombination::single(F::one(), 0); // Assuming var 0 is constant 1
        let result_lc = LinearCombination::single(F::one(), result_index);
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc_ab,
            c: result_lc,
        })?;
        
        Ok(ProverWire {
            index: result_index,
            value: result_value,
        })
    }
    
    fn mul(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let result_value = a.value.mul(&b.value);
        let result_index = self.cs.alloc_variable();
        self.assignments.push(result_value);
        
        // Add constraint: a * b = result
        let lc_a = LinearCombination::single(F::one(), a.index);
        let lc_b = LinearCombination::single(F::one(), b.index);
        let lc_result = LinearCombination::single(F::one(), result_index);
        
        self.cs.add_constraint(R1CSConstraint {
            a: lc_a,
            b: lc_b,
            c: lc_result,
        })?;
        
        Ok(ProverWire {
            index: result_index,
            value: result_value,
        })
    }
    
    fn neg(&mut self, a: Self::W) -> Result<Self::W, Error> {
        let result_value = a.value.neg();
        let result_index = self.cs.alloc_variable();
        self.assignments.push(result_value);
        
        // Constraint: -a = result, or a + result = 0
        // Encoded as: 1 * (a + result) = 0
        let mut lc = LinearCombination::zero();
        lc.add_term(F::one(), a.index);
        lc.add_term(F::one(), result_index);
        
        let one = LinearCombination::single(F::one(), 0);
        let zero = LinearCombination::zero();
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc,
            c: zero,
        })?;
        
        Ok(ProverWire {
            index: result_index,
            value: result_value,
        })
    }
    
    fn enforce_zero(&mut self, a: Self::W) -> Result<(), Error> {
        // SECURITY: Add constraint FIRST to ensure consistency
        // Even if witness check fails, the constraint system structure
        // remains valid and can be reused for verification
        
        // Add constraint: a = 0
        // Encoded as: 1 * a = 0
        let one = LinearCombination::single(F::one(), 0);
        let lc_a = LinearCombination::single(F::one(), a.index);
        let zero = LinearCombination::zero();
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc_a,
            c: zero,
        })?;
        
        // THEN check witness satisfies the constraint without leaking details
        // Avoid including sensitive indices/values in error messages
        if !a.value.is_zero() {
            return Err(Error::SynthesisError("Constraint violation: expected zero".to_string()));
        }
        
        Ok(())
    }
    
    fn new_io(&self) -> Self::IO {
        VecSink::new()
    }
}

// Zeroize prover assignments on drop where supported
impl<F> Drop for ProverDriver<F>
where
    F: Field + Zeroize,
{
    fn drop(&mut self) {
        // Best-effort zeroization of witness assignments
        self.assignments.zeroize();
    }
}

// ============================================================================
// Verifier Driver
// ============================================================================

/// Driver for verification context.
///
/// Only builds the constraint system structure, no witness values.
pub struct VerifierDriver<F: Field> {
    /// The constraint system structure
    pub cs: ConstraintSystem<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> VerifierDriver<F> {
    /// Create a new verifier driver
    pub fn new() -> Self {
        let mut cs = ConstraintSystem::new();
        
        // Allocate variable 0 as constant 1
        // This is a standard R1CS convention
        let _one_var = cs.alloc_variable();
        
        Self {
            cs,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Default for VerifierDriver<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> Driver for VerifierDriver<F> {
    type F = F;
    type W = VerifierWire;
    type MaybeKind = WithoutWitness;
    type IO = VecSink<Self::W>;
    
    fn alloc(&mut self, _value: Witness<Self, F>) -> Result<Self::W, Error> {
        // No witness in verification context
        let index = self.cs.alloc_variable();
        Ok(VerifierWire { index })
    }
    
    fn alloc_const(&mut self, _value: F) -> Result<Self::W, Error> {
        let index = self.cs.alloc_variable();
        Ok(VerifierWire { index })
    }
    
    fn add(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let result_index = self.cs.alloc_variable();
        
        // Add constraint structure (no values)
        let mut lc_ab = LinearCombination::zero();
        lc_ab.add_term(F::one(), a.index);
        lc_ab.add_term(F::one(), b.index);
        
        let one = LinearCombination::single(F::one(), 0);
        let result_lc = LinearCombination::single(F::one(), result_index);
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc_ab,
            c: result_lc,
        })?;
        
        Ok(VerifierWire { index: result_index })
    }
    
    fn mul(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let result_index = self.cs.alloc_variable();
        
        let lc_a = LinearCombination::single(F::one(), a.index);
        let lc_b = LinearCombination::single(F::one(), b.index);
        let lc_result = LinearCombination::single(F::one(), result_index);
        
        self.cs.add_constraint(R1CSConstraint {
            a: lc_a,
            b: lc_b,
            c: lc_result,
        })?;
        
        Ok(VerifierWire { index: result_index })
    }
    
    fn neg(&mut self, a: Self::W) -> Result<Self::W, Error> {
        let result_index = self.cs.alloc_variable();
        
        let mut lc = LinearCombination::zero();
        lc.add_term(F::one(), a.index);
        lc.add_term(F::one(), result_index);
        
        let one = LinearCombination::single(F::one(), 0);
        let zero = LinearCombination::zero();
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc,
            c: zero,
        })?;
        
        Ok(VerifierWire { index: result_index })
    }
    
    fn enforce_zero(&mut self, a: Self::W) -> Result<(), Error> {
        // Just add the constraint structure
        let one = LinearCombination::single(F::one(), 0);
        let lc_a = LinearCombination::single(F::one(), a.index);
        let zero = LinearCombination::zero();
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc_a,
            c: zero,
        })?;
        
        Ok(())
    }
    
    fn new_io(&self) -> Self::IO {
        VecSink::new()
    }
}

// ============================================================================
// PublicInput Driver
// ============================================================================

/// Driver for computing public inputs.
///
/// Similar to prover but may not have all witness values.
pub struct PublicInputDriver<F: Field> {
    /// Constraint system
    pub cs: ConstraintSystem<F>,
    /// Known values
    pub values: Vec<Option<F>>,
}

impl<F: Field> PublicInputDriver<F> {
    /// Create a new public input driver
    pub fn new() -> Self {
        let mut cs = ConstraintSystem::new();
        let mut values = Vec::new();
        
        // Allocate variable 0 as constant 1
        // This is a standard R1CS convention
        let _one_var = cs.alloc_variable();
        values.push(Some(F::one()));
        
        Self {
            cs,
            values,
        }
    }
}

impl<F: Field> Default for PublicInputDriver<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> Driver for PublicInputDriver<F> {
    type F = F;
    type W = PublicInputWire<F>;
    type MaybeKind = WithWitness; // May have partial witness
    type IO = VecSink<Self::W>;
    
    fn alloc(&mut self, value: Witness<Self, F>) -> Result<Self::W, Error> {
        let val = value.get().copied();
        let index = self.cs.alloc_variable();
        self.values.push(val);
        
        Ok(PublicInputWire { index, value: val })
    }
    
    fn alloc_const(&mut self, value: F) -> Result<Self::W, Error> {
        let index = self.cs.alloc_variable();
        self.values.push(Some(value));
        
        Ok(PublicInputWire {
            index,
            value: Some(value),
        })
    }
    
    fn add(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let result_value = match (a.value, b.value) {
            (Some(av), Some(bv)) => Some(av.add(&bv)),
            _ => None,
        };
        
        let result_index = self.cs.alloc_variable();
        self.values.push(result_value);
        
        let mut lc_ab = LinearCombination::zero();
        lc_ab.add_term(F::one(), a.index);
        lc_ab.add_term(F::one(), b.index);
        
        let one = LinearCombination::single(F::one(), 0);
        let result_lc = LinearCombination::single(F::one(), result_index);
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc_ab,
            c: result_lc,
        })?;
        
        Ok(PublicInputWire {
            index: result_index,
            value: result_value,
        })
    }
    
    fn mul(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let result_value = match (a.value, b.value) {
            (Some(av), Some(bv)) => Some(av.mul(&bv)),
            _ => None,
        };
        
        let result_index = self.cs.alloc_variable();
        self.values.push(result_value);
        
        let lc_a = LinearCombination::single(F::one(), a.index);
        let lc_b = LinearCombination::single(F::one(), b.index);
        let lc_result = LinearCombination::single(F::one(), result_index);
        
        self.cs.add_constraint(R1CSConstraint {
            a: lc_a,
            b: lc_b,
            c: lc_result,
        })?;
        
        Ok(PublicInputWire {
            index: result_index,
            value: result_value,
        })
    }
    
    fn neg(&mut self, a: Self::W) -> Result<Self::W, Error> {
        let result_value = a.value.map(|v| v.neg());
        
        let result_index = self.cs.alloc_variable();
        self.values.push(result_value);
        
        let mut lc = LinearCombination::zero();
        lc.add_term(F::one(), a.index);
        lc.add_term(F::one(), result_index);
        
        let one = LinearCombination::single(F::one(), 0);
        let zero = LinearCombination::zero();
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc,
            c: zero,
        })?;
        
        Ok(PublicInputWire {
            index: result_index,
            value: result_value,
        })
    }
    
    fn enforce_zero(&mut self, a: Self::W) -> Result<(), Error> {
        // SECURITY: Add constraint FIRST to ensure consistency
        let one = LinearCombination::single(F::one(), 0);
        let lc_a = LinearCombination::single(F::one(), a.index);
        let zero = LinearCombination::zero();
        
        self.cs.add_constraint(R1CSConstraint {
            a: one,
            b: lc_a,
            c: zero,
        })?;
        
        // THEN check witness if available without leaking indices/values
        if let Some(val) = a.value {
            if !val.is_zero() {
                return Err(Error::SynthesisError("Constraint violation: expected zero".to_string()));
            }
        }
        
        Ok(())
    }
    
    fn new_io(&self) -> Self::IO {
        VecSink::new()
    }
}

