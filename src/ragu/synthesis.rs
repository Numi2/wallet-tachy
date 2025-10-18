//! Circuit synthesis utilities and helpers

use super::*;

// ============================================================================
// Circuit Composition
// ============================================================================

/// Trait for composable circuits
pub trait Composable<F: Field>: Circuit<F> {
    /// Compose this circuit with another circuit
    fn compose<C: Circuit<F>>(self, other: C) -> ComposedCircuit<F, Self, C>
    where
        Self: Sized,
    {
        ComposedCircuit {
            first: self,
            second: other,
            _marker: PhantomData,
        }
    }
}

// Blanket implementation for all circuits
impl<F: Field, C: Circuit<F>> Composable<F> for C {}

/// A circuit composed of two sub-circuits
pub struct ComposedCircuit<F: Field, C1: Circuit<F>, C2: Circuit<F>> {
    first: C1,
    second: C2,
    _marker: PhantomData<F>,
}

// ============================================================================
// Synthesis Helpers
// ============================================================================

/// Helper for synthesizing a circuit with both prover and verifier drivers
pub struct SynthesisHelper<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> SynthesisHelper<F> {
    /// Synthesize a circuit in proving mode
    pub fn synthesize_prover<C: Circuit<F>>(
        circuit: &C,
        instance: C::Instance<'_>,
        witness: C::Witness<'_>,
    ) -> Result<ProverDriver<F>, Error> {
        let mut prover = ProverDriver::new();
        
        let input_witness = Witness::new(instance);
        let witness_data = Witness::new(witness);
        
        let io = circuit.input(&mut prover, input_witness)?;
        let (_main_io, _aux) = circuit.main(&mut prover, witness_data)?;
        
        let mut output = prover.new_io();
        circuit.output(&mut prover, io, &mut output)?;
        
        Ok(prover)
    }
    
    /// Synthesize a circuit in verification mode (no witness)
    pub fn synthesize_verifier<C: Circuit<F>>(
        circuit: &C,
    ) -> Result<VerifierDriver<F>, Error> {
        let mut verifier = VerifierDriver::new();
        
        let io = circuit.input(&mut verifier, Witness::empty())?;
        let (_main_io, _aux) = circuit.main(&mut verifier, Witness::empty())?;
        
        let mut output = verifier.new_io();
        circuit.output(&mut verifier, io, &mut output)?;
        
        Ok(verifier)
    }
    
    /// Check that prover and verifier generate the same constraint structure
    pub fn check_consistency<C: Circuit<F>>(
        circuit: &C,
        instance: C::Instance<'_>,
        witness: C::Witness<'_>,
    ) -> Result<bool, Error> {
        let prover = Self::synthesize_prover(circuit, instance, witness)?;
        let verifier = Self::synthesize_verifier(circuit)?;
        
        Ok(prover.cs.num_constraints() == verifier.cs.num_constraints()
            && prover.cs.num_variables == verifier.cs.num_variables)
    }
}

// ============================================================================
// Circuit Statistics
// ============================================================================

/// Statistics about a synthesized circuit
#[derive(Clone, Debug)]
pub struct CircuitStats {
    /// Number of variables
    pub num_variables: usize,
    
    /// Number of constraints
    pub num_constraints: usize,
    
    /// Number of public inputs
    pub num_public_inputs: usize,
    
    /// Number of witness values (prover only)
    pub num_witness_values: Option<usize>,
}

impl CircuitStats {
    /// Extract statistics from a prover driver
    pub fn from_prover<F: Field>(driver: &ProverDriver<F>) -> Self {
        Self {
            num_variables: driver.cs.num_variables,
            num_constraints: driver.cs.num_constraints(),
            num_public_inputs: driver.cs.num_public_inputs,
            num_witness_values: Some(driver.assignments.len()),
        }
    }
    
    /// Extract statistics from a verifier driver
    pub fn from_verifier<F: Field>(driver: &VerifierDriver<F>) -> Self {
        Self {
            num_variables: driver.cs.num_variables,
            num_constraints: driver.cs.num_constraints(),
            num_public_inputs: driver.cs.num_public_inputs,
            num_witness_values: None,
        }
    }
    
    /// Calculate the density of the constraint system
    pub fn density(&self) -> f64 {
        if self.num_variables == 0 {
            return 0.0;
        }
        self.num_constraints as f64 / self.num_variables as f64
    }
}

impl fmt::Display for CircuitStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Circuit Statistics:")?;
        writeln!(f, "  Variables:    {}", self.num_variables)?;
        writeln!(f, "  Constraints:  {}", self.num_constraints)?;
        writeln!(f, "  Public inputs: {}", self.num_public_inputs)?;
        if let Some(witness_count) = self.num_witness_values {
            writeln!(f, "  Witness values: {}", witness_count)?;
        }
        writeln!(f, "  Density:      {:.2}", self.density())?;
        Ok(())
    }
}

// ============================================================================
// Constraint Verification
// ============================================================================

/// Verify that a witness satisfies all constraints
pub struct ConstraintVerifier<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> ConstraintVerifier<F> {
    /// Verify all constraints in a prover driver
    pub fn verify(driver: &ProverDriver<F>) -> Result<bool, Error> {
        for (idx, constraint) in driver.cs.constraints.iter().enumerate() {
            let satisfied = Self::verify_constraint(constraint, &driver.assignments)?;
            if !satisfied {
                return Err(Error::SynthesisError(
                    format!("Constraint {} not satisfied", idx)
                ));
            }
        }
        Ok(true)
    }
    
    /// Verify a single R1CS constraint
    fn verify_constraint(
        constraint: &R1CSConstraint<F>,
        assignments: &[F],
    ) -> Result<bool, Error> {
        let a_val = Self::eval_lc(&constraint.a, assignments)?;
        let b_val = Self::eval_lc(&constraint.b, assignments)?;
        let c_val = Self::eval_lc(&constraint.c, assignments)?;
        
        // Check a * b = c, i.e., a * b - c = 0
        let product = a_val.mul(&b_val);
        Ok(product.sub(&c_val).is_zero())
    }
    
    /// Evaluate a linear combination with bounds checking
    /// 
    /// # Security
    /// CRITICAL: Returns error if any variable index is out of bounds.
    /// This prevents silent failures that could hide constraint system bugs.
    fn eval_lc(lc: &LinearCombination<F>, assignments: &[F]) -> Result<F, Error> {
        let mut result = F::zero();
        for (coeff, var_idx) in lc.terms() {
            if *var_idx >= assignments.len() {
                return Err(Error::SynthesisError(
                    format!(
                        "Variable index {} out of bounds (assignment length: {})", 
                        var_idx, 
                        assignments.len()
                    )
                ));
            }
            let term = coeff.mul(&assignments[*var_idx]);
            result = result.add(&term);
        }
        Ok(result)
    }
}

// ============================================================================
// Witness Builder
// ============================================================================

/// Helper for incrementally building witness data
pub struct WitnessBuilder<F: Field> {
    values: Vec<F>,
}

impl<F: Field> WitnessBuilder<F> {
    /// Create a new witness builder
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }
    
    /// Add a field element to the witness
    pub fn push(&mut self, value: F) {
        self.values.push(value);
    }
    
    /// Add multiple field elements
    pub fn extend(&mut self, values: impl IntoIterator<Item = F>) {
        self.values.extend(values);
    }
    
    /// Get the number of witness values
    pub fn len(&self) -> usize {
        self.values.len()
    }
    
    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
    
    /// Get a reference to the witness values
    pub fn values(&self) -> &[F] {
        &self.values
    }
    
    /// Consume the builder and return the witness values
    pub fn build(self) -> Vec<F> {
        self.values
    }
}

impl<F: Field> Default for WitnessBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ragu::fields::TestField;
    use crate::ragu::circuits::SimpleCircuit;
    
    #[test]
    fn test_synthesis_helper() {
        let circuit = SimpleCircuit;
        
        let instance = ();
        let witness = (TestField::new(2), TestField::new(3), TestField::new(4));
        
        let prover = SynthesisHelper::synthesize_prover(
            &circuit,
            instance,
            witness,
        ).expect("Prover synthesis failed");
        
        assert!(prover.cs.num_constraints() > 0);
        assert!(prover.cs.num_variables > 0);
    }
    
    #[test]
    fn test_consistency_check() {
        let circuit = SimpleCircuit;
        
        let instance = ();
        let witness = (TestField::new(2), TestField::new(3), TestField::new(4));
        
        let consistent = SynthesisHelper::check_consistency(
            &circuit,
            instance,
            witness,
        ).expect("Consistency check failed");
        
        assert!(consistent, "Prover and verifier should generate same structure");
    }
    
    #[test]
    fn test_circuit_stats() {
        let mut prover = ProverDriver::<TestField>::new();
        
        let a = prover.alloc(Witness::new(TestField::new(5))).unwrap();
        let b = prover.alloc(Witness::new(TestField::new(7))).unwrap();
        let _c = prover.mul(a, b).unwrap();
        
        let stats = CircuitStats::from_prover(&prover);
        
        assert!(stats.num_variables > 0);
        assert!(stats.num_constraints > 0);
        assert_eq!(stats.num_witness_values, Some(prover.assignments.len()));
    }
    
    #[test]
    fn test_witness_builder() {
        let mut builder = WitnessBuilder::<TestField>::new();
        
        builder.push(TestField::new(1));
        builder.push(TestField::new(2));
        builder.extend([TestField::new(3), TestField::new(4)]);
        
        assert_eq!(builder.len(), 4);
        
        let values = builder.build();
        assert_eq!(values.len(), 4);
    }
}

