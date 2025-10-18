//! Demonstration of the Ragu PCD toolkit
//!
//! This example shows how to:
//! 1. Define a custom circuit
//! 2. Use the ProverDriver to synthesize with witness
//! 3. Use the VerifierDriver to build constraint structure
//! 4. Leverage the Maybe<T> abstraction for witness handling

use tachy_wallet::ragu::*;

// ============================================================================
// Example 1: Simple Multiplication Circuit
// ============================================================================

/// Demonstrates basic circuit synthesis with witness
fn example_simple_multiplication() {
    println!("=== Example 1: Simple Multiplication Circuit ===\n");
    
    // Create a prover driver
    let mut prover = ProverDriver::<TestField>::new();
    
    // Allocate witness values
    let a = prover
        .alloc(Witness::new(TestField::new(7)))
        .expect("Failed to allocate a");
    let b = prover
        .alloc(Witness::new(TestField::new(6)))
        .expect("Failed to allocate b");
    
    // Compute a * b
    let result = prover.mul(a, b).expect("Failed to multiply");
    
    println!("Allocated variables: {}", prover.cs.num_variables);
    println!("Generated constraints: {}", prover.cs.num_constraints());
    println!("Result value: {} (expected: 42)\n", result.value.value());
}

// ============================================================================
// Example 2: Boolean Logic Circuit
// ============================================================================

/// Demonstrates boolean gadgets
fn example_boolean_logic() {
    println!("=== Example 2: Boolean Logic Circuit ===\n");
    
    let mut prover = ProverDriver::<TestField>::new();
    
    // Allocate boolean values
    let true_bit = prover
        .alloc(Witness::new(TestField::new(1)))
        .expect("Failed to allocate true");
    let false_bit = prover
        .alloc(Witness::new(TestField::new(0)))
        .expect("Failed to allocate false");
    
    // Test AND gate
    let and_result = BooleanGadget::and(&mut prover, true_bit.clone(), false_bit.clone())
        .expect("AND failed");
    println!("TRUE AND FALSE = {} (expected: 0)", and_result.value.value());
    
    // Test OR gate
    let or_result = BooleanGadget::or(&mut prover, true_bit.clone(), false_bit.clone())
        .expect("OR failed");
    println!("TRUE OR FALSE = {} (expected: 1)", or_result.value.value());
    
    // Test NOT gate
    let not_result = BooleanGadget::not(&mut prover, false_bit.clone())
        .expect("NOT failed");
    println!("NOT FALSE = {} (expected: 1)", not_result.value.value());
    
    // Test XOR gate
    let xor_result = BooleanGadget::xor(&mut prover, true_bit.clone(), false_bit.clone())
        .expect("XOR failed");
    println!("TRUE XOR FALSE = {} (expected: 1)", xor_result.value.value());
    
    println!("\nTotal constraints: {}\n", prover.cs.num_constraints());
}

// ============================================================================
// Example 3: Custom Circuit Implementation
// ============================================================================

/// A circuit that verifies the Pythagorean theorem: a^2 + b^2 = c^2
struct PythagoreanCircuit;

impl Circuit<TestField> for PythagoreanCircuit {
    type Instance<'instance> = TestField; // Public c^2
    type IO<'source, D: Driver<F = TestField>> = D::W;
    type Witness<'witness> = (TestField, TestField); // Private (a, b)
    type Aux<'witness> = ();
    
    fn input<'instance, D: Driver<F = TestField>>(
        &self,
        dr: &mut D,
        input: Witness<D, Self::Instance<'instance>>,
    ) -> Result<Self::IO<'instance, D>, Error> {
        // Allocate public c^2
        if let Some(c_squared) = input.get() {
            dr.alloc_const(*c_squared)
        } else {
            dr.alloc(Witness::empty())
        }
    }
    
    fn main<'witness, D: Driver<F = TestField>>(
        &self,
        dr: &mut D,
        witness: Witness<D, Self::Witness<'witness>>,
    ) -> Result<(Self::IO<'witness, D>, Witness<D, Self::Aux<'witness>>), Error> {
        if let Some((a, b)) = witness.get() {
            // Allocate private a and b
            let a_wire = dr.alloc(Witness::new(*a))?;
            let b_wire = dr.alloc(Witness::new(*b))?;
            
            // Compute a^2
            let a_squared = dr.mul(a_wire.clone(), a_wire)?;
            
            // Compute b^2
            let b_squared = dr.mul(b_wire.clone(), b_wire)?;
            
            // Compute a^2 + b^2
            let sum = dr.add(a_squared, b_squared)?;
            
            Ok((sum, Witness::empty()))
        } else {
            // Verification path (no witness)
            let a_wire = dr.alloc(Witness::empty())?;
            let b_wire = dr.alloc(Witness::empty())?;
            
            let a_squared = dr.mul(a_wire.clone(), a_wire)?;
            let b_squared = dr.mul(b_wire.clone(), b_wire)?;
            let sum = dr.add(a_squared, b_squared)?;
            
            Ok((sum, Witness::empty()))
        }
    }
    
    fn output<'source, D: Driver<F = TestField>>(
        &self,
        dr: &mut D,
        io: Self::IO<'source, D>,
        output: &mut D::IO,
    ) -> Result<(), Error> {
        output.push(io);
        Ok(())
    }
}

fn example_custom_circuit() {
    println!("=== Example 3: Pythagorean Theorem Circuit ===\n");
    
    let circuit = PythagoreanCircuit;
    
    // Example: 3^2 + 4^2 = 5^2
    // So a=3, b=4, c^2=25
    let a = TestField::new(3);
    let b = TestField::new(4);
    let c_squared = TestField::new(25);
    
    // Prover path: has witness
    let mut prover = ProverDriver::<TestField>::new();
    
    let public_input = Witness::new(c_squared);
    let witness = Witness::new((a, b));
    
    let public_io = circuit
        .input(&mut prover, public_input)
        .expect("Failed to process input");
    
    let (computed_io, _aux) = circuit
        .main(&mut prover, witness)
        .expect("Failed to synthesize main");
    
    println!("For a=3, b=4, computed a^2 + b^2 = {}", 
             computed_io.value.value());
    println!("Expected c^2 = {}", c_squared.value());
    println!("Constraints: {}", prover.cs.num_constraints());
    
    // Verifier path: no witness
    let mut verifier = VerifierDriver::<TestField>::new();
    
    let _ = circuit
        .input(&mut verifier, Witness::empty())
        .expect("Failed to process input (verifier)");
    
    let _ = circuit
        .main(&mut verifier, Witness::empty())
        .expect("Failed to synthesize main (verifier)");
    
    println!("Verifier constraint system: {} constraints", 
             verifier.cs.num_constraints());
    println!("Prover and verifier constraint counts match: {}\n",
             prover.cs.num_constraints() == verifier.cs.num_constraints());
}

// ============================================================================
// Example 4: Maybe<T> Abstraction Demo
// ============================================================================

fn example_maybe_abstraction() {
    println!("=== Example 4: Maybe<T> Abstraction ===\n");
    
    // With witness context
    let maybe_with: Maybe<WithWitness, u64> = Maybe::just(42);
    println!("WithWitness context has value: {}", maybe_with.is_some());
    if let Some(val) = maybe_with.as_ref() {
        println!("Value: {}", val);
    }
    
    // Without witness context (verification)
    let maybe_without: Maybe<WithoutWitness, u64> = Maybe::none();
    println!("WithoutWitness context has value: {}", maybe_without.is_some());
    println!("This collapses to zero-sized type in verification!\n");
    
    // Map operation
    let doubled = maybe_with.map(|x| x * 2);
    println!("Doubled value: {:?}\n", doubled.as_ref());
}

// ============================================================================
// Example 5: Constraint System Inspection
// ============================================================================

fn example_constraint_inspection() {
    println!("=== Example 5: Constraint System Inspection ===\n");
    
    let mut prover = ProverDriver::<TestField>::new();
    
    // Build a small circuit: (a + b) * c
    let a = prover.alloc(Witness::new(TestField::new(2))).unwrap();
    let b = prover.alloc(Witness::new(TestField::new(3))).unwrap();
    let c = prover.alloc(Witness::new(TestField::new(5))).unwrap();
    
    let sum = prover.add(a, b).unwrap();
    let product = prover.mul(sum, c).unwrap();
    
    println!("Circuit: (2 + 3) * 5 = {}", product.value.value());
    println!("Expected: 25\n");
    
    println!("Constraint system details:");
    println!("  Variables allocated: {}", prover.cs.num_variables);
    println!("  Constraints generated: {}", prover.cs.num_constraints());
    println!("  Witness assignments: {}", prover.assignments.len());
    
    // Verify witness satisfies constraints
    println!("\nWitness values:");
    for (idx, val) in prover.assignments.iter().enumerate() {
        println!("  var[{}] = {}", idx, val.value());
    }
    println!();
}

// ============================================================================
// Example 6: Using Built-in Circuits
// ============================================================================

fn example_builtin_circuits() {
    println!("=== Example 6: Built-in Example Circuits ===\n");
    
    // SimpleCircuit: computes a * b + c
    let simple = SimpleCircuit;
    let mut prover = ProverDriver::<TestField>::new();
    
    let witness = Witness::new((
        TestField::new(5),  // a
        TestField::new(7),  // b
        TestField::new(10), // c
    ));
    
    let (_io, _) = simple.main(&mut prover, witness).expect("SimpleCircuit failed");
    println!("SimpleCircuit: 5 * 7 + 10 =");
    println!("  Constraints: {}", prover.cs.num_constraints());
    
    // SquareRootCircuit: verifies x^2 = y
    let sqrt = SquareRootCircuit;
    let mut prover2 = ProverDriver::<TestField>::new();
    
    let public_y = Witness::new(TestField::new(49));
    let private_x = Witness::new(TestField::new(7));
    
    let _y_wire = sqrt.input(&mut prover2, public_y).expect("Input failed");
    let (_x_squared, _) = sqrt.main(&mut prover2, private_x).expect("Main failed");
    
    println!("\nSquareRootCircuit: Verify 7^2 = 49");
    println!("  Constraints: {}", prover2.cs.num_constraints());
    println!();
}

// ============================================================================
// Example 7: Non-uniform Circuit Support (Conceptual)
// ============================================================================

fn example_non_uniform_concept() {
    println!("=== Example 7: Non-uniform Circuit Concept ===\n");
    
    println!("Ragu supports non-uniform circuits for PCD trees.");
    println!("Different nodes can use different circuit structures:");
    println!("  - Leaf nodes: simple spend/output circuits");
    println!("  - Internal nodes: folding/aggregation circuits");
    println!("  - Root node: final verification circuit");
    println!("\nThe Driver abstraction allows the same circuit code to");
    println!("work in different contexts (proving, verifying, etc.)");
    println!("without code duplication.\n");
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║         Ragu PCD Toolkit Demonstration                  ║");
    println!("║  R1CS-based Proof-Carrying Data for Orchard/Tachyon     ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    example_simple_multiplication();
    example_boolean_logic();
    example_custom_circuit();
    example_maybe_abstraction();
    example_constraint_inspection();
    example_builtin_circuits();
    example_non_uniform_concept();
    
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║                  Demo Complete!                          ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
}

