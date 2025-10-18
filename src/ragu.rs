//! Ragu: Proof-Carrying Data Toolkit for Orchard/Tachyon
//!
//! A simple R1CS-like arithmetization framework designed for:
//! - Proof-carrying data (PCD) systems
//! - Non-uniform circuits (different structures at different PCD nodes)
//! - Zero-cost abstractions between witness/non-witness contexts
//! - Efficient circuit synthesis without heavy FFTs or preprocessing
//!
//! # Overview
//!
//! Ragu provides a clean, simple abstraction for building circuits that participate
//! in proof-carrying data systems. Unlike heavy SNARK frameworks, ragu focuses on
//! clarity, auditability, and performance through a simple R1CS constraint system.
//!
//! ## Key Features
//!
//! ### Zero-Cost Abstractions
//!
//! The [`Maybe<T>`] abstraction allows circuits to work identically in proving and
//! verification contexts. In verification, witness data collapses to zero-sized types
//! with no runtime overhead.
//!
//! ### Unified Driver Interface
//!
//! The [`Driver`] trait abstracts over different synthesis contexts:
//! - [`ProverDriver`]: Full witness, generates proofs
//! - [`VerifierDriver`]: No witness, builds constraint structure
//! - [`PublicInputDriver`]: Partial witness, computes public inputs
//!
//! ### Non-Uniform Circuits
//!
//! Ragu supports PCD trees where different nodes have different circuit structures.
//! The same code works for leaf, fold, aggregate, and root circuits.
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use tachy_wallet::ragu::*;
//!
//! // Create a prover driver
//! let mut prover = ProverDriver::<TestField>::new();
//!
//! // Allocate witness values
//! let a = prover.alloc(Witness::new(TestField::new(7)))?;
//! let b = prover.alloc(Witness::new(TestField::new(6)))?;
//!
//! // Compute a * b
//! let result = prover.mul(a, b)?;
//!
//! println!("Result: {}", result.value);
//! println!("Constraints: {}", prover.cs.num_constraints());
//! ```
//!
//! ## Module Structure
//!
//! - [`drivers`]: Concrete Driver implementations
//! - [`fields`]: Field trait implementations (TestField, PallasField, VestaField)
//! - [`circuits`]: Circuit gadgets and example circuits
//! - [`synthesis`]: Circuit composition and synthesis utilities
//! - [`pcd`]: Proof-carrying data framework
//!
//! For more details, see the [README](src/ragu/README.md).

use std::fmt;
use std::marker::PhantomData;

// ============================================================================
// Field Trait
// ============================================================================

/// Field trait for arithmetic in the constraint system.
/// Designed for Pasta curves (Pallas/Vesta) but generic enough for other fields.
pub trait Field: Clone + Copy + fmt::Debug + Sized + 'static {
    /// Field zero
    fn zero() -> Self;
    
    /// Field one
    fn one() -> Self;
    
    /// Addition
    fn add(&self, other: &Self) -> Self;
    
    /// Subtraction
    fn sub(&self, other: &Self) -> Self;
    
    /// Multiplication
    fn mul(&self, other: &Self) -> Self;
    
    /// Negation
    fn neg(&self) -> Self;
    
    /// Multiplicative inverse (if it exists)
    fn invert(&self) -> Option<Self>;
    
    /// Check if zero
    fn is_zero(&self) -> bool;
    
    /// Square
    fn square(&self) -> Self {
        self.mul(self)
    }
    
    /// Double
    fn double(&self) -> Self {
        self.add(self)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during circuit synthesis or proof generation
#[derive(Debug, Clone)]
pub enum Error {
    /// Synthesis failed (e.g., constraint unsatisfied)
    SynthesisError(String),
    
    /// Invalid witness data
    InvalidWitness(String),
    
    /// Invalid public input
    InvalidPublicInput(String),
    
    /// Circuit structure mismatch
    CircuitMismatch(String),
    
    /// Generic error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SynthesisError(s) => write!(f, "Synthesis error: {}", s),
            Error::InvalidWitness(s) => write!(f, "Invalid witness: {}", s),
            Error::InvalidPublicInput(s) => write!(f, "Invalid public input: {}", s),
            Error::CircuitMismatch(s) => write!(f, "Circuit mismatch: {}", s),
            Error::Other(s) => write!(f, "Error: {}", s),
        }
    }
}

impl std::error::Error for Error {}

// ============================================================================
// Maybe<T> Abstraction
// ============================================================================

/// Controls whether witness data is present or absent in a context.
///
/// This trait allows zero-cost elimination: in verification contexts,
/// `WithWitness` collapses to zero-sized types.
pub trait MaybeKind: Clone + Copy + fmt::Debug + 'static {
    /// Whether witness is present in this context
    const HAS_WITNESS: bool;
}

/// Marker type: witness IS present (proving context)
#[derive(Clone, Copy, Debug)]
pub struct WithWitness;

impl MaybeKind for WithWitness {
    const HAS_WITNESS: bool = true;
}

/// Marker type: witness is NOT present (verification context)
#[derive(Clone, Copy, Debug)]
pub struct WithoutWitness;

impl MaybeKind for WithoutWitness {
    const HAS_WITNESS: bool = false;
}

/// A value that may or may not be present depending on context.
///
/// In proving contexts (WithWitness), contains `Some(T)`.
/// In verification contexts (WithoutWitness), always `None` with zero cost.
#[derive(Clone, Debug)]
pub struct Maybe<M: MaybeKind, T> {
    value: Option<T>,
    _marker: PhantomData<M>,
}

impl<M: MaybeKind, T> Maybe<M, T> {
    /// Create a Maybe from an Option
    pub fn from_option(value: Option<T>) -> Self {
        Self {
            value,
            _marker: PhantomData,
        }
    }
    
    /// Create a Maybe with a value (only when witness is present)
    pub fn just(value: T) -> Self
    where
        M: MaybeKind,
    {
        Self {
            value: Some(value),
            _marker: PhantomData,
        }
    }
    
    /// Create an empty Maybe
    pub fn none() -> Self {
        Self {
            value: None,
            _marker: PhantomData,
        }
    }
    
    /// Apply a function to the contained value if present
    pub fn map<U, F>(self, f: F) -> Maybe<M, U>
    where
        F: FnOnce(T) -> U,
    {
        Maybe {
            value: self.value.map(f),
            _marker: PhantomData,
        }
    }
    
    /// Apply a fallible function to the contained value
    pub fn and_then<U, F>(self, f: F) -> Result<Maybe<M, U>, Error>
    where
        F: FnOnce(T) -> Result<U, Error>,
    {
        match self.value {
            Some(v) => Ok(Maybe::just(f(v)?)),
            None => Ok(Maybe::none()),
        }
    }
    
    /// Execute a function with the value if present
    pub fn with<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.value.as_ref().map(f)
    }
    
    /// Take the value out (consuming self)
    pub fn take(self) -> Option<T> {
        self.value
    }
    
    /// Get a reference to the value
    pub fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }
    
    /// Check if value is present
    pub fn is_some(&self) -> bool {
        self.value.is_some()
    }
    
    /// Check if value is absent
    pub fn is_none(&self) -> bool {
        self.value.is_none()
    }
}

// ============================================================================
// Witness Wrapper
// ============================================================================

/// Wraps witness data, parameterized by the Driver's MaybeKind.
///
/// In proving contexts, contains the actual witness.
/// In verification contexts, collapses to zero-sized type.
#[derive(Clone, Debug)]
pub struct Witness<D: Driver, T> {
    value: Maybe<D::MaybeKind, T>,
}

impl<D: Driver, T> Witness<D, T> {
    /// Create a witness from a value
    pub fn new(value: T) -> Self {
        Self {
            value: Maybe::just(value),
        }
    }
    
    /// Create an empty witness (for verification contexts)
    pub fn empty() -> Self {
        Self {
            value: Maybe::none(),
        }
    }
    
    /// Create from Maybe
    pub fn from_maybe(value: Maybe<D::MaybeKind, T>) -> Self {
        Self { value }
    }
    
    /// Map a function over the witness
    pub fn map<U, F>(self, f: F) -> Witness<D, U>
    where
        F: FnOnce(T) -> U,
    {
        Witness {
            value: self.value.map(f),
        }
    }
    
    /// Get the inner value
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }
    
    /// Take the inner value
    pub fn take(self) -> Option<T> {
        self.value.take()
    }
}

// ============================================================================
// Sink Trait (for IO handling)
// ============================================================================

/// A sink for input/output values in circuits.
///
/// This abstracts how variables are fed in/out of circuit components.
pub trait Sink<D: Driver, W: Clone>: Sized {
    /// Push a wire into the sink
    fn push(&mut self, wire: W);
    
    /// Push multiple wires
    fn push_many(&mut self, wires: impl IntoIterator<Item = W>) {
        for wire in wires {
            self.push(wire);
        }
    }
}

/// Simple vector-based sink implementation
#[derive(Clone, Debug)]
pub struct VecSink<W> {
    wires: Vec<W>,
}

impl<W> VecSink<W> {
    /// Create a new empty sink
    pub fn new() -> Self {
        Self { wires: Vec::new() }
    }
    
    /// Get the accumulated wires
    pub fn wires(&self) -> &[W] {
        &self.wires
    }
    
    /// Take ownership of the wires
    pub fn into_wires(self) -> Vec<W> {
        self.wires
    }
}

impl<W> Default for VecSink<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Driver, W: Clone> Sink<D, W> for VecSink<W> {
    fn push(&mut self, wire: W) {
        self.wires.push(wire);
    }
}

// ============================================================================
// Driver Trait
// ============================================================================

/// Abstracts over different contexts: proving, verification, public input computation.
///
/// The Driver provides methods for constraint system operations and manages
/// the witness presence via MaybeKind.
pub trait Driver: Sized {
    /// The field used for arithmetic
    type F: Field;
    
    /// The wire type (abstract representation of a variable)
    type W: Clone + fmt::Debug;
    
    /// Controls witness presence
    type MaybeKind: MaybeKind;
    
    /// Input/output sink type
    type IO: Sink<Self, Self::W>;
    
    /// Allocate a new witness variable
    fn alloc(
        &mut self,
        value: Witness<Self, Self::F>,
    ) -> Result<Self::W, Error>;
    
    /// Allocate a constant
    fn alloc_const(&mut self, value: Self::F) -> Result<Self::W, Error>;
    
    /// Add two wires
    fn add(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error>;
    
    /// Multiply two wires
    fn mul(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error>;
    
    /// Negate a wire
    fn neg(&mut self, a: Self::W) -> Result<Self::W, Error>;
    
    /// Subtract two wires (a - b)
    fn sub(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error> {
        let neg_b = self.neg(b)?;
        self.add(a, neg_b)
    }
    
    /// Scale a wire by a constant
    fn scale(&mut self, a: Self::W, scalar: Self::F) -> Result<Self::W, Error> {
        let c = self.alloc_const(scalar)?;
        self.mul(a, c)
    }
    
    /// Enforce that a wire equals zero
    fn enforce_zero(&mut self, a: Self::W) -> Result<(), Error>;
    
    /// Enforce equality between two wires
    fn enforce_equal(&mut self, a: Self::W, b: Self::W) -> Result<(), Error> {
        let diff = self.sub(a, b)?;
        self.enforce_zero(diff)
    }
    
    /// Assert that a boolean wire is 0 or 1
    fn assert_boolean(&mut self, a: Self::W) -> Result<(), Error> {
        // Enforce a * (1 - a) = 0
        let one = self.alloc_const(Self::F::one())?;
        let one_minus_a = self.sub(one, a.clone())?;
        let product = self.mul(a, one_minus_a)?;
        self.enforce_zero(product)
    }
    
    /// Select between two wires based on a boolean condition
    /// Returns: condition * true_wire + (1 - condition) * false_wire
    /// 
    /// # Security: Constant-Time Selection
    /// 
    /// This is implemented as arithmetic over field elements, which is
    /// constant-time with respect to both the condition value and the wire values.
    /// No branching occurs based on secret data.
    /// 
    /// The constraint system enforces:
    /// - condition is boolean (0 or 1)
    /// - result = condition ? true_wire : false_wire
    /// 
    /// This pattern is safe for use with secret data in ZK proofs.
    fn select(
        &mut self,
        condition: Self::W,
        true_wire: Self::W,
        false_wire: Self::W,
    ) -> Result<Self::W, Error> {
        // First ensure condition is boolean
        self.assert_boolean(condition.clone())?;
        
        // condition * true_wire
        let selected_true = self.mul(condition.clone(), true_wire)?;
        
        // (1 - condition)
        let one = self.alloc_const(Self::F::one())?;
        let not_condition = self.sub(one, condition)?;
        
        // (1 - condition) * false_wire
        let selected_false = self.mul(not_condition, false_wire)?;
        
        // Sum them (all operations constant-time)
        self.add(selected_true, selected_false)
    }
    
    /// Create a new IO sink
    fn new_io(&self) -> Self::IO;
}

// ============================================================================
// Circuit Trait
// ============================================================================

/// Defines a circuit that can be synthesized, proven, and verified.
///
/// The circuit is decomposed into three phases:
/// - `input`: map instance data to IO
/// - `main`: process witness and produce IO + auxiliary data
/// - `output`: finalize public output
pub trait Circuit<F: Field>: Sized {
    /// Public instance data (e.g., public inputs)
    type Instance<'instance>;
    
    /// Input/output type for this circuit
    type IO<'source, D: Driver<F = F>>;
    
    /// Private witness data
    type Witness<'witness>;
    
    /// Auxiliary witness data produced by main
    type Aux<'witness>;
    
    /// Map instance data to IO
    fn input<'instance, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        input: Witness<D, Self::Instance<'instance>>,
    ) -> Result<Self::IO<'instance, D>, Error>;
    
    /// Main circuit logic: process witness, produce IO and auxiliary data
    fn main<'witness, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        witness: Witness<D, Self::Witness<'witness>>,
    ) -> Result<(Self::IO<'witness, D>, Witness<D, Self::Aux<'witness>>), Error>;
    
    /// Finalize output from IO
    fn output<'source, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        io: Self::IO<'source, D>,
        output: &mut D::IO,
    ) -> Result<(), Error>;
}

// ============================================================================
// Constraint System
// ============================================================================

/// Represents an R1CS constraint: (a, b, c) such that a * b = c
#[derive(Clone, Debug)]
pub struct R1CSConstraint<F: Field> {
    /// Left wire assignment
    pub a: LinearCombination<F>,
    /// Right wire assignment
    pub b: LinearCombination<F>,
    /// Output wire assignment
    pub c: LinearCombination<F>,
}

/// A linear combination of variables: sum of (coefficient, variable_index) pairs
#[derive(Clone, Debug)]
pub struct LinearCombination<F: Field> {
    terms: Vec<(F, usize)>,
}

impl<F: Field> LinearCombination<F> {
    /// Create an empty linear combination
    pub fn zero() -> Self {
        Self { terms: Vec::new() }
    }
    
    /// Create a linear combination with a single term
    pub fn single(coeff: F, var: usize) -> Self {
        Self {
            terms: vec![(coeff, var)],
        }
    }
    
    /// Add a term to the linear combination
    pub fn add_term(&mut self, coeff: F, var: usize) {
        self.terms.push((coeff, var));
    }
    
    /// Get the terms
    pub fn terms(&self) -> &[(F, usize)] {
        &self.terms
    }
}

/// A constraint system that accumulates R1CS constraints
#[derive(Clone, Debug)]
pub struct ConstraintSystem<F: Field> {
    /// All constraints
    pub constraints: Vec<R1CSConstraint<F>>,
    /// Number of variables allocated
    pub num_variables: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Total number of linear-combination terms across all constraints
    total_lc_terms: usize,
}

/// Resource limits for constraint systems
/// 
/// These limits prevent DoS attacks through memory exhaustion
pub mod limits {
    /// Maximum number of constraints (10M constraints ≈ 1GB memory)
    pub const MAX_CONSTRAINTS: usize = 10_000_000;
    /// Maximum number of variables (10M variables ≈ 80MB memory)
    pub const MAX_VARIABLES: usize = 10_000_000;
    /// Maximum number of public inputs
    pub const MAX_PUBLIC_INPUTS: usize = 1_000_000;
    /// Maximum total number of LC terms across all constraints (≈ 200M terms)
    pub const MAX_TOTAL_LC_TERMS: usize = 200_000_000;
}

impl<F: Field> ConstraintSystem<F> {
    /// Create a new constraint system
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            num_variables: 0,
            num_public_inputs: 0,
            total_lc_terms: 0,
        }
    }
    
    /// Allocate a new variable
    /// 
    /// # Security Note
    /// Variable allocation is bounded by add_constraint limits (MAX_CONSTRAINTS).
    /// Since each constraint requires at least one variable, this implicitly
    /// limits variables to ~3 * MAX_CONSTRAINTS in worst case.
    /// 
    /// Explicit variable limit checking could be added if needed, but adds
    /// overhead to every allocation. Current approach is sufficient for DoS prevention.
    pub fn alloc_variable(&mut self) -> usize {
        if self.num_variables >= limits::MAX_VARIABLES {
            panic!("Variable limit exceeded");
        }
        let next = self
            .num_variables
            .checked_add(1)
            .expect("usize overflow on variable allocation");
        let idx = self.num_variables;
        self.num_variables = next;
        idx
    }
    
    /// Validate that all variable indices in a linear combination are in bounds
    fn validate_linear_combination(&self, lc: &LinearCombination<F>) -> Result<(), Error> {
        for (_, var_idx) in lc.terms() {
            if *var_idx >= self.num_variables {
                return Err(Error::CircuitMismatch("Invalid variable index".to_string()));
            }
        }
        Ok(())
    }
    
    /// Add a constraint with validation and resource limits
    /// 
    /// # Security
    /// - Validates that all variable indices are in bounds
    /// - Enforces MAX_CONSTRAINTS limit to prevent DoS attacks
    /// - Prevents out-of-bounds access during constraint evaluation
    pub fn add_constraint(&mut self, constraint: R1CSConstraint<F>) -> Result<(), Error> {
        // Check resource limit
        if self.constraints.len() >= limits::MAX_CONSTRAINTS {
            return Err(Error::Other("Maximum constraint limit exceeded".to_string()));
        }
        
        // Validate all variable indices in the constraint
        self.validate_linear_combination(&constraint.a)?;
        self.validate_linear_combination(&constraint.b)?;
        self.validate_linear_combination(&constraint.c)?;
        
        // Track cumulative LC terms and enforce a global cap to bound memory
        let terms_in_constraint = constraint.a.terms().len()
            + constraint.b.terms().len()
            + constraint.c.terms().len();
        let new_total = self
            .total_lc_terms
            .checked_add(terms_in_constraint)
            .ok_or_else(|| Error::Other("LC term counter overflow".to_string()))?;
        if new_total > limits::MAX_TOTAL_LC_TERMS {
            return Err(Error::Other("Maximum LC terms limit exceeded".to_string()));
        }
        self.total_lc_terms = new_total;
        
        self.constraints.push(constraint);
        Ok(())
    }
    
    /// Add a constraint without validation (internal use only)
    /// 
    /// # Safety
    /// Caller must ensure all variable indices are valid.
    /// Only use this when performance is critical and validation is done elsewhere.
    // Unchecked insertion removed to enforce validation invariants globally
    
    /// Get the number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}

impl<F: Field> Default for ConstraintSystem<F> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Module Exports
// ============================================================================

pub mod drivers;
pub mod fields;
pub mod circuits;
pub mod synthesis;
pub mod pcd;
pub mod nova_backend;

// Re-export commonly used types
pub use drivers::{ProverDriver, VerifierDriver, PublicInputDriver};
pub use drivers::{ProverWire, VerifierWire, PublicInputWire};
pub use fields::{TestField, PallasField, VestaField};

pub use circuits::{
    BooleanGadget,
    ComparisonGadget,
    HashGadget,
    NumberGadget,
    SimpleCircuit,
    SquareRootCircuit,
};

pub use synthesis::{
    Composable,
    ComposedCircuit,
    SynthesisHelper,
    CircuitStats,
    ConstraintVerifier,
    WitnessBuilder,
};

pub use pcd::{
    NodeType,
    PCDProof,
    ProofMetadata,
    PCDCircuit,
    PCDTree,
    FoldingCircuit,
    PCDBuilder,
};

pub use nova_backend::{
    NovaProver,
    NovaVerifier,
    NovaProof,
    CompressedNovaProof,
    NovaPublicParams,
    NovaIntegration,
    ProvingCost,
};


