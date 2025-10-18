# Ragu: Proof-Carrying Data Toolkit

Ragu is a simple R1CS-based arithmetization framework designed for building proof-carrying data (PCD) systems for the Orchard shielded protocol and Tachyon scale-layer.

## ⚠️ Important: Ragu is a Toolkit, Not a Complete Prover

**Ragu provides circuit synthesis and R1CS constraint generation**, but does **NOT** include cryptographic proof generation. To generate actual proofs, Ragu must be paired with a **proving backend** such as Nova.

See [BACKEND_INTEGRATION.md](BACKEND_INTEGRATION.md) for details on backend options and integration.

## Overview

Ragu provides:

- **Simple R1CS arithmetization** for clarity, auditability, and performance
- **Non-uniform circuit support** for different structures at different PCD nodes
- **Zero-cost abstractions** between witness and non-witness contexts
- **Efficient circuit synthesis** without heavy FFTs or preprocessing
- **Modular driver architecture** for proving, verification, and public input computation

## Core Abstractions

### 1. Field Trait

The `Field` trait provides arithmetic operations over finite fields:

```rust
pub trait Field: Clone + Copy + Debug + Sized + 'static {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn invert(&self) -> Option<Self>;
    fn is_zero(&self) -> bool;
}
```

**Implementations:**
- `TestField`: Simple u64 field for testing (mod 2^31 - 1)
- `PallasField`: Wrapper for pasta_curves::Fp (requires `pasta` feature)
- `VestaField`: Wrapper for pasta_curves::Fq (requires `pasta` feature)

### 2. Maybe<T> Abstraction

`Maybe<M, T>` generalizes `Option<T>` with zero-cost elimination based on context:

```rust
pub trait MaybeKind {
    const HAS_WITNESS: bool;
}

pub struct WithWitness;    // Has witness (proving)
pub struct WithoutWitness; // No witness (verifying)

pub struct Maybe<M: MaybeKind, T> { ... }
```

**Key benefit:** In verification contexts (`WithoutWitness`), `Maybe` collapses to zero-sized types with no runtime overhead.

**Usage:**
```rust
// Proving context
let with_witness: Maybe<WithWitness, u64> = Maybe::just(42);

// Verification context (zero-cost)
let without: Maybe<WithoutWitness, u64> = Maybe::none();
```

### 3. Driver Trait

The `Driver` trait abstracts over different synthesis contexts:

```rust
pub trait Driver: Sized {
    type F: Field;              // Field type
    type W: Clone + Debug;      // Wire type
    type MaybeKind: MaybeKind; // Witness presence
    type IO: Sink<Self, Self::W>; // I/O sink
    
    // Allocation
    fn alloc(&mut self, value: Witness<Self, Self::F>) -> Result<Self::W, Error>;
    fn alloc_const(&mut self, value: Self::F) -> Result<Self::W, Error>;
    
    // Arithmetic
    fn add(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error>;
    fn mul(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error>;
    fn neg(&mut self, a: Self::W) -> Result<Self::W, Error>;
    fn sub(&mut self, a: Self::W, b: Self::W) -> Result<Self::W, Error>;
    
    // Constraints
    fn enforce_zero(&mut self, a: Self::W) -> Result<(), Error>;
    fn enforce_equal(&mut self, a: Self::W, b: Self::W) -> Result<(), Error>;
    fn assert_boolean(&mut self, a: Self::W) -> Result<(), Error>;
    fn select(&mut self, cond: Self::W, t: Self::W, f: Self::W) -> Result<Self::W, Error>;
}
```

**Implementations:**
- `ProverDriver<F>`: Proof generation with full witness
- `VerifierDriver<F>`: Verification (constraint structure only)
- `PublicInputDriver<F>`: Public input computation

### 4. Circuit Trait

The `Circuit` trait defines the circuit interface:

```rust
pub trait Circuit<F: Field>: Sized {
    type Instance<'instance>;   // Public inputs
    type IO<'source, D: Driver<F = F>>; // I/O type
    type Witness<'witness>;     // Private witness
    type Aux<'witness>;         // Auxiliary data
    
    fn input<'instance, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        input: Witness<D, Self::Instance<'instance>>,
    ) -> Result<Self::IO<'instance, D>, Error>;
    
    fn main<'witness, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        witness: Witness<D, Self::Witness<'witness>>,
    ) -> Result<(Self::IO<'witness, D>, Witness<D, Self::Aux<'witness>>), Error>;
    
    fn output<'source, D: Driver<F = F>>(
        &self,
        dr: &mut D,
        io: Self::IO<'source, D>,
        output: &mut D::IO,
    ) -> Result<(), Error>;
}
```

**Circuit phases:**
1. **input**: Map public instance data to I/O
2. **main**: Process private witness, generate constraints
3. **output**: Finalize public outputs

## R1CS Constraint System

Ragu uses a simple R1CS (Rank-1 Constraint System) representation:

```rust
pub struct R1CSConstraint<F: Field> {
    pub a: LinearCombination<F>, // Left input
    pub b: LinearCombination<F>, // Right input
    pub c: LinearCombination<F>, // Output
}
// Enforces: a * b = c
```

Each constraint ensures that the product of two linear combinations equals a third.

## Gadgets

Ragu includes several built-in gadget libraries:

### BooleanGadget

```rust
BooleanGadget::assert_bit(dr, bit)?;
BooleanGadget::and(dr, a, b)?;
BooleanGadget::or(dr, a, b)?;
BooleanGadget::not(dr, a)?;
BooleanGadget::xor(dr, a, b)?;
```

### NumberGadget

```rust
NumberGadget::to_bits(dr, value, num_bits)?;
NumberGadget::from_bits(dr, &bits)?;
```

### ComparisonGadget

```rust
ComparisonGadget::is_equal(dr, a, b)?;
```

## Example Usage

### Basic Circuit

```rust
use tachy_wallet::ragu::*;

// Create a prover driver
let mut prover = ProverDriver::<TestField>::new();

// Allocate witness values
let a = prover.alloc(Witness::new(TestField::new(7)))?;
let b = prover.alloc(Witness::new(TestField::new(6)))?;

// Compute a * b
let result = prover.mul(a, b)?;

println!("Constraints: {}", prover.cs.num_constraints());
```

### Custom Circuit

```rust
struct MyCircuit;

impl Circuit<TestField> for MyCircuit {
    type Instance<'instance> = TestField;
    type IO<'source, D: Driver<F = TestField>> = D::W;
    type Witness<'witness> = TestField;
    type Aux<'witness> = ();
    
    fn input<'instance, D: Driver<F = TestField>>(
        &self,
        dr: &mut D,
        input: Witness<D, Self::Instance<'instance>>,
    ) -> Result<Self::IO<'instance, D>, Error> {
        if let Some(val) = input.get() {
            dr.alloc_const(*val)
        } else {
            dr.alloc(Witness::empty())
        }
    }
    
    fn main<'witness, D: Driver<F = TestField>>(
        &self,
        dr: &mut D,
        witness: Witness<D, Self::Witness<'witness>>,
    ) -> Result<(Self::IO<'witness, D>, Witness<D, Self::Aux<'witness>>), Error> {
        let x = if let Some(val) = witness.get() {
            dr.alloc(Witness::new(*val))?
        } else {
            dr.alloc(Witness::empty())?
        };
        
        // Your circuit logic here
        let result = dr.mul(x.clone(), x)?;
        
        Ok((result, Witness::empty()))
    }
    
    fn output<'source, D: Driver<F = TestField>>(
        &self,
        _dr: &mut D,
        io: Self::IO<'source, D>,
        output: &mut D::IO,
    ) -> Result<(), Error> {
        output.push(io);
        Ok(())
    }
}
```

## Non-Uniform Circuits

Ragu supports **non-uniform circuits** where different nodes in a PCD tree can have different circuit structures:

- **Leaf nodes**: Simple spend/output circuits
- **Internal nodes**: Folding/aggregation circuits  
- **Root node**: Final verification circuit

The `Driver` abstraction allows the same circuit code to work across all contexts without duplication.

## Design Philosophy

### Zero-Cost Abstractions

The `Maybe<T>` abstraction and `Driver` trait enable the same circuit code to run efficiently in both proving and verification contexts. The Rust type system eliminates runtime overhead through monomorphization.

### Simplicity Over Complexity

Ragu uses R1CS instead of more complex "PLONKish" arithmetizations. This provides:
- **Auditability**: Easier to understand and verify
- **Performance**: Simpler constraint system → faster synthesis
- **Clarity**: Less abstraction overhead for developers

### Tailored for Zcash

Unlike general-purpose SNARK frameworks, Ragu is specifically designed for:
- Pasta curve cycle (Pallas/Vesta)
- Orchard/Tachyon protocol requirements
- PCD trees with non-uniform circuits
- Efficient folding and aggregation

## Testing

Run the example demonstration:

```bash
cargo run --example ragu_demo
```

Run unit tests:

```bash
cargo test --lib ragu
```

## Integration with Tachyon

Ragu serves as the **proving-toolkit layer** for Tachyon's PCD system:

1. **Wallet transactions** generate proofs using ragu circuits
2. **Oblivious sync services** use ragu for proof folding
3. **Aggregators** combine proofs into compact PCD
4. **Validators** verify aggregated proofs efficiently

The toolkit enables Tachyon to achieve:
- Validator state pruning
- Reduced state contention
- Efficient proof aggregation
- Privacy-preserving synchronization

## Performance Considerations

### Circuit Synthesis
Circuit synthesis is a "hot path" operation that happens frequently. Ragu optimizes for:
- Minimal constraint overhead
- Efficient witness assignment
- Fast constraint generation

### Memory Efficiency
- Witnesses are optional based on context
- Zero-sized types in verification
- Lazy constraint generation where possible

### Proof Size
R1CS constraints are simple and compact, leading to:
- Smaller proof artifacts
- Faster verification
- Better aggregation efficiency

## Proving Backend Integration

### Nova Backend (Recommended)

Ragu includes API design for Nova-based proof generation:

```rust
use tachy_wallet::ragu::*;
use tachy_wallet::ragu::nova_backend::*;

// 1. Synthesize circuit with Ragu
let circuit = MyCircuit;
let mut prover = ProverDriver::<PallasField>::new();
let (io, _) = circuit.main(&mut prover, witness)?;

// 2. Create Nova prover
let nova_prover = NovaProver::from_driver(&prover)?;

// 3. Generate proof (implementation pending)
let proof = nova_prover.prove_compressed(&prover.assignments)?;

// 4. Verify
let valid = NovaVerifier::verify_compressed(&proof, &public_inputs)?;
```

**Status**: API complete, implementation pending (~4-6 weeks estimated).

### Why Nova?

- ✅ Native R1CS support (perfect fit!)
- ✅ Efficient folding for IVC
- ✅ Pasta cycle (Pallas/Vesta)
- ✅ No trusted setup
- ✅ Small proofs (~10KB compressed)
- ✅ Fast verification (<1ms)

See [BACKEND_INTEGRATION.md](BACKEND_INTEGRATION.md) for comprehensive backend comparison and integration guide.

## Future Enhancements

Backend implementation priorities:

1. **Nova proof generation/verification** (next step)
2. **SuperNova/HyperNova** evaluation (emerging, better for non-uniform circuits)
3. **Proof compression** optimization
4. **Benchmark suite** across backends

Circuit/gadget enhancements:

- **Poseidon hash gadget** full implementation
- **Advanced gadgets** (range proofs, merkle proofs, etc.)
- **Optimization passes** for constraint reduction
- **Formal verification** of critical constraints

## References

- Blog post: "Ragu for Orchard: Recursion Al Dente" by Sean Bowe (April 17, 2025)
- [seanbowe.com](https://seanbowe.com/blog/ragu-for-orchard-part1/)
- Orchard shielded protocol specification
- Tachyon project documentation

## License

This implementation is part of the tachy-wallet project.

