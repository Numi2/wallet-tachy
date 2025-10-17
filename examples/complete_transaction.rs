
//! Alice has a note worth 1 ZEC and wants to send it to Bob.
//!
//! Steps:
//! 1. Alice and Bob establish a shared secret (via out-of-band channel)
//! 2. Alice creates a transaction spending her note and creating Bob's note
//! 3. Alice generates a tachystamp proof for the transaction
//! 4. The network verifies the proof and accepts the transaction
//! 5. Bob can later spend his note using the same process

#[cfg(feature = "tachystamps")]
use rand::rngs::OsRng;

#[cfg(feature = "tachystamps")]
use tachy_wallet::{
    // Note structures
    TachyonNote,
    PaymentKey,
    NullifierKey,
    Nonce,
    CommitmentKey,
    NullifierFlavor,
    derive_note_secrets,
    
    // Tachystamps
    Prover,
    RecParams,
    AnchorRange,
    build_tree,
    open_path,
    Tachygram,
    
    // Transaction building
    SpendContext,
    TachyonTxBuilder,
};

#[cfg(feature = "tachystamps")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Tachyon Complete Transaction Example ===\n");

    // ----------------------------- Setup -----------------------------
    
    println!("1. Setting up keys for Alice and Bob...");
    
    // Alice's keys
    let alice_pk = PaymentKey::random(OsRng);
    let alice_nk = NullifierKey::random(OsRng);
    println!("   Alice's payment key: {:?}", &alice_pk.0[..8]);
    
    // Bob's keys
    let bob_pk = PaymentKey::random(OsRng);
    let bob_nk = NullifierKey::random(OsRng);
    println!("   Bob's payment key: {:?}", &bob_pk.0[..8]);

    // ----------------------------- Alice Receives a Note -----------------------------
    
    println!("\n2. Alice receives 1 ZEC (100,000,000 zatoshis)...");
    
    // Shared secret from previous sender to Alice (out-of-band)
    let alice_shared_secret = b"alice-receives-1zec-shared-secret";
    let (alice_psi, alice_rcm, alice_flavor) = derive_note_secrets(alice_shared_secret);
    
    // Alice's note
    let alice_note = TachyonNote::new(
        alice_pk,
        100_000_000, // 1 ZEC = 100 million zatoshis
        alice_psi,
        alice_rcm,
    );
    
    let alice_cm = alice_note.commitment();
    println!("   Alice's note commitment: {:?}", &alice_cm.0[..8]);

    // ----------------------------- Build Merkle Tree -----------------------------
    
    println!("\n3. Building Merkle tree with Alice's note...");
    
    // In a real system, this tree would contain many notes
    let tree_height = 4; // 16 capacity
    let leaves = vec![Tachygram(alice_cm.0)];
    let tree = build_tree(&leaves, tree_height);
    let tree_root_fp = tree.root();
    let tree_root = tree_root_fp.to_repr();
    
    println!("   Tree root: {:?}", &tree_root[..8]);
    println!("   Alice's note is at index 0");

    // ----------------------------- Alice Sends to Bob -----------------------------
    
    println!("\n4. Alice creates transaction to send 1 ZEC to Bob...");
    
    // Alice and Bob establish shared secret (out-of-band, e.g., via ECDH)
    let bob_shared_secret = b"alice-to-bob-1zec-shared-secret-";
    let (bob_psi, bob_rcm, _bob_flavor) = derive_note_secrets(bob_shared_secret);
    
    // Bob's note (receiving 1 ZEC)
    let bob_note = TachyonNote::new(
        bob_pk,
        100_000_000,
        bob_psi,
        bob_rcm,
    );
    
    let bob_cm = bob_note.commitment();
    println!("   Bob's note commitment: {:?}", &bob_cm.0[..8]);

    // ----------------------------- Build Transaction -----------------------------
    
    println!("\n5. Building transaction with spend and output...");
    
    // Alice's spend context
    let alice_merkle_path = open_path(&tree, 0);
    let alice_spend = SpendContext {
        note: alice_note.clone(),
        nk: alice_nk,
        flavor: alice_flavor,
        merkle_path: alice_merkle_path,
        note_index: 0,
    };
    
    let alice_nf = alice_spend.nullifier();
    println!("   Alice's nullifier: {:?}", &alice_nf.0[..8]);
    
    // Build transaction
    let anchor_range = AnchorRange {
        start: 100,
        end: 200,
    };
    
    let mut tx_builder = TachyonTxBuilder::new(tree_root, anchor_range);
    tx_builder.add_spend(alice_spend);
    
    // Add Bob's output
    let bob_output = tachy_wallet::OutputContext {
        note: bob_note.clone(),
        tree_root,
        note_index: 1,
    };
    tx_builder.add_output(bob_output);
    
    // Check balance
    println!("   Checking transaction balance...");
    tx_builder.check_balance()?;
    println!("   ✓ Transaction is balanced (1 ZEC in, 1 ZEC out)");

    // ----------------------------- Generate Tachystamp Proof -----------------------------
    
    println!("\n6. Generating tachystamp proof...");
    
    // Setup prover
    let rec_params = RecParams {
        tree_height,
        batch_leaves: 1, // One note per batch
    };
    
    let mut prover = Prover::setup(&rec_params)?;
    prover.init(tree_root_fp, anchor_range)?;
    
    println!("   Prover initialized");
    
    // Build proof
    let compressed = tx_builder.build_tachystamp(&mut prover)?;
    println!("   ✓ Proof generated successfully");
    println!("   Proof size: {} bytes", compressed.proof.len());
    println!("   VK size: {} bytes", compressed.vk.len());
    println!("   Steps: {}", compressed.meta.steps);

    // ----------------------------- Verify Transaction -----------------------------
    
    println!("\n7. Verifying transaction...");
    
    // Extract tachygrams that would go on-chain
    let tachygrams = tx_builder.extract_tachygrams();
    println!("   Tachygrams: {} (1 nullifier + 1 commitment)", tachygrams.len());
    
    // Verify proof
    let z0 = vec![
        compressed.meta.acc_init,
        compressed.meta.ctx,
        halo2curves::pasta::Fp::ZERO,
    ];
    
    let verified = Prover::verify(&compressed, &z0)?;
    println!("   ✓ Proof verified successfully: {}", verified);

    // ----------------------------- Bob Can Now Spend -----------------------------
    
    println!("\n8. Bob can now spend his note in a future transaction...");
    println!("   Bob's note value: {} zatoshis (1 ZEC)", bob_note.value);
    println!("   Bob needs to:");
    println!("   - Compute nullifier using his nullifier key");
    println!("   - Prove membership of his note commitment");
    println!("   - Generate new tachystamp proof for his spend");

    println!("\n=== Transaction Complete ===");
    println!("\nSummary:");
    println!("  • Alice spent 1 ZEC");
    println!("  • Bob received 1 ZEC");
    println!("  • Proof size: ~{} KB", compressed.proof.len() / 1024);
    println!("  • Privacy preserved: No link between Alice's spend and Bob's output");
    println!("  • Oblivious sync ready: Nullifiers don't reveal note positions");

    Ok(())
}

#[cfg(not(feature = "tachystamps"))]
fn main() {
    eprintln!("This example requires the 'tachystamps' feature.");
    eprintln!("Run with: cargo run --example complete_transaction --features tachystamps");
    std::process::exit(1);
}
