//! Real Proof Aggregation Demo
//!
//! This demonstrates ACTUAL proof aggregation with cryptographic verification.
//! Run with: cargo run --example proof_aggregation_demo --features tachystamps

use tachy_wallet::*;
use halo2curves::pasta::Fp as PallasFp;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Tachyon Proof Aggregation Demo ===\n");

    // Step 1: Generate real proofs
    println!("Step 1: Generating individual tachystamp proofs...");
    
    let proofs = generate_real_proofs(3)?;
    println!("✓ Generated {} proofs", proofs.len());
    for (i, proof) in proofs.iter().enumerate() {
        println!("  Proof {}: {} steps, {} action pairs", 
            i + 1, 
            proof.meta.steps,
            proof.meta.authorized_pairs.len()
        );
    }

    // Step 2: Create proof batch
    println!("\nStep 2: Creating proof batch...");
    let mut batch = proof_aggregation::ProofBatch::new();
    
    for (i, proof) in proofs.iter().enumerate() {
        let context = format!("tx-{}", i + 1).into_bytes();
        batch.add_proof(proof.clone(), context);
    }
    println!("✓ Batch contains {} proofs", batch.len());

    // Step 3: Aggregate with cryptographic verification
    println!("\nStep 3: Aggregating proofs with CryptographicVerifier...");
    
    let z0 = vec![PallasFp::from(0u64), PallasFp::from(0u64)];
    let verifier = proof_aggregation::CryptographicVerifier::new(z0.clone());
    let aggregate_id = 42u32;
    
    let aggregate = proof_aggregation::aggregate_proofs_with_verifier(
        batch,
        aggregate_id,
        &verifier
    )?;
    
    println!("✓ Aggregation successful!");
    println!("  Aggregate ID: {}", aggregate.aggregate_id);
    println!("  Total actions: {}", aggregate.total_actions);
    println!("  Transactions: {}", aggregate.tx_metadata.len());
    println!("  Pairs root: {}", hex::encode(&aggregate.pairs_root));
    println!("  Aggregate digest: {}", hex::encode(&aggregate.agg_digest));

    // Step 4: Verify aggregate structure
    println!("\nStep 4: Verifying aggregate structure...");
    proof_aggregation::verify_aggregate(&aggregate, &z0)?;
    println!("✓ Structural verification passed");

    // Step 5: Full verification with originals
    println!("\nStep 5: Full verification against original proofs...");
    proof_aggregation::verify_aggregate_full(&aggregate, &proofs, &verifier)?;
    println!("✓ Full cryptographic verification passed");

    // Step 6: Extract per-transaction data
    println!("\nStep 6: Extracting per-transaction authorized pairs...");
    for i in 0..aggregate.tx_metadata.len() {
        let pairs = proof_aggregation::get_tx_authorized_pairs(&aggregate, i).unwrap();
        println!("  TX {}: {} pairs", i + 1, pairs.len());
        for (j, (cv, rk)) in pairs.iter().enumerate() {
            println!("    Action {}: cv={}, rk={}", 
                j + 1, 
                hex::encode(&cv[..4]),
                hex::encode(&rk[..4])
            );
        }
    }

    // Step 7: Demonstrate different context policies
    println!("\nStep 7: Testing different context policies...");
    test_context_policies(&proofs)?;

    println!("\n✅ All aggregation operations completed successfully!");
    println!("\nThis demonstrates:");
    println!("  ✓ Real cryptographic proof generation");
    println!("  ✓ Individual proof verification");
    println!("  ✓ Proof aggregation with commitment binding");
    println!("  ✓ Full aggregate verification");
    println!("  ✓ Merkle commitment over authorized pairs");
    println!("  ✓ Deterministic aggregate digests");
    println!("  ✓ Flexible context policies");

    Ok(())
}

/// Generate real tachystamp proofs using Nova recursion
fn generate_real_proofs(count: usize) -> Result<Vec<tachystamps::Compressed>, Box<dyn std::error::Error>> {
    use tachystamps::*;
    
    let mut proofs = Vec::new();
    
    // Create public parameters (same for all proofs)
    let pp = Prover::public_params()?;
    
    for i in 0..count {
        // Create a prover instance
        let z0 = vec![PallasFp::from(0u64), PallasFp::from(0u64)];
        let mut prover = Prover::new(pp.clone(), z0)?;
        
        // Add 2-3 actions per proof
        let num_actions = 2 + (i % 2);
        for j in 0..num_actions {
            // Generate random (cv_net, rk) pair
            let mut cv = [0u8; 32];
            let mut rk = [0u8; 32];
            OsRng.fill_bytes(&mut cv);
            OsRng.fill_bytes(&mut rk);
            
            prover.add_authorized_pair(cv, rk);
        }
        
        // Create dummy membership proofs (for demo purposes)
        let tree_leaves = vec![Tachygram([i as u8; 32])];
        let tree = build_tree(&tree_leaves, 4);
        let path = open_path(&tree, 0);
        
        let anchor_range = AnchorRange { start: 0, end: 100 };
        
        // Add a proof step
        prover.step(&path, &tree_leaves[0], &anchor_range)?;
        
        // Finalize to compressed proof
        let compressed = prover.finalize()?;
        proofs.push(compressed);
    }
    
    Ok(proofs)
}

/// Test all context policy variants
fn test_context_policies(proofs: &[tachystamps::Compressed]) -> Result<(), Box<dyn std::error::Error>> {
    use proof_aggregation::*;
    
    let verifier = NoopVerifier; // Use noop for quick policy testing
    
    // Test Zero policy
    let mut batch = ProofBatch::new();
    for (i, p) in proofs.iter().enumerate() {
        batch.add_proof(p.clone(), format!("tx-{}", i).into_bytes());
    }
    let agg = aggregate_proofs_with_verifier_and_policy(
        batch, 1, &verifier, ContextPolicy::Zero
    )?;
    println!("  ✓ Zero policy: ctx = {}", agg.merged_proof.meta.ctx);
    
    // Test FromAggregateId policy
    let mut batch = ProofBatch::new();
    for (i, p) in proofs.iter().enumerate() {
        batch.add_proof(p.clone(), format!("tx-{}", i).into_bytes());
    }
    let agg = aggregate_proofs_with_verifier_and_policy(
        batch, 99, &verifier, ContextPolicy::FromAggregateId
    )?;
    println!("  ✓ FromAggregateId policy: ctx = {}", agg.merged_proof.meta.ctx);
    
    // Test CombineInputContexts policy
    let mut batch = ProofBatch::new();
    for (i, p) in proofs.iter().enumerate() {
        batch.add_proof(p.clone(), format!("tx-{}", i).into_bytes());
    }
    let agg = aggregate_proofs_with_verifier_and_policy(
        batch, 1, &verifier, ContextPolicy::CombineInputContexts
    )?;
    println!("  ✓ CombineInputContexts policy: ctx = {}", agg.merged_proof.meta.ctx);
    
    // Test HashWithMetadata policy
    let mut batch = ProofBatch::new();
    for (i, p) in proofs.iter().enumerate() {
        batch.add_proof(p.clone(), format!("tx-{}", i).into_bytes());
    }
    let agg = aggregate_proofs_with_verifier_and_policy(
        batch, 1, &verifier, ContextPolicy::HashWithMetadata
    )?;
    println!("  ✓ HashWithMetadata policy: ctx = {} (hash-derived)", 
        hex::encode(&agg.merged_proof.meta.ctx.to_repr()[..4]));
    
    // Test Custom policy
    let mut batch = ProofBatch::new();
    for (i, p) in proofs.iter().enumerate() {
        batch.add_proof(p.clone(), format!("tx-{}", i).into_bytes());
    }
    let custom_ctx = PallasFp::from(12345u64);
    let agg = aggregate_proofs_with_verifier_and_policy(
        batch, 1, &verifier, ContextPolicy::Custom(custom_ctx)
    )?;
    println!("  ✓ Custom policy: ctx = {}", agg.merged_proof.meta.ctx);
    
    Ok(())
}

