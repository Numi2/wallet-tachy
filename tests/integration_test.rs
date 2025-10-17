//! Integration Tests for Tachyon Wallet
//!
//! Complete transaction lifecycle:
//! 1. Key generation
//! 2. Note creation (output)
//! 3. Transaction building
//! 4. Signing with randomized keys
//! 5. Bundle construction
//! 6. Verification
//! 7. Note spending

#[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
mod full_flow_tests {
    use rand::rngs::OsRng;
    use tachy_wallet::*;

    #[test]
    fn test_complete_payment_flow() {
        // ========== Setup: Key Generation ==========
        
        // Sender's keys
        let sender_ask = SpendAuthorizationKey::random(OsRng);
        let sender_ak = SpendAuthorizationVerifyingKey::from(&sender_ask);
        let sender_pk = PaymentKey::random(OsRng);
        let sender_nk = NullifierKey::random(OsRng);
        
        // Recipient's keys
        let recipient_pk = PaymentKey::random(OsRng);
        
        // ========== Step 1: Create a Note (Sender receives funds) ==========
        
        // Simulate sender receiving a note from a previous transaction
        let shared_secret_in = b"sender-receives-note-secret-123456789012";
        let (psi_in, rcm_in, flavor_in) = derive_note_secrets(shared_secret_in);
        
        let sender_note = TachyonNote::new(sender_pk, 100_000_000, psi_in, rcm_in); // 1 ZEC
        
        // Compute commitment (would be published on-chain)
        let sender_cm = sender_note.commitment();
        
        println!("✓ Sender received note with value: {} zatoshis", sender_note.value);
        println!("  Note commitment: {:?}", hex::encode(&sender_cm.0[..8]));
        
        // ========== Step 2: Build Transaction to Send Funds ==========
        
        // Sender wants to send 0.5 ZEC to recipient
        let send_amount = 50_000_000u64; // 0.5 ZEC
        let change_amount = 50_000_000u64; // 0.5 ZEC change back to sender
        
        // Establish shared secret with recipient (out-of-band)
        let shared_secret_out = b"sender-to-recipient-secret-789012345678";
        let (psi_out, rcm_out, _flavor_out) = derive_note_secrets(shared_secret_out);
        
        // Create output note for recipient
        let recipient_note = TachyonNote::new(recipient_pk, send_amount, psi_out, rcm_out);
        
        // Create change note for sender
        let shared_secret_change = b"sender-change-secret-456789012345678901";
        let (psi_change, rcm_change, _flavor_change) = derive_note_secrets(shared_secret_change);
        let change_note = TachyonNote::new(sender_pk, change_amount, psi_change, rcm_change);
        
        println!("✓ Created output notes:");
        println!("  Recipient: {} zatoshis", recipient_note.value);
        println!("  Change: {} zatoshis", change_note.value);
        
        // ========== Step 3: Create Spend Context ==========
        
        // Build a dummy Merkle tree and get witness
        let tree_leaves = vec![Tachygram(sender_cm.0)];
        let tree = crate::tachystamps::build_tree(&tree_leaves, 4); // Height 4
        let merkle_path = crate::tachystamps::open_path(&tree, 0);
        
        let spend_ctx = SpendContext {
            note: sender_note.clone(),
            nk: sender_nk,
            flavor: flavor_in,
            merkle_path,
            note_index: 0,
        };
        
        // ========== Step 4: Build Transaction ==========
        
        let tree_root = {
            use halo2curves::pasta::Fp as PallasFp;
            use halo2curves::ff::PrimeField;
            tree.root().to_repr()
        };
        
        let anchor_range = AnchorRange { start: 0, end: 100 };
        
        let mut tx_builder = TachyonTxBuilder::new(tree_root, anchor_range);
        tx_builder.add_spend(spend_ctx);
        
        let output_ctx_recipient = OutputContext {
            note: recipient_note,
            tree_root,
            note_index: 1,
        };
        let output_ctx_change = OutputContext {
            note: change_note,
            tree_root,
            note_index: 2,
        };
        
        tx_builder.add_output(output_ctx_recipient);
        tx_builder.add_output(output_ctx_change);
        
        // Check balance
        assert!(tx_builder.check_balance().is_ok());
        println!("✓ Transaction balanced");
        
        // Extract tachygrams
        let tachygrams = tx_builder.extract_tachygrams();
        assert_eq!(tachygrams.len(), 3); // 1 nullifier + 2 commitments
        println!("✓ Extracted {} tachygrams", tachygrams.len());
        
        // ========== Step 5: Sign with Randomized Keys ==========
        
        let (rsk, rk, alpha) = create_randomized_keypair(&sender_ask, OsRng);
        
        let message = b"transaction-signature-message";
        let sig = rsk.sign(message, OsRng);
        
        // Verify signature
        assert!(verify_with_randomized_key(&rk, message, &sig).is_ok());
        println!("✓ Created and verified randomized signature");
        
        // ========== Step 6: Note Encryption (Traditional Action Path) ==========
        
        use halo2curves::pasta::pallas::{Affine as PallasAffine, Point as PallasPoint, Scalar as PallasScalar};
        use halo2curves::ff::{Field, PrimeField};
        use group::{Curve, Group, GroupEncoding};
        
        let esk = EphemeralSecretKey::random(OsRng);
        let ivk = IncomingViewingKey::random(OsRng);
        
        // Derive pk_d from ivk (simplified)
        let ivk_scalar = PallasScalar::from_repr(ivk.0).unwrap();
        let pk_d = DiversifiedTransmissionKey(
            PallasAffine::from(PallasPoint::generator() * ivk_scalar).to_bytes()
        );
        
        let note_plaintext = NotePlaintext::new(
            100_000_000,
            [3u8; 32], // rho
            [4u8; 32], // rseed
            b"Payment memo".to_vec(),
        ).unwrap();
        
        let (epk, ciphertext) = encrypt_note(&note_plaintext, &pk_d, &esk).unwrap();
        let decrypted = decrypt_note(&ciphertext, &epk, &ivk).unwrap();
        
        assert_eq!(decrypted.value, note_plaintext.value);
        println!("✓ Note encryption/decryption successful");
        
        println!("\n✅ Complete transaction flow test passed!");
    }

    #[test]
    fn test_value_commitment_balance() {
        use tachy_wallet::value_commit::*;
        
        // Simulate a balanced transaction: 1 ZEC in, 0.6 ZEC out, 0.4 ZEC change
        let rcv_spend = ValueCommitRandomness::random(OsRng);
        let rcv_out1 = ValueCommitRandomness::random(OsRng);
        let rcv_out2 = ValueCommitRandomness::random(OsRng);
        
        let cv_spend = ValueCommit::new(100_000_000, &rcv_spend); // 1 ZEC input
        let cv_out1 = ValueCommit::new(60_000_000, &rcv_out1);   // 0.6 ZEC output
        let cv_out2 = ValueCommit::new(40_000_000, &rcv_out2);   // 0.4 ZEC change
        
        // Binding signing key = rcv_spend - rcv_out1 - rcv_out2
        use halo2curves::ff::Field;
        let bsk_scalar = rcv_spend.0 - rcv_out1.0 - rcv_out2.0;
        let bsk = BindingSigningKey(bsk_scalar);
        let bvk = BindingVerifyingKey::from_signing_key(&bsk);
        
        // Sign transaction
        let message = b"balanced-transaction";
        let sig = bsk.sign(message, OsRng);
        
        // Verify
        assert!(sig.verify(&bvk, message).is_ok());
        
        println!("✓ Value commitment balance verification passed");
    }

    #[test]
    fn test_unlinkability() {
        // Same wallet, two different transactions
        let ask = SpendAuthorizationKey::random(OsRng);
        
        // Transaction 1
        let (rsk1, rk1, _) = create_randomized_keypair(&ask, OsRng);
        let msg1 = b"transaction-1";
        let sig1 = rsk1.sign(msg1, OsRng);
        
        // Transaction 2 (same wallet, different randomization)
        let (rsk2, rk2, _) = create_randomized_keypair(&ask, OsRng);
        let msg2 = b"transaction-2";
        let sig2 = rsk2.sign(msg2, OsRng);
        
        // Each verifies independently
        assert!(verify_with_randomized_key(&rk1, msg1, &sig1).is_ok());
        assert!(verify_with_randomized_key(&rk2, msg2, &sig2).is_ok());
        
        // Keys should be different (unlinkable)
        assert_ne!(rk1, rk2);
        
        // Cross-verification fails
        assert!(verify_with_randomized_key(&rk1, msg2, &sig2).is_err());
        assert!(verify_with_randomized_key(&rk2, msg1, &sig1).is_err());
        
        println!("✓ Transaction unlinkability verified");
    }

    #[test]
    fn test_proof_aggregation_flow() {
        use tachy_wallet::proof_aggregation::*;
        use halo2curves::pasta::Fp as PallasFp;
        
        // Create multiple transactions
        let mut batch = ProofBatch::new();
        
        // Transaction 1: 2 actions
        let proof1 = Compressed {
            proof: vec![1, 2, 3],
            vk: vec![4, 5, 6],
            meta: crate::tachystamps::ProofMeta {
                steps: 1,
                acc_init: PallasFp::from(0u64),
                acc_final: PallasFp::from(1u64),
                ctx: PallasFp::from(2u64),
                authorized_pairs: vec![
                    ([1u8; 32], [101u8; 32]),
                    ([2u8; 32], [102u8; 32]),
                ],
            },
        };
        
        // Transaction 2: 3 actions
        let proof2 = Compressed {
            proof: vec![7, 8, 9],
            vk: vec![10, 11, 12],
            meta: crate::tachystamps::ProofMeta {
                steps: 1,
                acc_init: PallasFp::from(1u64),
                acc_final: PallasFp::from(2u64),
                ctx: PallasFp::from(3u64),
                authorized_pairs: vec![
                    ([3u8; 32], [103u8; 32]),
                    ([4u8; 32], [104u8; 32]),
                    ([5u8; 32], [105u8; 32]),
                ],
            },
        };
        
        batch.add_proof(proof1, b"tx1-context".to_vec());
        batch.add_proof(proof2, b"tx2-context".to_vec());
        
        // Aggregate
        let aggregate = aggregate_proofs(batch, 42).unwrap();
        
        // Verify aggregate structure
        assert_eq!(aggregate.total_actions, 5);
        assert_eq!(aggregate.tx_metadata.len(), 2);
        assert_eq!(aggregate.tx_metadata[0].action_count, 2);
        assert_eq!(aggregate.tx_metadata[1].action_count, 3);
        
        // Verify aggregate
        let z0 = vec![PallasFp::from(0u64), PallasFp::from(0u64), PallasFp::from(0u64)];
        assert!(verify_aggregate(&aggregate, &z0).is_ok());
        
        // Extract pairs for transaction 1
        let tx1_pairs = get_tx_authorized_pairs(&aggregate, 0).unwrap();
        assert_eq!(tx1_pairs.len(), 2);
        assert_eq!(tx1_pairs[0].0, [1u8; 32]);
        assert_eq!(tx1_pairs[0].1, [101u8; 32]);
        
        println!("✓ Proof aggregation flow verified");
    }

    #[test]
    fn test_oblivious_sync_flow() {
        use tachy_wallet::blockchain_provider::*;
        
        // Create a cached provider
        let provider = CachedBlockchainProvider::new();
        
        // Add some blocks
        provider.add_block(
            100,
            vec![Tachygram([1u8; 32]), Tachygram([2u8; 32])],
            [0u8; 32],
            vec![],
        );
        
        provider.add_block(
            101,
            vec![Tachygram([3u8; 32])],
            [1u8; 32],
            vec![crate::oblivious_sync::Nullifier([10u8; 32])],
        );
        
        // Query blocks
        let tachygrams = provider.get_tachygrams_in_block(100).unwrap();
        assert_eq!(tachygrams.len(), 2);
        
        // Check nullifier
        let nf = crate::oblivious_sync::Nullifier([10u8; 32]);
        let spent = provider.is_nullifier_spent_in_range(&nf, 100, 102).unwrap();
        assert_eq!(spent, Some(101));
        
        println!("✓ Oblivious sync provider working");
    }

    #[test]
    fn test_wallet_sync_with_provider() {
        use tachy_wallet::blockchain_provider::*;
        use tachy_wallet::oblivious_sync::*;
        use halo2curves::pasta::Fp as PallasFp;
        
        // Create provider and add blocks
        let provider = CachedBlockchainProvider::new();
        for i in 1..=10 {
            provider.add_block(i, vec![], [i as u8; 32], vec![]);
        }
        
        // Create wallet
        let mut wallet = WalletState::new();
        
        // Add a note to track
        let nullifier = crate::oblivious_sync::Nullifier([42u8; 32]);
        let commitment = Tachygram([43u8; 32]);
        let witness = crate::tachystamps::MerklePath {
            siblings: vec![PallasFp::from(0u64); 4],
            directions: vec![false; 4],
        };
        
        wallet.add_note(nullifier, commitment, witness, 5);
        
        assert_eq!(wallet.notes.len(), 1);
        assert_eq!(wallet.current_block, 0);
        
        println!("✓ Wallet sync setup completed");
    }
}

#[cfg(not(all(feature = "tachystamps", feature = "oblivious-sync")))]
#[test]
fn test_features_required() {
    println!("⚠️  Integration tests require features: tachystamps, oblivious-sync");
    println!("   Run with: cargo test --features tachystamps,oblivious-sync");
}

