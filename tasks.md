Architecture & Crypto
Migrate to Halo2 with custom Poseidon gates and lookup tables - would reduce circuit size by ~10x and prover time by ~5x compared to Nova's generic R1CS.
Use poseidon-paramgen for domain-specific parameters - currently relying on Nova's built-in constants which aren't optimized for Tachyon's specific security level.
Implement proper SnarkPack-style proof aggregation - current aggregation works but doesn't achieve logarithmic verifier cost for block-level batching.
Add formal nullifier flavor cryptanalysis - the oblivious sync privacy claim needs rigorous proof that flavor mechanism prevents position leakage.
Implement full Merkle non-membership proofs for spent nullifier set - currently simplified to just accumulator updates.
Performance & Optimization
Replace Sled with async-compatible storage - use redb or surrealdb to avoid blocking I/O in wallet sync operations.
Add incremental Merkle tree caching with frontier optimization - currently rebuilding witnesses from scratch, should use sparse Merkle tree with cached frontiers.
Batch RedPallas signature verification - implement reddsa's batch API to verify 100+ signatures in ~2x time of single verification.
SIMD-optimize Poseidon native hash - current implementation doesn't use vector instructions, leaving 4-8x performance on table.
Implement proof compression with recursive SNARKs - compress tachystamps from ~20KB to ~2KB using final Halo2 wrapping layer.
Security & Testing
Add property-based testing with proptest - critical for circuit satisfiability, nullifier uniqueness, and balance integrity properties.
Implement constant-time Poseidon in-circuit - current circuit doesn't guarantee timing-attack resistance for secret witnesses.
Fuzz test all deserialization paths - use cargo-fuzz on proof verification, action parsing, and bundle validation to find panics.
Add comprehensive test vectors from Zcash test suite - currently no cross-implementation validation against Orchard reference.
Perform formal circuit audit - verify constraint system soundness, especially for Merkle path gadget and nullifier derivation.
Protocol Completeness
Implement full out-of-band payment KEM - currently stubbed, needs proper X25519/ML-KEM hybrid for post-quantum resistance.
Add mixnet integration for network privacy - oblivious sync only works if requests can't be correlated; needs Nym or Tor integration.
Implement ZIP-224 compliant fee mechanism - no transaction fee handling exists, blocks real network deployment.
Add multi-asset support (ZSAs) - current value commitments assume single asset, needs asset ID binding.
Implement viewing key derivation and wallet export - full ZIP-32 hierarchical key derivation missing, only basic key generation exists.
Developer Experience
Compile to WASM for browser wallets - current ark-* dependencies and Nova don't support wasm32-unknown-unknown target.
Add comprehensive benchmarking suite with Criterion - no systematic measurement of proof generation, verification, or sync times.
Generate circuit diagrams and constraint counts - use halo2_proofs::dev::MockProver visualization tools for debugging.
Write protocol specification document - code comments exist but no standalone spec for independent implementation.
Add OpenAPI spec for oblivious sync service - currently just internal structs, needs standardized REST/gRPC interface.
Infrastructure
Implement actual blockchain RPC integration - RpcBlockchainProvider is stubbed, needs zcashd/zebra JSON-RPC client.
Add persistent proof cache with content-addressing - tachystamps should be deduplicated by digest to save storage.
Implement hardware wallet integration - signing keys should support Ledger/Trezor via SLIP-0044 derivation.
Add telemetry and metrics - instrument prover time, sync latency, proof size for production monitoring.
Create Docker images for oblivious sync service - needs reproducible build environment and deployment tooling.
