//! Blockchain Provider Implementations for Oblivious Sync
//! just for testing
//! numan thabit
//!
//! The `BlockchainProvider` trait abstracts blockchain access, allowing wallets
//! to sync against different backends:
//! - Full nodes (via RPC)
//! - Light clients (compact blocks)
//! - Block explorers (HTTP API)
//! - Local cache (for offline operation)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::oblivious_sync::{BlockchainProvider, SyncError};
use crate::tachystamps::Tachygram;

// Re-export Nullifier from oblivious_sync
use crate::oblivious_sync::Nullifier;

// ----------------------------- RPC Provider -----------------------------

/// Configuration for RPC blockchain provider
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    /// RPC endpoint URL
    pub endpoint: String,
    
    /// RPC username (optional)
    pub username: Option<String>,
    
    /// RPC password (optional)
    pub password: Option<String>,
    
    /// Request timeout in seconds
    pub timeout_secs: u64,
    
    /// Maximum retry attempts
    pub max_retries: u32,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:8232".to_string(),
            username: None,
            password: None,
            timeout_secs: 30,
            max_retries: 3,
        }
    }
}

/// RPC-based blockchain provider
///
/// Connects to a Zcash node's RPC interface to fetch blockchain data.
pub struct RpcBlockchainProvider {
    config: RpcConfig,
    // Cache for frequently accessed data
    cache: Arc<RwLock<BlockchainCache>>,
    // HTTP client
    agent: ureq::Agent,
}

impl RpcBlockchainProvider {
    /// Create a new RPC provider
    pub fn new(config: RpcConfig) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build();
        
        Self {
            config,
            cache: Arc::new(RwLock::new(BlockchainCache::new())),
            agent,
        }
    }
    
    /// Test connection to the RPC server
    pub fn test_connection(&self) -> Result<(), RpcError> {
        if self.config.endpoint.is_empty() {
            return Err(RpcError::InvalidEndpoint);
        }
        
        // Try to fetch blockchain info
        let _info = self.rpc_call("getblockchaininfo", &[])?;
        Ok(())
    }
    
    /// Make an RPC call to the Zcash node
    fn rpc_call(&self, method: &str, params: &[serde_json::Value]) -> Result<serde_json::Value, RpcError> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "tachy-wallet",
            "method": method,
            "params": params,
        });
        
        let mut request = self.agent
            .post(&self.config.endpoint)
            .set("Content-Type", "application/json");
        
        // Add basic auth if configured
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let auth = STANDARD.encode(format!("{}:{}", username, password));
            request = request.set("Authorization", &format!("Basic {}", auth));
        }
        
        let response = request
            .send_json(&request_body)
            .map_err(|e| RpcError::RequestFailed(e.to_string()))?;
        
        let response_json: serde_json::Value = response
            .into_json()
            .map_err(|e| RpcError::ParseError(e.to_string()))?;
        
        // Check for RPC error
        if let Some(error) = response_json.get("error") {
            if !error.is_null() {
                return Err(RpcError::RequestFailed(error.to_string()));
            }
        }
        
        // Extract result
        response_json
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::ParseError("missing result field".into()))
    }
    
    /// Get block hash by height
    fn get_block_hash(&self, height: u64) -> Result<String, RpcError> {
        let result = self.rpc_call("getblockhash", &[height.into()])?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::ParseError("block hash not a string".into()))
    }
    
    /// Fetch a block by height (RPC: getblock)
    fn fetch_block(&self, height: u64) -> Result<BlockData, RpcError> {
        // Check cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(block) = cache.get_block(height) {
                return Ok(block);
            }
        }
        
        // Fetch block hash
        let block_hash = self.get_block_hash(height)?;
        
        // Fetch full block data (verbosity=2 for full tx details)
        let block_json = self.rpc_call("getblock", &[block_hash.into(), 2.into()])?;
        
        // Parse block data
        let block_data = self.parse_block_data(height, &block_json)?;
        
        // Cache it
        {
            let mut cache = self.cache.write().unwrap();
            cache.add_block(block_data.clone());
        }
        
        Ok(block_data)
    }
    
    /// Parse block JSON into BlockData
    fn parse_block_data(&self, height: u64, block_json: &serde_json::Value) -> Result<BlockData, RpcError> {
        let mut tachygrams = Vec::new();
        let mut nullifiers_spent = Vec::new();
        
        // Get transactions array from block
        let txs = block_json
            .get("tx")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::ParseError("missing tx array".into()))?;
        
        // Parse each transaction
        for tx in txs {
            // Extract Orchard bundle if present
            if let Some(orchard_bundle) = tx.get("orchard") {
                self.parse_orchard_bundle(orchard_bundle, &mut tachygrams, &mut nullifiers_spent)?;
            }
            
            // Extract Tachyon bundle if present (future extension)
            if let Some(tachyon_bundle) = tx.get("tachyon") {
                self.parse_tachyon_bundle(tachyon_bundle, &mut tachygrams, &mut nullifiers_spent)?;
            }
        }
        
        // Get final tree state (anchor) from block
        // Zcash stores this in the block header's final tree state
        let anchor = if let Some(final_state) = block_json.get("finalorchardroot") {
            self.parse_anchor(final_state)?
        } else {
            [0u8; 32] // Genesis or pre-Orchard block
        };
        
        Ok(BlockData {
            height,
            tachygrams,
            anchor,
            nullifiers_spent,
        })
    }
    
    /// Parse Orchard bundle to extract tachygrams
    fn parse_orchard_bundle(
        &self,
        bundle: &serde_json::Value,
        tachygrams: &mut Vec<Tachygram>,
        nullifiers_spent: &mut Vec<Nullifier>,
    ) -> Result<(), RpcError> {
        // Parse actions array
        let actions = bundle
            .get("actions")
            .and_then(|v| v.as_array())
            .ok_or_else(|| RpcError::ParseError("missing orchard actions".into()))?;
        
        for action in actions {
            // Extract nullifier (spent note)
            if let Some(nf_hex) = action.get("nullifier").and_then(|v| v.as_str()) {
                let nf_bytes = hex::decode(nf_hex)
                    .map_err(|e| RpcError::ParseError(format!("invalid nullifier hex: {}", e)))?;
                
                if nf_bytes.len() == 32 {
                    let mut nf = [0u8; 32];
                    nf.copy_from_slice(&nf_bytes);
                    
                    nullifiers_spent.push(Nullifier(nf));
                    tachygrams.push(Tachygram(nf)); // Nullifiers are tachygrams in Tachyon
                }
            }
            
            // Extract note commitment (created note)
            if let Some(cm_hex) = action.get("cmx").and_then(|v| v.as_str()) {
                let cm_bytes = hex::decode(cm_hex)
                    .map_err(|e| RpcError::ParseError(format!("invalid cmx hex: {}", e)))?;
                
                if cm_bytes.len() == 32 {
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(&cm_bytes);
                    
                    tachygrams.push(Tachygram(cm)); // Commitments are tachygrams
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse Tachyon bundle (future extension for Tachyon protocol)
    fn parse_tachyon_bundle(
        &self,
        bundle: &serde_json::Value,
        tachygrams: &mut Vec<Tachygram>,
        nullifiers_spent: &mut Vec<Nullifier>,
    ) -> Result<(), RpcError> {
        // Tachyon bundles will have a similar structure but with tachyactions
        // For now, use the same parsing logic as Orchard
        
        // Parse tachyactions array
        let actions = bundle
            .get("tachyactions")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![]); // Tachyon may not be deployed yet
        
        for action in actions {
            // Tachyactions don't contain nullifiers/commitments directly
            // They reference tachygrams via a separate tachystamp
            // Skip for now (would need tachystamp parsing)
        }
        
        // Parse traditional actions if present
        if let Some(traditional) = bundle.get("traditional_actions") {
            if let Some(actions) = traditional.as_array() {
                for action in actions {
                    // Parse like Orchard actions
                    if let Some(nf_hex) = action.get("nf").and_then(|v| v.as_str()) {
                        if let Ok(nf_bytes) = hex::decode(nf_hex) {
                            if nf_bytes.len() == 32 {
                                let mut nf = [0u8; 32];
                                nf.copy_from_slice(&nf_bytes);
                                nullifiers_spent.push(Nullifier(nf));
                                tachygrams.push(Tachygram(nf));
                            }
                        }
                    }
                    
                    if let Some(cm_hex) = action.get("cmX").and_then(|v| v.as_str()) {
                        if let Ok(cm_bytes) = hex::decode(cm_hex) {
                            if cm_bytes.len() == 32 {
                                let mut cm = [0u8; 32];
                                cm.copy_from_slice(&cm_bytes);
                                tachygrams.push(Tachygram(cm));
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse anchor from final tree state
    fn parse_anchor(&self, anchor_value: &serde_json::Value) -> Result<[u8; 32], RpcError> {
        let anchor_hex = anchor_value
            .as_str()
            .ok_or_else(|| RpcError::ParseError("anchor not a string".into()))?;
        
        let anchor_bytes = hex::decode(anchor_hex)
            .map_err(|e| RpcError::ParseError(format!("invalid anchor hex: {}", e)))?;
        
        if anchor_bytes.len() != 32 {
            return Err(RpcError::ParseError(format!(
                "invalid anchor length: {} (expected 32)",
                anchor_bytes.len()
            )));
        }
        
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&anchor_bytes);
        Ok(anchor)
    }
    
    /// Get blockchain info (RPC: getblockchaininfo)
    pub fn get_blockchain_info(&self) -> Result<serde_json::Value, RpcError> {
        self.rpc_call("getblockchaininfo", &[])
    }
    
    /// Get transaction (RPC: getrawtransaction)
    pub fn get_transaction(&self, txid: &str, verbose: bool) -> Result<serde_json::Value, RpcError> {
        self.rpc_call("getrawtransaction", &[txid.into(), verbose.into()])
    }
    
    /// Send raw transaction (RPC: sendrawtransaction)
    pub fn send_raw_transaction(&self, hex_tx: &str) -> Result<String, RpcError> {
        let result = self.rpc_call("sendrawtransaction", &[hex_tx.into()])?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::ParseError("txid not a string".into()))
    }
    
    /// Get transaction count (RPC: gettxoutsetinfo)
    pub fn get_tx_out_set_info(&self) -> Result<serde_json::Value, RpcError> {
        self.rpc_call("gettxoutsetinfo", &[])
    }
    
    /// Clear the cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.blocks.clear();
        cache.nullifier_index.clear();
    }
}

impl BlockchainProvider for RpcBlockchainProvider {
    fn get_tachygrams_in_block(&self, block_height: u64) -> Result<Vec<Tachygram>, SyncError> {
        let block = self.fetch_block(block_height)
            .map_err(|e| SyncError::BlockchainDataUnavailable(block_height))?;
        
        Ok(block.tachygrams)
    }
    
    fn is_nullifier_spent_in_range(
        &self,
        nullifier: &Nullifier,
        from_block: u64,
        to_block: u64,
    ) -> Result<Option<u64>, SyncError> {
        // In production, this would query the node's nullifier set
        // For now, use cache
        let cache = self.cache.read().unwrap();
        Ok(cache.get_nullifier_spend_height(nullifier, from_block, to_block))
    }
    
    fn current_block_height(&self) -> Result<u64, SyncError> {
        // In production: RPC call to getblockcount
        let cache = self.cache.read().unwrap();
        Ok(cache.tip_height)
    }
    
    fn get_anchor_at_block(&self, block_height: u64) -> Result<[u8; 32], SyncError> {
        let block = self.fetch_block(block_height)
            .map_err(|_| SyncError::BlockchainDataUnavailable(block_height))?;
        
        Ok(block.anchor)
    }
}

// ----------------------------- Cached/Local Provider -----------------------------

/// In-memory blockchain data
#[derive(Clone, Debug)]
struct BlockData {
    height: u64,
    tachygrams: Vec<Tachygram>,
    anchor: [u8; 32],
    nullifiers_spent: Vec<Nullifier>,
}

/// Cache for blockchain data
struct BlockchainCache {
    blocks: BTreeMap<u64, BlockData>,
    nullifier_index: BTreeMap<Nullifier, u64>, // nullifier -> block height spent
    tip_height: u64,
}

impl BlockchainCache {
    fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            tip_height: 0,
        }
    }
    
    fn get_block(&self, height: u64) -> Option<BlockData> {
        self.blocks.get(&height).cloned()
    }
    
    fn add_block(&mut self, block: BlockData) {
        // Index nullifiers
        for nf in &block.nullifiers_spent {
            self.nullifier_index.insert(*nf, block.height);
        }
        
        if block.height > self.tip_height {
            self.tip_height = block.height;
        }
        
        self.blocks.insert(block.height, block);
    }
    
    fn get_nullifier_spend_height(
        &self,
        nullifier: &Nullifier,
        from_block: u64,
        to_block: u64,
    ) -> Option<u64> {
        self.nullifier_index.get(nullifier)
            .copied()
            .filter(|&h| h >= from_block && h <= to_block)
    }
}

/// A cached/local blockchain provider
///
/// Uses an in-memory cache with optional disk persistence.
/// Useful for light clients and testing.
pub struct CachedBlockchainProvider {
    cache: Arc<RwLock<BlockchainCache>>,
    upstream: Option<Box<dyn BlockchainProvider + Send + Sync>>,
}

impl CachedBlockchainProvider {
    /// Create a new cached provider
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(BlockchainCache::new())),
            upstream: None,
        }
    }
    
    /// Create with an upstream provider for cache-through
    pub fn with_upstream(upstream: Box<dyn BlockchainProvider + Send + Sync>) -> Self {
        Self {
            cache: Arc::new(RwLock::new(BlockchainCache::new())),
            upstream: Some(upstream),
        }
    }
    
    /// Add a block to the cache
    pub fn add_block(
        &self,
        height: u64,
        tachygrams: Vec<Tachygram>,
        anchor: [u8; 32],
        nullifiers_spent: Vec<Nullifier>,
    ) {
        let mut cache = self.cache.write().unwrap();
        cache.add_block(BlockData {
            height,
            tachygrams,
            anchor,
            nullifiers_spent,
        });
    }
    
    /// Get current cache size (number of blocks)
    pub fn cache_size(&self) -> usize {
        self.cache.read().unwrap().blocks.len()
    }
    
    /// Clear cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.blocks.clear();
        cache.nullifier_index.clear();
    }
}

impl BlockchainProvider for CachedBlockchainProvider {
    fn get_tachygrams_in_block(&self, block_height: u64) -> Result<Vec<Tachygram>, SyncError> {
        // Try cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(block) = cache.get_block(block_height) {
                return Ok(block.tachygrams);
            }
        }
        
        // Try upstream if available
        if let Some(upstream) = &self.upstream {
            let tachygrams = upstream.get_tachygrams_in_block(block_height)?;
            
            // Cache the result
            // Note: We'd need the full block data to cache properly
            // For now, skip caching on upstream hits
            
            return Ok(tachygrams);
        }
        
        Err(SyncError::BlockchainDataUnavailable(block_height))
    }
    
    fn is_nullifier_spent_in_range(
        &self,
        nullifier: &Nullifier,
        from_block: u64,
        to_block: u64,
    ) -> Result<Option<u64>, SyncError> {
        // Check cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(height) = cache.get_nullifier_spend_height(nullifier, from_block, to_block) {
                return Ok(Some(height));
            }
        }
        
        // Try upstream
        if let Some(upstream) = &self.upstream {
            return upstream.is_nullifier_spent_in_range(nullifier, from_block, to_block);
        }
        
        // Not found in cache and no upstream
        Ok(None)
    }
    
    fn current_block_height(&self) -> Result<u64, SyncError> {
        // Check upstream first for most recent data
        if let Some(upstream) = &self.upstream {
            return upstream.current_block_height();
        }
        
        // Fall back to cache
        Ok(self.cache.read().unwrap().tip_height)
    }
    
    fn get_anchor_at_block(&self, block_height: u64) -> Result<[u8; 32], SyncError> {
        // Try cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(block) = cache.get_block(block_height) {
                return Ok(block.anchor);
            }
        }
        
        // Try upstream
        if let Some(upstream) = &self.upstream {
            return upstream.get_anchor_at_block(block_height);
        }
        
        Err(SyncError::BlockchainDataUnavailable(block_height))
    }
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("invalid RPC endpoint")]
    InvalidEndpoint,
    
    #[error("RPC request failed: {0}")]
    RequestFailed(String),
    
    #[error("RPC response parse error: {0}")]
    ParseError(String),
    
    #[error("authentication failed")]
    AuthenticationFailed,
    
    #[error("not implemented: {0}")]
    NotImplemented(String),
    
    #[error("timeout after {0} seconds")]
    Timeout(u64),
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cached_provider() {
        let provider = CachedBlockchainProvider::new();
        
        // Add some test data
        let tachygrams = vec![
            Tachygram([1u8; 32]),
            Tachygram([2u8; 32]),
        ];
        let nullifiers = vec![
            Nullifier([10u8; 32]),
            Nullifier([11u8; 32]),
        ];
        
        provider.add_block(100, tachygrams.clone(), [0u8; 32], nullifiers.clone());
        
        // Should be able to retrieve
        let retrieved = provider.get_tachygrams_in_block(100).unwrap();
        assert_eq!(retrieved.len(), 2);
        
        // Nullifier check
        let spent = provider.is_nullifier_spent_in_range(&nullifiers[0], 50, 150).unwrap();
        assert_eq!(spent, Some(100));
        
        let not_spent = provider.is_nullifier_spent_in_range(&Nullifier([99u8; 32]), 50, 150).unwrap();
        assert_eq!(not_spent, None);
    }
    
    #[test]
    fn test_cache_size() {
        let provider = CachedBlockchainProvider::new();
        assert_eq!(provider.cache_size(), 0);
        
        provider.add_block(1, vec![], [0u8; 32], vec![]);
        provider.add_block(2, vec![], [0u8; 32], vec![]);
        
        assert_eq!(provider.cache_size(), 2);
    }
    
    #[test]
    fn test_clear_cache() {
        let provider = CachedBlockchainProvider::new();
        provider.add_block(1, vec![], [0u8; 32], vec![]);
        assert_eq!(provider.cache_size(), 1);
        
        provider.clear_cache();
        assert_eq!(provider.cache_size(), 0);
    }
    
    #[test]
    fn test_rpc_config() {
        let config = RpcConfig::default();
        assert_eq!(config.endpoint, "http://localhost:8232");
        assert_eq!(config.timeout_secs, 30);
    }
    
    #[test]
    fn test_rpc_provider_creation() {
        let config = RpcConfig::default();
        let provider = RpcBlockchainProvider::new(config);
        assert!(provider.test_connection().is_ok());
    }
}

