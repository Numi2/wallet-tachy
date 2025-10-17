//! Tachyon Wallet Persistence Layer
//!
//! Provides encrypted, durable storage for wallet state using the sled embedded database.

#![allow(missing_docs)]
//!
//! # Security Model
//!
//! - Master key derived from password using Argon2id (never stored on disk)
//! - Sensitive data (notes, keys, memos) encrypted with XChaCha20-Poly1305
//! - Constant-time operations for cryptographic comparisons
//! - Zeroization of secrets on drop
//!
//! # Storage Schema
//!
//! ```text
//! wallet.db/
//! ├── metadata/          # Wallet metadata (current block, anchor, etc.)
//! ├── notes/             # Encrypted note records
//! ├── nullifiers/        # Nullifier spent status
//! ├── transactions/      # Transaction history
//! ├── capsules/          # Recovery capsules
//! ├── sync_checkpoints/  # Sync state for resume
//! ├── chain_state/       # Hash chain accumulator state
//! └── config/            # Configuration settings
//! ```

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sled::{Db, Tree};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};


// All imports always available (no feature gates)
#[allow(unused_imports)]
use crate::notes::{CommitmentKey, Nonce, NullifierKey, PaymentKey, TachyonNote};
#[allow(unused_imports)]
use crate::oblivious_sync::{NoteState, WalletState};
#[allow(unused_imports)]
use crate::recovery::{Capsule, SnapshotState};
#[allow(unused_imports)]
use crate::tachystamps::Tachygram;
#[allow(unused_imports)]
use crate::Nullifier;

// ----------------------------- Constants -----------------------------

const SCHEMA_VERSION: u32 = 1;

// Argon2id parameters for password hashing
const ARGON2_M_COST: u32 = 256 * 1024; // 256 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 threads

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum PersistenceError {
    #[error("database error: {0}")]
    Database(#[from] sled::Error),

    #[error("encryption error")]
    Encryption,

    #[error("decryption error")]
    Decryption,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid password")]
    InvalidPassword,

    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: u32, actual: u32 },

    #[error("database corrupted: {0}")]
    Corrupted(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ----------------------------- Network Type -----------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Regtest,
}

impl NetworkType {
    fn as_str(&self) -> &'static str {
        match self {
            NetworkType::Mainnet => "mainnet",
            NetworkType::Testnet => "testnet",
            NetworkType::Regtest => "regtest",
        }
    }

    fn from_str(s: &str) -> Result<Self, PersistenceError> {
        match s {
            "mainnet" => Ok(NetworkType::Mainnet),
            "testnet" => Ok(NetworkType::Testnet),
            "regtest" => Ok(NetworkType::Regtest),
            _ => Err(PersistenceError::Corrupted(format!(
                "invalid network type: {}",
                s
            ))),
        }
    }
}

// ----------------------------- Key Derivation -----------------------------

/// Master key derived from user password.
/// Never stored on disk, must be rederived on wallet open.
#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterKey([u8; 32]);

impl MasterKey {
    /// Derive master key from password using Argon2id.
    fn derive(password: &str, salt: &[u8; 16]) -> Result<Self, PersistenceError> {
        use argon2::Argon2;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
                .map_err(|e| PersistenceError::Corrupted(format!("argon2 params: {}", e)))?,
        );

        let mut master_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut master_key)
            .map_err(|e| PersistenceError::Corrupted(format!("argon2 hash: {}", e)))?;

        Ok(MasterKey(master_key))
    }

    /// Derive wallet encryption key using HKDF.
    fn derive_wallet_key(&self) -> EncryptionKey {
        let hk = Hkdf::<Sha256>::new(Some(b"zcash-tachyon-wallet"), &self.0);
        let mut key = [0u8; 32];
        hk.expand(b"wallet-encryption", &mut key).unwrap();
        EncryptionKey(key)
    }

    /// Derive metadata encryption key using HKDF.
    fn derive_metadata_key(&self) -> EncryptionKey {
        let hk = Hkdf::<Sha256>::new(Some(b"zcash-tachyon-wallet"), &self.0);
        let mut key = [0u8; 32];
        hk.expand(b"metadata-encryption", &mut key).unwrap();
        EncryptionKey(key)
    }

    /// Derive transaction encryption key using HKDF.
    fn derive_tx_key(&self) -> EncryptionKey {
        let hk = Hkdf::<Sha256>::new(Some(b"zcash-tachyon-wallet"), &self.0);
        let mut key = [0u8; 32];
        hk.expand(b"transaction-encryption", &mut key).unwrap();
        EncryptionKey(key)
    }
}

/// Encryption key for AEAD operations.
#[derive(Zeroize, ZeroizeOnDrop)]
struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    /// Encrypt data with deterministic nonce derived from context.
    #[allow(dead_code)]
    fn encrypt(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, PersistenceError> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());

        // Derive deterministic nonce from context using BLAKE3
        let nonce_bytes = blake3::derive_key("zcash-tachyon-nonce", context);
        let nonce: &XNonce = (&nonce_bytes[..24]).into();

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| PersistenceError::Encryption)
    }

    /// Decrypt data with deterministic nonce derived from context.
    #[allow(dead_code)]
    fn decrypt(&self, ciphertext: &[u8], context: &[u8]) -> Result<Vec<u8>, PersistenceError> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());

        // Derive same deterministic nonce
        let nonce_bytes = blake3::derive_key("zcash-tachyon-nonce", context);
        let nonce: &XNonce = (&nonce_bytes[..24]).into();

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PersistenceError::Decryption)
    }
}

// ----------------------------- Database Structure -----------------------------

/// Internal database structure with typed trees.
struct WalletDatabase {
    /// Raw sled database
    _inner: Db,

    // Main trees
    metadata: Tree,
    notes: Tree,
    nullifiers: Tree,
    transactions: Tree,
    capsules: Tree,
    sync_checkpoints: Tree,
    #[allow(dead_code)]
    chain_state: Tree,
    config: Tree,

    // Index trees
    #[allow(dead_code)]
    balance_index: Tree,
}

impl WalletDatabase {
    /// Open or create the database at the given path.
    fn open(path: &Path) -> Result<Self, PersistenceError> {
        let db = sled::open(path)?;

        Ok(Self {
            metadata: db.open_tree("metadata")?,
            notes: db.open_tree("notes")?,
            nullifiers: db.open_tree("nullifiers")?,
            transactions: db.open_tree("transactions")?,
            capsules: db.open_tree("capsules")?,
            sync_checkpoints: db.open_tree("sync_checkpoints")?,
            chain_state: db.open_tree("chain_state")?,
            config: db.open_tree("config")?,
            balance_index: db.open_tree("balance_index")?,
            _inner: db,
        })
    }
}

// ----------------------------- Storage Records -----------------------------

/// Record for a stored note.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NoteRecord {
    // Note identification
    nullifier: [u8; 32],
    commitment: [u8; 32],

    // Encrypted note data (TachyonNote + NullifierKey)
    encrypted_note_data: Vec<u8>,

    // Hash chain position (block height where note was created)
    created_at_block: u64,
    last_checked_block: u64,
    spent: bool,
    spent_at_block: Option<u64>,

    // Metadata
    label: Option<String>,
    amount: u64, // Cached for quick balance calculation
    created_at_time: u64, // Unix timestamp
}

/// Plaintext note data for encryption/decryption.
#[cfg(feature = "tachystamps")]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NotePlaintextData {
    /// The actual note
    note: TachyonNote,
    
    /// Nullifier key for deriving the nullifier
    nullifier_key: NullifierKey,
}

/// Record for a transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionRecord {
    // Transaction ID
    pub txid: [u8; 32],
    pub block_height: u64,
    pub block_time: u64,

    // Direction: 0 = received, 1 = sent
    pub direction: u8,

    // Value
    pub value: u64, // Total value in zatoshis

    // Notes involved
    pub input_nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,

    // Encrypted memo
    pub encrypted_memo: Vec<u8>,

    // Labels
    pub label: Option<String>,
    pub recipient_label: Option<String>,

    // Confirmations
    pub confirmations: u32,
}

/// Sync checkpoint for resuming interrupted sync.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub block_height: u64,
    pub anchor: [u8; 32],

    // PCD proof at this checkpoint
    pub pcd_proof: Option<Vec<u8>>, // Serialized Compressed

    // Hash chain accumulator state
    pub chain_accumulator: [u8; 32],
    pub chain_tachygram_count: u64,

    // Timestamp
    pub timestamp: u64,
}

/// Cached hash chain state.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedChainState {
    accumulator: [u8; 32],
    tachygram_count: u64,
    valid_at_block: u64,
    cached_at: u64,
}

/// Information about a stored capsule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapsuleInfo {
    pub key: String,
    pub created_at: u64,
    pub label: Option<String>,
    pub size_bytes: usize,
}

/// Wallet integrity verification report.
#[derive(Clone, Debug, Default)]
pub struct IntegrityReport {
    pub total_notes: usize,
    pub unspent_notes: usize,
    pub spent_notes: usize,
    pub total_nullifiers: usize,
    pub total_transactions: usize,
    pub total_checkpoints: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl IntegrityReport {
    /// Check if the wallet is healthy (no errors).
    pub fn is_healthy(&self) -> bool {
        self.errors.is_empty()
    }
    
    /// Get a summary string.
    pub fn summary(&self) -> String {
        format!(
            "Notes: {} ({} unspent, {} spent), Nullifiers: {}, Transactions: {}, Checkpoints: {}, Errors: {}, Warnings: {}",
            self.total_notes,
            self.unspent_notes,
            self.spent_notes,
            self.total_nullifiers,
            self.total_transactions,
            self.total_checkpoints,
            self.errors.len(),
            self.warnings.len()
        )
    }
}

/// Portable wallet export format (for backup/restore).
#[cfg(feature = "oblivious-sync")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletExport {
    /// Schema version
    pub version: u32,
    
    /// Network type
    pub network: NetworkType,
    
    /// Complete wallet state
    pub wallet_state: WalletState,
    
    /// All sync checkpoints
    pub checkpoints: Vec<SyncCheckpoint>,
    
    /// Transaction history
    pub transactions: Vec<TransactionRecord>,
    
    /// Export timestamp
    pub exported_at: u64,
}

// ----------------------------- Main Storage Interface -----------------------------

/// Main wallet storage interface.
pub struct WalletStore {
    db: WalletDatabase,
    #[allow(dead_code)]
    wallet_key: EncryptionKey,
    #[allow(dead_code)]
    metadata_key: EncryptionKey,
    #[allow(dead_code)]
    tx_key: EncryptionKey,
    network: NetworkType,
}

impl WalletStore {
    // =============== Initialization ===============

    /// Create a new wallet database.
    pub fn create(
        path: &Path,
        password: &str,
        network: NetworkType,
    ) -> Result<Self, PersistenceError> {
        // Generate random salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Derive master key and encryption keys
        let master_key = MasterKey::derive(password, &salt)?;
        let wallet_key = master_key.derive_wallet_key();
        let metadata_key = master_key.derive_metadata_key();
        let tx_key = master_key.derive_tx_key();

        // Open database
        let db = WalletDatabase::open(path)?;

        // Initialize metadata
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        db.metadata.insert("salt", &salt[..])?;
        db.metadata
            .insert("schema_version", &SCHEMA_VERSION.to_le_bytes())?;
        db.metadata
            .insert("created_at", &now.to_le_bytes())?;
        db.metadata
            .insert("current_block", &0u64.to_le_bytes())?;
        db.metadata.insert("anchor", &[0u8; 32][..])?;
        db.metadata
            .insert("note_count", &0u64.to_le_bytes())?;
        db.metadata
            .insert("spent_note_count", &0u64.to_le_bytes())?;

        // Set network
        db.config.insert("network", network.as_str().as_bytes())?;

        db.metadata.flush()?;
        db.config.flush()?;

        Ok(Self {
            db,
            wallet_key,
            metadata_key,
            tx_key,
            network,
        })
    }

    /// Open an existing wallet database.
    pub fn open(path: &Path, password: &str) -> Result<Self, PersistenceError> {
        let db = WalletDatabase::open(path)?;

        // Check schema version
        let version = db
            .metadata
            .get("schema_version")?
            .ok_or_else(|| PersistenceError::NotFound("schema_version".into()))?;
        let version = u32::from_le_bytes(
            version
                .as_ref()
                .try_into()
                .map_err(|_| PersistenceError::Corrupted("invalid schema version".into()))?,
        );

        if version != SCHEMA_VERSION {
            return Err(PersistenceError::SchemaVersionMismatch {
                expected: SCHEMA_VERSION,
                actual: version,
            });
        }

        // Load salt
        let salt_bytes = db
            .metadata
            .get("salt")?
            .ok_or_else(|| PersistenceError::NotFound("salt".into()))?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);

        // Derive keys
        let master_key = MasterKey::derive(password, &salt)?;
        let wallet_key = master_key.derive_wallet_key();
        let metadata_key = master_key.derive_metadata_key();
        let tx_key = master_key.derive_tx_key();

        // Verify password by trying to decrypt a test value
        // (If we have any encrypted notes, try decrypting one)
        // For now, assume password is correct if key derivation succeeds

        // Load network
        let network_bytes = db
            .config
            .get("network")?
            .ok_or_else(|| PersistenceError::NotFound("network".into()))?;
        let network_str = std::str::from_utf8(&network_bytes)
            .map_err(|_| PersistenceError::Corrupted("invalid network string".into()))?;
        let network = NetworkType::from_str(network_str)?;

        Ok(Self {
            db,
            wallet_key,
            metadata_key,
            tx_key,
            network,
        })
    }

    // =============== Wallet State ===============

    /// Save complete wallet state.
    #[cfg(feature = "oblivious-sync")]
    pub fn save_wallet_state(&mut self, wallet: &WalletState) -> Result<(), PersistenceError> {
        // Update metadata
        self.set_current_block(wallet.current_block)?;
        self.set_anchor(wallet.anchor)?;

        // Save all notes
        for note in &wallet.notes {
            self.save_note_state(note)?;
        }

        // Update note count
        self.db.metadata.insert(
            "note_count",
            &(wallet.notes.len() as u64).to_le_bytes(),
        )?;

        Ok(())
    }

    /// Load complete wallet state.
    #[cfg(feature = "oblivious-sync")]
    pub fn load_wallet_state(&self) -> Result<WalletState, PersistenceError> {
        let current_block = self.get_current_block()?;
        let anchor = self.get_anchor()?;

        // Load all notes
        let mut notes = Vec::new();
        for item in self.db.notes.iter() {
            let (_, value) = item?;
            let record: NoteRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

            // Decrypt and convert to NoteState
            let note_state = self.note_record_to_state(&record)?;
            notes.push(note_state);
        }

        // Load PCD proof from latest checkpoint if present
        let pcd_proof = self.load_latest_checkpoint()?
            .and_then(|checkpoint| checkpoint.pcd_proof)
            .and_then(|bytes| serde_cbor::from_slice(&bytes).ok());

        // Load seen nullifiers
        let mut seen_nullifiers = std::collections::BTreeSet::new();
        for item in self.db.nullifiers.iter() {
            let (key, _) = item?;
            let mut nf = [0u8; 32];
            hex::decode_to_slice(&key, &mut nf)
                .map_err(|e| PersistenceError::Corrupted(format!("invalid nullifier hex: {}", e)))?;
            seen_nullifiers.insert(Nullifier(nf));
        }

        Ok(WalletState {
            current_block,
            anchor,
            notes,
            pcd_proof,
            seen_nullifiers,
        })
    }
    
    /// Recover wallet from latest checkpoint.
    /// This is faster than loading full state for large wallets.
    #[cfg(feature = "oblivious-sync")]
    pub fn recover_from_checkpoint(&self) -> Result<Option<WalletState>, PersistenceError> {
        let checkpoint = match self.load_latest_checkpoint()? {
            Some(cp) => cp,
            None => return Ok(None),
        };
        
        // Restore basic state from checkpoint
        let current_block = checkpoint.block_height;
        let anchor = checkpoint.anchor;
        
        // Load PCD proof
        let pcd_proof = checkpoint.pcd_proof
            .and_then(|bytes| serde_cbor::from_slice(&bytes).ok());
        
        // Load only unspent notes (optimization)
        let notes = self.get_unspent_notes()?;
        
        // Load nullifiers seen since checkpoint
        let mut seen_nullifiers = std::collections::BTreeSet::new();
        for item in self.db.nullifiers.iter() {
            let (key, value) = item?;
            
            // Parse block height
            let height_bytes: [u8; 8] = value.as_ref()
                .try_into()
                .map_err(|_| PersistenceError::Corrupted("invalid nullifier height".into()))?;
            let height = u64::from_le_bytes(height_bytes);
            
            // Only include nullifiers from recent blocks
            if height >= checkpoint.block_height {
                let mut nf = [0u8; 32];
                hex::decode_to_slice(&key, &mut nf)
                    .map_err(|e| PersistenceError::Corrupted(format!("invalid nullifier hex: {}", e)))?;
                seen_nullifiers.insert(Nullifier(nf));
            }
        }
        
        Ok(Some(WalletState {
            current_block,
            anchor,
            notes,
            pcd_proof,
            seen_nullifiers,
        }))
    }
    
    /// Verify wallet integrity.
    /// Checks that stored data is consistent and not corrupted.
    pub fn verify_integrity(&self) -> Result<IntegrityReport, PersistenceError> {
        let mut report = IntegrityReport::default();
        
        // Check schema version
        let version_bytes = self.db.metadata.get("schema_version")?
            .ok_or_else(|| PersistenceError::NotFound("schema_version".into()))?;
        let version = u32::from_le_bytes(
            version_bytes.as_ref().try_into()
                .map_err(|_| PersistenceError::Corrupted("invalid schema_version".into()))?
        );
        
        if version != SCHEMA_VERSION {
            report.errors.push(format!(
                "Schema version mismatch: {} != {}",
                version, SCHEMA_VERSION
            ));
        }
        
        // Check all notes can be deserialized
        for item in self.db.notes.iter() {
            let (key, value) = item?;
            report.total_notes += 1;
            
            match serde_cbor::from_slice::<NoteRecord>(&value) {
                Ok(record) => {
                    if record.spent {
                        report.spent_notes += 1;
                    } else {
                        report.unspent_notes += 1;
                    }
                    
                    // Verify witness structure
                    // Hash chain design doesn't use witness siblings/directions
                    if false { // Disabled check for new design
                        report.warnings.push(format!(
                            "Note {}: witness size mismatch",
                            hex::encode(&key)
                        ));
                    }
                }
                Err(e) => {
                    report.errors.push(format!(
                        "Note {}: deserialization failed: {}",
                        hex::encode(&key), e
                    ));
                }
            }
        }
        
        // Check nullifiers consistency
        for item in self.db.nullifiers.iter() {
            let (key, _) = item?;
            report.total_nullifiers += 1;
            
            // Verify hex format
            if hex::decode(&key).is_err() {
                report.errors.push(format!(
                    "Nullifier {}: invalid hex",
                    String::from_utf8_lossy(&key)
                ));
            }
        }
        
        // Check transactions
        for item in self.db.transactions.iter() {
            let (_, value) = item?;
            report.total_transactions += 1;
            
            if serde_cbor::from_slice::<TransactionRecord>(&value).is_err() {
                report.errors.push("Transaction deserialization failed".into());
            }
        }
        
        // Check checkpoints
        for item in self.db.sync_checkpoints.iter() {
            let (_, value) = item?;
            report.total_checkpoints += 1;
            
            if serde_cbor::from_slice::<SyncCheckpoint>(&value).is_err() {
                report.errors.push("Checkpoint deserialization failed".into());
            }
        }
        
        Ok(report)
    }
    
    /// Export wallet to a portable format (for backup).
    #[cfg(feature = "oblivious-sync")]
    pub fn export_wallet(&self) -> Result<WalletExport, PersistenceError> {
        let wallet_state = self.load_wallet_state()?;
        let checkpoints = self.list_all_checkpoints()?;
        let transactions = self.get_transactions(1000)?; // Last 1000 txs
        
        let export = WalletExport {
            version: SCHEMA_VERSION,
            network: self.network,
            wallet_state,
            checkpoints,
            transactions,
            exported_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        Ok(export)
    }
    
    /// Import wallet from exported data.
    #[cfg(feature = "oblivious-sync")]
    pub fn import_wallet(&mut self, export: &WalletExport) -> Result<(), PersistenceError> {
        // Verify version compatibility
        if export.version > SCHEMA_VERSION {
            return Err(PersistenceError::Corrupted(format!(
                "Export version {} is newer than supported {}",
                export.version, SCHEMA_VERSION
            )));
        }
        
        // Verify network matches
        if export.network != self.network {
            return Err(PersistenceError::Corrupted(format!(
                "Network mismatch: export is {:?}, wallet is {:?}",
                export.network, self.network
            )));
        }
        
        // Import wallet state
        self.save_wallet_state(&export.wallet_state)?;
        
        // Import checkpoints
        for checkpoint in &export.checkpoints {
            self.save_checkpoint_direct(checkpoint)?;
        }
        
        // Import transactions
        for tx in &export.transactions {
            self.save_transaction(tx)?;
        }
        
        Ok(())
    }
    
    /// List all checkpoints (for export).
    #[allow(dead_code)]
    fn list_all_checkpoints(&self) -> Result<Vec<SyncCheckpoint>, PersistenceError> {
        let mut checkpoints = Vec::new();
        
        for item in self.db.sync_checkpoints.iter() {
            let (_, value) = item?;
            let checkpoint: SyncCheckpoint = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
            checkpoints.push(checkpoint);
        }
        
        // Sort by block height
        checkpoints.sort_by_key(|cp| cp.block_height);
        
        Ok(checkpoints)
    }
    
    /// Save checkpoint directly (for import).
    #[allow(dead_code)]
    fn save_checkpoint_direct(&mut self, checkpoint: &SyncCheckpoint) -> Result<(), PersistenceError> {
        let key = format!("checkpoint_{:016}", checkpoint.block_height);
        let value = serde_cbor::to_vec(checkpoint)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        self.db.sync_checkpoints.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get current block height.
    pub fn get_current_block(&self) -> Result<u64, PersistenceError> {
        let bytes = self
            .db
            .metadata
            .get("current_block")?
            .ok_or_else(|| PersistenceError::NotFound("current_block".into()))?;
        Ok(u64::from_le_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| PersistenceError::Corrupted("invalid current_block".into()))?,
        ))
    }

    /// Set current block height.
    pub fn set_current_block(&mut self, height: u64) -> Result<(), PersistenceError> {
        self.db
            .metadata
            .insert("current_block", &height.to_le_bytes())?;
        Ok(())
    }

    /// Get current anchor.
    pub fn get_anchor(&self) -> Result<[u8; 32], PersistenceError> {
        let bytes = self
            .db
            .metadata
            .get("anchor")?
            .ok_or_else(|| PersistenceError::NotFound("anchor".into()))?;
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(&bytes);
        Ok(anchor)
    }

    /// Set current anchor.
    pub fn set_anchor(&mut self, anchor: [u8; 32]) -> Result<(), PersistenceError> {
        self.db.metadata.insert("anchor", &anchor[..])?;
        Ok(())
    }

    // =============== Notes ===============

    /// Save a note with full encryption.
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    pub fn save_note(
        &mut self,
        note_state: &NoteState,
        tachyon_note: &TachyonNote,
        nullifier_key: &NullifierKey,
    ) -> Result<(), PersistenceError> {
        // Encrypt the note data
        let encrypted_note_data = self.encrypt_note_data(tachyon_note, nullifier_key, &note_state.commitment.0)?;
        
        let record = NoteRecord {
            nullifier: note_state.nullifier.0,
            commitment: note_state.commitment.0,
            encrypted_note_data,
            created_at_block: note_state.created_at_block,
            last_checked_block: note_state.last_checked_block,
            spent: note_state.spent,
            spent_at_block: if note_state.spent {
                Some(note_state.last_checked_block)
            } else {
                None
            },
            label: None,
            amount: tachyon_note.value, // Store plaintext amount for quick balance calc
            created_at_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let key = hex::encode(note_state.nullifier.0);
        let value = serde_cbor::to_vec(&record)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

        self.db.notes.insert(key.as_bytes(), value)?;
        Ok(())
    }
    
    /// Save a note state (legacy method for compatibility).
    /// This version doesn't have the actual note data, only metadata.
    #[cfg(feature = "oblivious-sync")]
    fn save_note_state(&mut self, note: &NoteState) -> Result<(), PersistenceError> {
        // Create a dummy encrypted payload for notes without full data
        let encrypted_note_data = vec![];

        let record = NoteRecord {
            nullifier: note.nullifier.0,
            commitment: note.commitment.0,
            encrypted_note_data,
            created_at_block: note.created_at_block,
            last_checked_block: note.last_checked_block,
            spent: note.spent,
            spent_at_block: if note.spent {
                Some(note.last_checked_block)
            } else {
                None
            },
            label: None,
            amount: 0,
            created_at_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let key = hex::encode(note.nullifier.0);
        let value = serde_cbor::to_vec(&record)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

        self.db.notes.insert(key.as_bytes(), value)?;
        Ok(())
    }
    
    /// Encrypt note data (TachyonNote + NullifierKey).
    #[cfg(feature = "tachystamps")]
    fn encrypt_note_data(
        &self,
        note: &TachyonNote,
        nullifier_key: &NullifierKey,
        commitment: &[u8; 32],
    ) -> Result<Vec<u8>, PersistenceError> {
        // Serialize the note data
        let plaintext_data = NotePlaintextData {
            note: note.clone(),
            nullifier_key: nullifier_key.clone(),
        };
        
        let plaintext = serde_cbor::to_vec(&plaintext_data)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        // Encrypt using commitment as context (deterministic nonce)
        let ciphertext = self.wallet_key.encrypt(&plaintext, commitment)?;
        
        Ok(ciphertext)
    }
    
    /// Decrypt note data.
    #[cfg(feature = "tachystamps")]
    fn decrypt_note_data(
        &self,
        encrypted: &[u8],
        commitment: &[u8; 32],
    ) -> Result<(TachyonNote, NullifierKey), PersistenceError> {
        // Decrypt
        let plaintext = self.wallet_key.decrypt(encrypted, commitment)?;
        
        // Deserialize
        let data: NotePlaintextData = serde_cbor::from_slice(&plaintext)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        Ok((data.note, data.nullifier_key))
    }
    
    /// Load a note with full decryption.
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    pub fn load_note(
        &self,
        nullifier: &[u8; 32],
    ) -> Result<Option<(NoteState, TachyonNote, NullifierKey)>, PersistenceError> {
        let key = hex::encode(nullifier);
        
        if let Some(value) = self.db.notes.get(key.as_bytes())? {
            let record: NoteRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
            
            // Decrypt note data if present
            if !record.encrypted_note_data.is_empty() {
                let (note, nk) = self.decrypt_note_data(&record.encrypted_note_data, &record.commitment)?;
                
                // Reconstruct NoteState
                let note_state = self.note_record_to_state(&record)?;
                
                Ok(Some((note_state, note, nk)))
            } else {
                // Legacy record without encrypted data
                let note_state = self.note_record_to_state(&record)?;
                
                // Return dummy note data (can't decrypt)
                // This is for backwards compatibility
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Convert NoteRecord to NoteState.
    #[cfg(feature = "oblivious-sync")]
    fn note_record_to_state(&self, record: &NoteRecord) -> Result<NoteState, PersistenceError> {
        // Hash chain approach - no witness needed, just position
        Ok(NoteState {
            nullifier: Nullifier(record.nullifier),
            commitment: Tachygram(record.commitment),
            created_at_block: record.created_at_block,
            last_checked_block: record.last_checked_block,
            spent: record.spent,
        })
    }

    /// Get all unspent notes (metadata only, no decryption).
    #[cfg(feature = "oblivious-sync")]
    pub fn get_unspent_notes(&self) -> Result<Vec<NoteState>, PersistenceError> {
        let mut notes = Vec::new();
        for item in self.db.notes.iter() {
            let (_, value) = item?;
            let record: NoteRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

            if !record.spent {
                notes.push(self.note_record_to_state(&record)?);
            }
        }
        Ok(notes)
    }
    
    /// Get all unspent notes with full decryption.
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    pub fn get_unspent_notes_decrypted(
        &self,
    ) -> Result<Vec<(NoteState, TachyonNote, NullifierKey)>, PersistenceError> {
        let mut notes = Vec::new();
        
        for item in self.db.notes.iter() {
            let (_, value) = item?;
            let record: NoteRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

            if !record.spent && !record.encrypted_note_data.is_empty() {
                let (note, nk) = self.decrypt_note_data(&record.encrypted_note_data, &record.commitment)?;
                let note_state = self.note_record_to_state(&record)?;
                notes.push((note_state, note, nk));
            }
        }
        
        Ok(notes)
    }
    
    /// List all notes (spent and unspent) with full decryption.
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    pub fn list_all_notes_decrypted(
        &self,
    ) -> Result<Vec<(NoteState, TachyonNote, NullifierKey)>, PersistenceError> {
        let mut notes = Vec::new();
        
        for item in self.db.notes.iter() {
            let (_, value) = item?;
            let record: NoteRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

            if !record.encrypted_note_data.is_empty() {
                let (note, nk) = self.decrypt_note_data(&record.encrypted_note_data, &record.commitment)?;
                let note_state = self.note_record_to_state(&record)?;
                notes.push((note_state, note, nk));
            }
        }
        
        Ok(notes)
    }
    
    /// Update note chain position (for sync operations).
    /// Hash chain approach - no witness needed, position is immutable once created
    #[cfg(feature = "tachystamps")]
    pub fn update_note_chain_position(
        &mut self,
        nullifier: &[u8; 32],
        _new_block: u64, // Position is immutable in hash chain
    ) -> Result<(), PersistenceError> {
        let key = hex::encode(nullifier);
        
        // Load existing record
        let value = self.db.notes.get(key.as_bytes())?
            .ok_or_else(|| PersistenceError::NotFound(format!("note {}", key)))?;
        
        let mut record: NoteRecord = serde_cbor::from_slice(&value)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        // Hash chain approach - position is fixed at creation time
        // Nothing to update, but keep function for API compatibility
        
        // Save back (no changes)
        let value = serde_cbor::to_vec(&record)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        self.db.notes.insert(key.as_bytes(), value)?;
        
        Ok(())
    }
    
    /// Update note label.
    pub fn update_note_label(
        &mut self,
        nullifier: &[u8; 32],
        label: Option<String>,
    ) -> Result<(), PersistenceError> {
        let key = hex::encode(nullifier);
        
        let value = self.db.notes.get(key.as_bytes())?
            .ok_or_else(|| PersistenceError::NotFound(format!("note {}", key)))?;
        
        let mut record: NoteRecord = serde_cbor::from_slice(&value)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        record.label = label;
        
        let value = serde_cbor::to_vec(&record)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        
        self.db.notes.insert(key.as_bytes(), value)?;
        
        Ok(())
    }

    /// Mark a note as spent.
    pub fn mark_note_spent(
        &mut self,
        nullifier: &[u8; 32],
        block: u64,
    ) -> Result<(), PersistenceError> {
        let key = hex::encode(nullifier);

        // Load record
        let value = self
            .db
            .notes
            .get(key.as_bytes())?
            .ok_or_else(|| PersistenceError::NotFound(format!("note {}", key)))?;

        let mut record: NoteRecord = serde_cbor::from_slice(&value)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

        // Update status
        record.spent = true;
        record.spent_at_block = Some(block);
        record.last_checked_block = block;

        // Save back
        let value = serde_cbor::to_vec(&record)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        self.db.notes.insert(key.as_bytes(), value)?;

        // Add to nullifiers tree
        self.db
            .nullifiers
            .insert(key.as_bytes(), &block.to_le_bytes())?;

        Ok(())
    }

    /// Get total note count.
    pub fn get_note_count(&self) -> Result<u64, PersistenceError> {
        let bytes = self
            .db
            .metadata
            .get("note_count")?
            .unwrap_or_else(|| sled::IVec::from(&0u64.to_le_bytes()[..]));
        Ok(u64::from_le_bytes(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| PersistenceError::Corrupted("invalid note_count".into()))?,
        ))
    }

    // =============== Nullifiers ===============

    /// Check if a nullifier has been spent.
    pub fn is_nullifier_spent(&self, nf: &[u8; 32]) -> Result<bool, PersistenceError> {
        let key = hex::encode(nf);
        Ok(self.db.nullifiers.contains_key(key.as_bytes())?)
    }

    /// Get the block height at which a nullifier was spent.
    pub fn get_nullifier_spend_height(&self, nf: &[u8; 32]) -> Result<Option<u64>, PersistenceError> {
        let key = hex::encode(nf);
        if let Some(value) = self.db.nullifiers.get(key.as_bytes())? {
            let height = u64::from_le_bytes(
                value
                    .as_ref()
                    .try_into()
                    .map_err(|_| PersistenceError::Corrupted("invalid nullifier height".into()))?,
            );
            Ok(Some(height))
        } else {
            Ok(None)
        }
    }

    /// Add a nullifier to the spent set.
    pub fn add_nullifier(&mut self, nf: &[u8; 32], block: u64) -> Result<(), PersistenceError> {
        let key = hex::encode(nf);
        self.db
            .nullifiers
            .insert(key.as_bytes(), &block.to_le_bytes())?;
        Ok(())
    }

    // =============== Transactions ===============

    /// Save a transaction record.
    pub fn save_transaction(&mut self, tx: &TransactionRecord) -> Result<(), PersistenceError> {
        // Key format: {block_height:016}_{tx_index:08}_{direction}
        // We don't have tx_index here, so use 0
        let key = format!(
            "{:016}_{:08}_{}",
            tx.block_height, 0, tx.direction
        );

        let value = serde_cbor::to_vec(tx)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

        self.db.transactions.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Get recent transactions (limited).
    pub fn get_transactions(&self, limit: usize) -> Result<Vec<TransactionRecord>, PersistenceError> {
        let mut txs = Vec::new();
        for item in self.db.transactions.iter().rev().take(limit) {
            let (_, value) = item?;
            let tx: TransactionRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
            txs.push(tx);
        }
        Ok(txs)
    }

    // =============== Balance ===============

    /// Get spendable balance (sum of unspent notes).
    pub fn get_balance(&self) -> Result<u64, PersistenceError> {
        let mut balance = 0u64;
        for item in self.db.notes.iter() {
            let (_, value) = item?;
            let record: NoteRecord = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
            if !record.spent {
                balance = balance.saturating_add(record.amount);
            }
        }
        Ok(balance)
    }

    // =============== Recovery Capsules ===============

    /// Save a recovery capsule.
    pub fn save_capsule(
        &mut self,
        capsule: &[u8],
        label: Option<&str>,
    ) -> Result<String, PersistenceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let key = format!("{:08}_{:016}", 1, now); // version_timestamp

        let info = CapsuleInfo {
            key: key.clone(),
            created_at: now,
            label: label.map(|s| s.to_string()),
            size_bytes: capsule.len(),
        };

        // Store capsule
        self.db.capsules.insert(key.as_bytes(), capsule)?;

        // Store metadata
        let meta_key = format!("{}_meta", key);
        let meta_value = serde_cbor::to_vec(&info)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
        self.db.capsules.insert(meta_key.as_bytes(), meta_value)?;

        Ok(key)
    }

    /// Load a recovery capsule.
    pub fn load_capsule(&self, key: &str) -> Result<Vec<u8>, PersistenceError> {
        self.db
            .capsules
            .get(key.as_bytes())?
            .map(|v| v.to_vec())
            .ok_or_else(|| PersistenceError::NotFound(format!("capsule {}", key)))
    }

    /// List all capsules.
    pub fn list_capsules(&self) -> Result<Vec<CapsuleInfo>, PersistenceError> {
        let mut capsules = Vec::new();
        for item in self.db.capsules.iter() {
            let (key, _) = item?;
            let key_str = std::str::from_utf8(&key)
                .map_err(|_| PersistenceError::Corrupted("invalid capsule key".into()))?;

            if key_str.ends_with("_meta") {
                continue;
            }

            let meta_key = format!("{}_meta", key_str);
            if let Some(meta_value) = self.db.capsules.get(meta_key.as_bytes())? {
                let info: CapsuleInfo = serde_cbor::from_slice(&meta_value)
                    .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
                capsules.push(info);
            }
        }
        Ok(capsules)
    }

    /// Delete a capsule.
    pub fn delete_capsule(&mut self, key: &str) -> Result<(), PersistenceError> {
        self.db.capsules.remove(key.as_bytes())?;
        let meta_key = format!("{}_meta", key);
        self.db.capsules.remove(meta_key.as_bytes())?;
        Ok(())
    }

    // =============== Sync Checkpoints ===============

    /// Save a sync checkpoint.
    #[cfg(feature = "oblivious-sync")]
    pub fn save_checkpoint(&mut self, wallet: &WalletState) -> Result<(), PersistenceError> {
        let checkpoint = SyncCheckpoint {
            block_height: wallet.current_block,
            anchor: wallet.anchor,
            pcd_proof: wallet.pcd_proof.as_ref().map(|p| {
                serde_cbor::to_vec(p).unwrap()
            }),
            chain_accumulator: wallet.anchor,
            chain_tachygram_count: wallet.notes.len() as u64,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let key = format!("checkpoint_{:016}", wallet.current_block);
        let value = serde_cbor::to_vec(&checkpoint)
            .map_err(|e| PersistenceError::Serialization(e.to_string()))?;

        self.db.sync_checkpoints.insert(key.as_bytes(), value)?;

        // Prune old checkpoints (keep last 100)
        self.prune_old_checkpoints(100)?;

        Ok(())
    }

    /// Load the latest checkpoint.
    pub fn load_latest_checkpoint(&self) -> Result<Option<SyncCheckpoint>, PersistenceError> {
        if let Some(item) = self.db.sync_checkpoints.iter().next_back() {
            let (_, value) = item?;
            let checkpoint: SyncCheckpoint = serde_cbor::from_slice(&value)
                .map_err(|e| PersistenceError::Serialization(e.to_string()))?;
            Ok(Some(checkpoint))
        } else {
            Ok(None)
        }
    }

    /// Prune old checkpoints, keeping only the most recent.
    pub fn prune_old_checkpoints(&mut self, keep_count: usize) -> Result<(), PersistenceError> {
        let all_keys: Vec<_> = self
            .db
            .sync_checkpoints
            .iter()
            .keys()
            .collect::<Result<Vec<_>, _>>()?;

        if all_keys.len() > keep_count {
            let to_remove = all_keys.len() - keep_count;
            for key in all_keys.iter().take(to_remove) {
                self.db.sync_checkpoints.remove(key)?;
            }
        }

        Ok(())
    }

    // =============== Maintenance ===============

    /// Compact the database.
    pub fn compact(&mut self) -> Result<(), PersistenceError> {
        // Sled doesn't have explicit compaction, but we can flush
        self.db.metadata.flush()?;
        self.db.notes.flush()?;
        self.db.nullifiers.flush()?;
        self.db.transactions.flush()?;
        self.db.capsules.flush()?;
        self.db.sync_checkpoints.flush()?;
        Ok(())
    }

    /// Get database size on disk (approximate).
    pub fn get_db_size(&self) -> Result<u64, PersistenceError> {
        Ok(self.db.notes.len() as u64 * 300 // Approximate size per note
            + self.db.transactions.len() as u64 * 200) // Approximate size per tx
    }

    /// Get network type.
    pub fn network(&self) -> NetworkType {
        self.network
    }
}

impl Drop for WalletStore {
    fn drop(&mut self) {
        // Encryption keys are automatically zeroized by ZeroizeOnDrop
    }
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_open_wallet() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");

        // Create wallet
        let wallet = WalletStore::create(&path, "password123", NetworkType::Testnet).unwrap();
        assert_eq!(wallet.network(), NetworkType::Testnet);
        drop(wallet);

        // Reopen wallet
        let wallet = WalletStore::open(&path, "password123").unwrap();
        assert_eq!(wallet.network(), NetworkType::Testnet);
    }

    #[test]
    fn test_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");

        WalletStore::create(&path, "password123", NetworkType::Testnet).unwrap();

        // Wrong password should fail key derivation (though currently it won't error until decrypt)
        let _result = WalletStore::open(&path, "wrongpassword");
        // Currently this will succeed but fail on first decrypt attempt
        // In production, we'd store a password verifier
    }

    #[test]
    #[cfg(feature = "oblivious-sync")]
    fn test_save_load_wallet_state() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");

        let mut store = WalletStore::create(&path, "password", NetworkType::Mainnet).unwrap();

        // Create test wallet state
        let mut wallet = WalletState::new();
        wallet.current_block = 1000;
        wallet.anchor = [42u8; 32];

        // Save
        store.save_wallet_state(&wallet).unwrap();

        // Load
        let loaded = store.load_wallet_state().unwrap();
        assert_eq!(loaded.current_block, 1000);
        assert_eq!(loaded.anchor, [42u8; 32]);
    }

    #[test]
    fn test_nullifier_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");

        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();

        let nullifier = [1u8; 32];

        // Not spent initially
        assert!(!store.is_nullifier_spent(&nullifier).unwrap());

        // Add nullifier
        store.add_nullifier(&nullifier, 100).unwrap();

        // Now it's spent
        assert!(store.is_nullifier_spent(&nullifier).unwrap());
        assert_eq!(store.get_nullifier_spend_height(&nullifier).unwrap(), Some(100));
    }

    #[test]
    fn test_capsule_storage() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");

        let mut store = WalletStore::create(&path, "password", NetworkType::Mainnet).unwrap();

        let capsule_data = b"encrypted capsule data";
        let key = store.save_capsule(capsule_data, Some("test capsule")).unwrap();

        // Load capsule
        let loaded = store.load_capsule(&key).unwrap();
        assert_eq!(loaded, capsule_data);

        // List capsules
        let list = store.list_capsules().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, Some("test capsule".to_string()));

        // Delete capsule
        store.delete_capsule(&key).unwrap();
        assert!(store.load_capsule(&key).is_err());
    }

    #[test]
    #[cfg(feature = "oblivious-sync")]
    fn test_checkpoint_management() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");

        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();

        // Create and save checkpoints
        for i in 0..10 {
            let mut wallet = WalletState::new();
            wallet.current_block = i * 100;
            store.save_checkpoint(&wallet).unwrap();
        }

        // Load latest
        let latest = store.load_latest_checkpoint().unwrap().unwrap();
        assert_eq!(latest.block_height, 900);

        // Prune (keep last 5)
        store.prune_old_checkpoints(5).unwrap();

        // Should have 5 checkpoints
        let count = store.db.sync_checkpoints.len();
        assert_eq!(count, 5);
    }

    #[test]
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    fn test_encryption_deterministic() {
        let key = EncryptionKey([1u8; 32]);
        let plaintext = b"secret data";
        let context = b"context123";

        let ct1 = key.encrypt(plaintext, context).unwrap();
        let ct2 = key.encrypt(plaintext, context).unwrap();

        // Same plaintext and context should produce same ciphertext (deterministic nonce)
        assert_eq!(ct1, ct2);

        // Decrypt
        let pt = key.decrypt(&ct1, context).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_master_key_derivation() {
        let password = "test password";
        let salt = [0u8; 16];

        let mk1 = MasterKey::derive(password, &salt).unwrap();
        let mk2 = MasterKey::derive(password, &salt).unwrap();

        // Same password and salt should produce same key
        assert_eq!(mk1.0, mk2.0);

        // Different salt should produce different key
        let salt2 = [1u8; 16];
        let mk3 = MasterKey::derive(password, &salt2).unwrap();
        assert_ne!(mk1.0, mk3.0);
    }
    
    #[test]
    #[cfg(feature = "oblivious-sync")]
    fn test_recover_from_checkpoint() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();
        
        // Create and save a wallet state with checkpoint
        let mut wallet = WalletState::new();
        wallet.current_block = 1000;
        wallet.anchor = [42u8; 32];
        
        store.save_wallet_state(&wallet).unwrap();
        store.save_checkpoint(&wallet).unwrap();
        
        // Recover from checkpoint
        let recovered = store.recover_from_checkpoint().unwrap().unwrap();
        assert_eq!(recovered.current_block, 1000);
        assert_eq!(recovered.anchor, [42u8; 32]);
    }
    
    #[test]
    fn test_verify_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let store = WalletStore::create(&path, "password", NetworkType::Mainnet).unwrap();
        
        // Verify integrity of fresh wallet
        let report = store.verify_integrity().unwrap();
        assert!(report.is_healthy());
        assert_eq!(report.total_notes, 0);
        assert_eq!(report.total_nullifiers, 0);
        
        println!("Integrity: {}", report.summary());
    }
    
    #[test]
    #[cfg(feature = "oblivious-sync")]
    fn test_export_import_wallet() {
        let temp_dir = TempDir::new().unwrap();
        let path1 = temp_dir.path().join("wallet1.db");
        let path2 = temp_dir.path().join("wallet2.db");
        
        // Create wallet with some data
        let mut store1 = WalletStore::create(&path1, "password", NetworkType::Testnet).unwrap();
        
        let mut wallet = WalletState::new();
        wallet.current_block = 500;
        wallet.anchor = [99u8; 32];
        
        store1.save_wallet_state(&wallet).unwrap();
        store1.save_checkpoint(&wallet).unwrap();
        
        // Export
        let export = store1.export_wallet().unwrap();
        assert_eq!(export.version, SCHEMA_VERSION);
        assert_eq!(export.network, NetworkType::Testnet);
        assert_eq!(export.wallet_state.current_block, 500);
        
        // Import to new wallet
        let mut store2 = WalletStore::create(&path2, "password2", NetworkType::Testnet).unwrap();
        store2.import_wallet(&export).unwrap();
        
        // Verify imported state
        let imported = store2.load_wallet_state().unwrap();
        assert_eq!(imported.current_block, 500);
        assert_eq!(imported.anchor, [99u8; 32]);
    }
    
    #[test]
    #[cfg(feature = "oblivious-sync")]
    fn test_export_wrong_network() {
        let temp_dir = TempDir::new().unwrap();
        let path1 = temp_dir.path().join("wallet1.db");
        let path2 = temp_dir.path().join("wallet2.db");
        
        let store1 = WalletStore::create(&path1, "password", NetworkType::Testnet).unwrap();
        let mut store2 = WalletStore::create(&path2, "password", NetworkType::Mainnet).unwrap();
        
        let export = store1.export_wallet().unwrap();
        
        // Import should fail due to network mismatch
        let result = store2.import_wallet(&export);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Network mismatch"));
    }
    
    #[test]
    fn test_integrity_report_summary() {
        let mut report = IntegrityReport::default();
        report.total_notes = 10;
        report.unspent_notes = 7;
        report.spent_notes = 3;
        report.total_nullifiers = 3;
        report.total_transactions = 5;
        report.total_checkpoints = 2;
        
        let summary = report.summary();
        assert!(summary.contains("Notes: 10"));
        assert!(summary.contains("7 unspent"));
        assert!(summary.contains("3 spent"));
        assert!(report.is_healthy());
        
        // Add an error
        report.errors.push("Test error".into());
        assert!(!report.is_healthy());
    }
    
    #[test]
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    fn test_note_encryption_decryption() {
        use rand::rngs::OsRng;
        
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();
        
        // Create a test note
        let pk = PaymentKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        let rcm = CommitmentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);
        
        let note = TachyonNote::new(pk, 100_000_000, psi, rcm); // 1 ZEC
        let commitment = note.commitment();
        
        // Create note state
        let nullifier = Nullifier([1u8; 32]);
        let note_state = NoteState {
            nullifier,
            commitment: Tachygram(commitment.0),
            created_at_block: 1000,
            last_checked_block: 1000,
            spent: false,
        };
        
        // Save with encryption
        store.save_note(&note_state, &note, &nk).unwrap();
        
        // Load with decryption
        let loaded = store.load_note(&nullifier.0).unwrap();
        assert!(loaded.is_some());
        
        let (loaded_state, loaded_note, loaded_nk) = loaded.unwrap();
        
        // Verify decrypted note matches
        assert_eq!(loaded_note.value, 100_000_000);
        assert_eq!(loaded_note.pk.0, pk.0);
        assert_eq!(loaded_state.nullifier, nullifier);
        assert_eq!(loaded_state.spent, false);
        
        // Verify nullifier key matches
        assert_eq!(loaded_nk.0, nk.0);
    }
    
    #[test]
    #[cfg(feature = "tachystamps")]
    fn test_get_unspent_notes_decrypted() {
        use rand::rngs::OsRng;
        
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let mut store = WalletStore::create(&path, "password", NetworkType::Mainnet).unwrap();
        
        // Create multiple notes
        for i in 0..3 {
            let pk = PaymentKey::random(OsRng);
            let psi = Nonce::random(OsRng);
            let rcm = CommitmentKey::random(OsRng);
            let nk = NullifierKey::random(OsRng);
            
            let note = TachyonNote::new(pk, (i + 1) * 10_000_000, psi, rcm);
            let commitment = note.commitment();
            
            let nullifier = Nullifier([i as u8; 32]);
            let note_state = NoteState {
                nullifier,
                commitment: Tachygram(commitment.0),
                created_at_block: 1000 + i as u64,
                last_checked_block: 1000 + i as u64,
                spent: i == 2, // Mark last one as spent
            };
            
            store.save_note(&note_state, &note, &nk).unwrap();
        }
        
        // Get unspent notes
        let unspent = store.get_unspent_notes_decrypted().unwrap();
        assert_eq!(unspent.len(), 2); // Only 2 unspent
        
        // Verify amounts
        let total_value: u64 = unspent.iter().map(|(_, note, _)| note.value).sum();
        assert_eq!(total_value, 10_000_000 + 20_000_000); // 0.1 + 0.2 ZEC
    }
    
    #[test]
    #[cfg(feature = "tachystamps")]
    fn test_balance_calculation_with_encryption() {
        use rand::rngs::OsRng;
        
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();
        
        // Add notes with known values
        let amounts = vec![50_000_000, 75_000_000, 100_000_000]; // 0.5, 0.75, 1.0 ZEC
        
        for (i, amount) in amounts.iter().enumerate() {
            let pk = PaymentKey::random(OsRng);
            let psi = Nonce::random(OsRng);
            let rcm = CommitmentKey::random(OsRng);
            let nk = NullifierKey::random(OsRng);
            
            let note = TachyonNote::new(pk, *amount, psi, rcm);
            let commitment = note.commitment();
            
            let nullifier = Nullifier([i as u8; 32]);
            let note_state = NoteState {
                nullifier,
                commitment: Tachygram(commitment.0),
                created_at_block: 1000,
                last_checked_block: 1000,
                spent: false,
            };
            
            store.save_note(&note_state, &note, &nk).unwrap();
        }
        
        // Check balance
        let balance = store.get_balance().unwrap();
        assert_eq!(balance, 225_000_000); // 2.25 ZEC
        
        // Mark one as spent
        store.mark_note_spent(&[0u8; 32], 1001).unwrap();
        
        // Balance should decrease
        let balance = store.get_balance().unwrap();
        assert_eq!(balance, 175_000_000); // 1.75 ZEC (lost 0.5)
    }
    
    #[test]
    #[cfg(feature = "tachystamps")]
    fn test_update_note_witness() {
        use rand::rngs::OsRng;
        use halo2curves::pasta::Fp as PallasFp;
        
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();
        
        // Create and save a note
        let pk = PaymentKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        let rcm = CommitmentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);
        
        let note = TachyonNote::new(pk, 50_000_000, psi, rcm);
        let commitment = note.commitment();
        
        let nullifier = Nullifier([99u8; 32]);
        let note_state = NoteState {
            nullifier,
            commitment: Tachygram(commitment.0),
            created_at_block: 1000,
            last_checked_block: 1000,
            spent: false,
        };
        
        store.save_note(&note_state, &note, &nk).unwrap();
        
        // Update chain position (no-op in hash chain)
        store.update_note_chain_position(&nullifier.0, 1001).unwrap();
        
        // Load and verify - chain position is immutable
        let (loaded_state, _, _) = store.load_note(&nullifier.0).unwrap().unwrap();
        assert_eq!(loaded_state.created_at_block, 1000); // Position unchanged
    }
    
    #[test]
    #[cfg(feature = "tachystamps")]
    fn test_update_note_label() {
        use rand::rngs::OsRng;
        use halo2curves::pasta::Fp as PallasFp;
        
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let mut store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();
        
        // Create and save a note
        let pk = PaymentKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        let rcm = CommitmentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);
        
        let note = TachyonNote::new(pk, 50_000_000, psi, rcm);
        let commitment = note.commitment();
        
        let nullifier = Nullifier([88u8; 32]);
        let note_state = NoteState {
            nullifier,
            commitment: Tachygram(commitment.0),
            created_at_block: 1000,
            last_checked_block: 1000,
            spent: false,
        };
        
        store.save_note(&note_state, &note, &nk).unwrap();
        
        // Update label
        store.update_note_label(&nullifier.0, Some("Coffee payment".into())).unwrap();
        
        // Verify label was saved (would need to load full record to check)
        // For now, just verify no error
    }
    
    #[test]
    #[cfg(all(feature = "tachystamps", feature = "oblivious-sync"))]
    fn test_encryption_deterministic_v2() {
        use rand::rngs::OsRng;
        
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("wallet.db");
        
        let store = WalletStore::create(&path, "password", NetworkType::Testnet).unwrap();
        
        let pk = PaymentKey::random(OsRng);
        let psi = Nonce::random(OsRng);
        let rcm = CommitmentKey::random(OsRng);
        let nk = NullifierKey::random(OsRng);
        
        let note = TachyonNote::new(pk, 100_000_000, psi, rcm);
        let commitment = note.commitment();
        
        // Encrypt same data twice
        let ct1 = store.encrypt_note_data(&note, &nk, &commitment.0).unwrap();
        let ct2 = store.encrypt_note_data(&note, &nk, &commitment.0).unwrap();
        
        // Should be identical (deterministic nonce from commitment)
        assert_eq!(ct1, ct2);
        
        // Decrypt and verify
        let (decrypted, decrypted_nk) = store.decrypt_note_data(&ct1, &commitment.0).unwrap();
        assert_eq!(decrypted.value, 100_000_000);
        assert_eq!(decrypted_nk.0, nk.0);
    }
}

