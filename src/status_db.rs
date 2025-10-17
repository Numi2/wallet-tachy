//! Status Database for ZIP-324 Payment Tracking
//!
//! This module provides persistent storage for ZIP-324 payment capability URIs
//! and their status. It enables:

#![allow(missing_docs)]
//! - Tracking outbound payments (sender side)
//! - Tracking inbound payments (recipient side)
//! - Recovery scanning with gap limits
//! - Payment index management
//!
//! # Payment Flow (Sender)
//!
//! 1. `sender_create_capability()` creates a payment URI with ephemeral key
//! 2. URI is shared with recipient (QR code, link, etc.)
//! 3. Status tracked as `InProgress` until recipient finalizes
//! 4. When finalized, status updates to `Finalized`
//!
//! # Payment Flow (Recipient)
//!
//! 1. `recipient_finalize_capability()` detects funded note
//! 2. Sweeps funds to main wallet
//! 3. Status updates to `Finalized`

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sled::{Db, Tree};
use std::path::Path;
use thiserror::Error;

// ----------------------------- Types -----------------------------

/// Status of a ZIP-324 payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// Payment capability created, waiting for recipient to claim
    InProgress,
    
    /// Recipient is finalizing the payment (sweeping funds)
    Finalizing,
    
    /// Payment completed successfully
    Finalized,
    
    /// Payment failed or expired
    Failed,
    
    /// Payment cancelled by sender
    Cancelled,
}

impl PaymentStatus {
    #[allow(dead_code)]
    fn as_str(&self) -> &'static str {
        match self {
            PaymentStatus::InProgress => "in_progress",
            PaymentStatus::Finalizing => "finalizing",
            PaymentStatus::Finalized => "finalized",
            PaymentStatus::Failed => "failed",
            PaymentStatus::Cancelled => "cancelled",
        }
    }

    #[allow(dead_code)]
    fn from_str(s: &str) -> Result<Self, StatusDbError> {
        match s {
            "in_progress" => Ok(PaymentStatus::InProgress),
            "finalizing" => Ok(PaymentStatus::Finalizing),
            "finalized" => Ok(PaymentStatus::Finalized),
            "failed" => Ok(PaymentStatus::Failed),
            "cancelled" => Ok(PaymentStatus::Cancelled),
            _ => Err(StatusDbError::Corrupted(format!("invalid payment status: {}", s))),
        }
    }
}

/// Record of an outbound payment (sender side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundPayment {
    /// The payment capability URI
    pub uri: String,
    
    /// Derivation index used for this payment
    pub index: u32,
    
    /// Transaction ID that funded the ephemeral key
    pub txid: [u8; 32],
    
    /// Current status
    pub status: PaymentStatus,
    
    /// Optional description
    pub description: Option<String>,
    
    /// Amount in zatoshis
    pub amount_zat: u64,
    
    /// Unix timestamp when created
    pub created_at: u64,
    
    /// Unix timestamp when last updated
    pub updated_at: u64,
}

/// Record of an inbound payment (recipient side).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundPayment {
    /// The payment capability URI we received
    pub uri: String,
    
    /// Transaction ID that swept the funds to our wallet
    pub sweep_txid: Option<[u8; 32]>,
    
    /// Current status
    pub status: PaymentStatus,
    
    /// Optional description
    pub description: Option<String>,
    
    /// Amount in zatoshis
    pub amount_zat: u64,
    
    /// Unix timestamp when received
    pub received_at: u64,
    
    /// Unix timestamp when finalized
    pub finalized_at: Option<u64>,
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum StatusDbError {
    #[error("database error: {0}")]
    Database(#[from] sled::Error),
    
    #[error("serialization error: {0}")]
    Serialization(String),
    
    #[error("not found: {0}")]
    NotFound(String),
    
    #[error("corrupted data: {0}")]
    Corrupted(String),
    
    #[error("index overflow")]
    IndexOverflow,
}

// ----------------------------- Database -----------------------------

/// Status database for ZIP-324 payments.
pub struct StatusDb {
    /// Raw sled database
    _db: Db,
    
    /// Tree for outbound payments (key: index)
    outbound: Tree,
    
    /// Tree for inbound payments (key: uri hash)
    inbound: Tree,
    
    /// Tree for URI to index mapping
    uri_index: Tree,
    
    /// Tree for metadata (next index, etc.)
    metadata: Tree,
}

impl StatusDb {
    /// Open or create a status database at the given path.
    pub fn open(path: &Path) -> Result<Self, StatusDbError> {
        let db = sled::open(path)?;
        
        Ok(Self {
            outbound: db.open_tree("outbound")?,
            inbound: db.open_tree("inbound")?,
            uri_index: db.open_tree("uri_index")?,
            metadata: db.open_tree("metadata")?,
            _db: db,
        })
    }
    
    // =============== Payment Index Management ===============
    
    /// Get the next unused payment index.
    pub fn next_payment_index(&self) -> Result<u32, StatusDbError> {
        let current = match self.metadata.get("next_index")? {
            Some(bytes) => {
                let array: [u8; 4] = bytes.as_ref().try_into()
                    .map_err(|_| StatusDbError::Corrupted("invalid next_index".into()))?;
                u32::from_le_bytes(array)
            }
            None => 0,
        };
        
        // Increment for next time
        let next = current.checked_add(1)
            .ok_or(StatusDbError::IndexOverflow)?;
        self.metadata.insert("next_index", &next.to_le_bytes())?;
        
        Ok(current)
    }
    
    /// Reset the payment index (use with caution).
    pub fn reset_payment_index(&self, index: u32) -> Result<(), StatusDbError> {
        self.metadata.insert("next_index", &index.to_le_bytes())?;
        Ok(())
    }
    
    // =============== Outbound Payments ===============
    
    /// Store an outbound payment record.
    pub fn put_outbound(&self, payment: &OutboundPayment) -> Result<(), StatusDbError> {
        // Store by index
        let key = payment.index.to_le_bytes();
        let value = serde_cbor::to_vec(payment)
            .map_err(|e| StatusDbError::Serialization(e.to_string()))?;
        
        self.outbound.insert(&key, value)?;
        
        // Index URI -> index for quick lookups
        let uri_key = blake3::hash(payment.uri.as_bytes());
        self.uri_index.insert(uri_key.as_bytes(), &key)?;
        
        Ok(())
    }
    
    /// Get an outbound payment by index.
    pub fn get_outbound(&self, index: u32) -> Result<Option<OutboundPayment>, StatusDbError> {
        let key = index.to_le_bytes();
        
        if let Some(value) = self.outbound.get(&key)? {
            let payment: OutboundPayment = serde_cbor::from_slice(&value)
                .map_err(|e| StatusDbError::Serialization(e.to_string()))?;
            Ok(Some(payment))
        } else {
            Ok(None)
        }
    }
    
    /// Get an outbound payment by URI.
    pub fn get_outbound_by_uri(&self, uri: &str) -> Result<Option<OutboundPayment>, StatusDbError> {
        let uri_key = blake3::hash(uri.as_bytes());
        
        if let Some(index_bytes) = self.uri_index.get(uri_key.as_bytes())? {
            let index = u32::from_le_bytes(
                index_bytes.as_ref().try_into()
                    .map_err(|_| StatusDbError::Corrupted("invalid index in uri_index".into()))?
            );
            
            self.get_outbound(index)
        } else {
            Ok(None)
        }
    }
    
    /// List all outbound payments.
    pub fn list_outbound(&self) -> Result<Vec<OutboundPayment>, StatusDbError> {
        let mut payments = Vec::new();
        
        for item in self.outbound.iter() {
            let (_, value) = item?;
            let payment: OutboundPayment = serde_cbor::from_slice(&value)
                .map_err(|e| StatusDbError::Serialization(e.to_string()))?;
            payments.push(payment);
        }
        
        // Sort by index
        payments.sort_by_key(|p| p.index);
        
        Ok(payments)
    }
    
    /// List outbound payments with a specific status.
    pub fn list_outbound_by_status(&self, status: PaymentStatus) -> Result<Vec<OutboundPayment>, StatusDbError> {
        Ok(self.list_outbound()?
            .into_iter()
            .filter(|p| p.status == status)
            .collect())
    }
    
    /// Update the status of an outbound payment.
    pub fn update_outbound_status(
        &self,
        index: u32,
        status: PaymentStatus,
    ) -> Result<(), StatusDbError> {
        let mut payment = self.get_outbound(index)?
            .ok_or_else(|| StatusDbError::NotFound(format!("outbound payment {}", index)))?;
        
        payment.status = status;
        payment.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.put_outbound(&payment)?;
        
        Ok(())
    }
    
    /// Delete an outbound payment.
    pub fn delete_outbound(&self, index: u32) -> Result<(), StatusDbError> {
        // Get payment first to clean up URI index
        if let Some(payment) = self.get_outbound(index)? {
            let uri_key = blake3::hash(payment.uri.as_bytes());
            self.uri_index.remove(uri_key.as_bytes())?;
        }
        
        let key = index.to_le_bytes();
        self.outbound.remove(&key)?;
        
        Ok(())
    }
    
    // =============== Inbound Payments ===============
    
    /// Store an inbound payment record.
    pub fn put_inbound(&self, payment: &InboundPayment) -> Result<(), StatusDbError> {
        // Use URI hash as key
        let key = blake3::hash(payment.uri.as_bytes());
        let value = serde_cbor::to_vec(payment)
            .map_err(|e| StatusDbError::Serialization(e.to_string()))?;
        
        self.inbound.insert(key.as_bytes(), value)?;
        
        Ok(())
    }
    
    /// Get an inbound payment by URI.
    pub fn get_inbound(&self, uri: &str) -> Result<Option<InboundPayment>, StatusDbError> {
        let key = blake3::hash(uri.as_bytes());
        
        if let Some(value) = self.inbound.get(key.as_bytes())? {
            let payment: InboundPayment = serde_cbor::from_slice(&value)
                .map_err(|e| StatusDbError::Serialization(e.to_string()))?;
            Ok(Some(payment))
        } else {
            Ok(None)
        }
    }
    
    /// List all inbound payments.
    pub fn list_inbound(&self) -> Result<Vec<InboundPayment>, StatusDbError> {
        let mut payments = Vec::new();
        
        for item in self.inbound.iter() {
            let (_, value) = item?;
            let payment: InboundPayment = serde_cbor::from_slice(&value)
                .map_err(|e| StatusDbError::Serialization(e.to_string()))?;
            payments.push(payment);
        }
        
        // Sort by received timestamp
        payments.sort_by_key(|p| p.received_at);
        
        Ok(payments)
    }
    
    /// List inbound payments with a specific status.
    pub fn list_inbound_by_status(&self, status: PaymentStatus) -> Result<Vec<InboundPayment>, StatusDbError> {
        Ok(self.list_inbound()?
            .into_iter()
            .filter(|p| p.status == status)
            .collect())
    }
    
    /// Update the status of an inbound payment.
    pub fn update_inbound_status(
        &self,
        uri: &str,
        status: PaymentStatus,
        sweep_txid: Option<[u8; 32]>,
    ) -> Result<(), StatusDbError> {
        let mut payment = self.get_inbound(uri)?
            .ok_or_else(|| StatusDbError::NotFound(format!("inbound payment {}", uri)))?;
        
        payment.status = status;
        if sweep_txid.is_some() {
            payment.sweep_txid = sweep_txid;
        }
        if status == PaymentStatus::Finalized {
            payment.finalized_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );
        }
        
        self.put_inbound(&payment)?;
        
        Ok(())
    }
    
    /// Delete an inbound payment.
    pub fn delete_inbound(&self, uri: &str) -> Result<(), StatusDbError> {
        let key = blake3::hash(uri.as_bytes());
        self.inbound.remove(key.as_bytes())?;
        Ok(())
    }
    
    // =============== Statistics ===============
    
    /// Get payment statistics.
    pub fn stats(&self) -> Result<PaymentStats, StatusDbError> {
        let outbound = self.list_outbound()?;
        let inbound = self.list_inbound()?;
        
        Ok(PaymentStats {
            total_outbound: outbound.len(),
            total_inbound: inbound.len(),
            outbound_in_progress: outbound.iter().filter(|p| p.status == PaymentStatus::InProgress).count(),
            outbound_finalized: outbound.iter().filter(|p| p.status == PaymentStatus::Finalized).count(),
            inbound_in_progress: inbound.iter().filter(|p| p.status == PaymentStatus::InProgress).count(),
            inbound_finalized: inbound.iter().filter(|p| p.status == PaymentStatus::Finalized).count(),
            next_index: self.metadata
                .get("next_index")?
                .map(|b| u32::from_le_bytes(b.as_ref().try_into().unwrap()))
                .unwrap_or(0),
        })
    }
    
    // =============== Maintenance ===============
    
    /// Flush all pending writes.
    pub fn flush(&self) -> Result<(), StatusDbError> {
        self.outbound.flush()?;
        self.inbound.flush()?;
        self.uri_index.flush()?;
        self.metadata.flush()?;
        Ok(())
    }
    
    /// Clear all data (use with caution).
    pub fn clear(&self) -> Result<(), StatusDbError> {
        self.outbound.clear()?;
        self.inbound.clear()?;
        self.uri_index.clear()?;
        self.metadata.clear()?;
        Ok(())
    }
}

/// Payment statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentStats {
    pub total_outbound: usize,
    pub total_inbound: usize,
    pub outbound_in_progress: usize,
    pub outbound_finalized: usize,
    pub inbound_in_progress: usize,
    pub inbound_finalized: usize,
    pub next_index: u32,
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_payment_index() {
        let temp_dir = TempDir::new().unwrap();
        let db = StatusDb::open(&temp_dir.path().join("status.db")).unwrap();
        
        assert_eq!(db.next_payment_index().unwrap(), 0);
        assert_eq!(db.next_payment_index().unwrap(), 1);
        assert_eq!(db.next_payment_index().unwrap(), 2);
        
        // Reset
        db.reset_payment_index(100).unwrap();
        assert_eq!(db.next_payment_index().unwrap(), 100);
    }
    
    #[test]
    fn test_outbound_payment() {
        let temp_dir = TempDir::new().unwrap();
        let db = StatusDb::open(&temp_dir.path().join("status.db")).unwrap();
        
        let payment = OutboundPayment {
            uri: "https://pay.withzcash.com:65536/payment/v1#amount=1.0&key=test".into(),
            index: 0,
            txid: [1u8; 32],
            status: PaymentStatus::InProgress,
            description: Some("Test payment".into()),
            amount_zat: 100_000_000,
            created_at: 1000,
            updated_at: 1000,
        };
        
        // Store
        db.put_outbound(&payment).unwrap();
        
        // Retrieve by index
        let retrieved = db.get_outbound(0).unwrap().unwrap();
        assert_eq!(retrieved, payment);
        
        // Retrieve by URI
        let retrieved = db.get_outbound_by_uri(&payment.uri).unwrap().unwrap();
        assert_eq!(retrieved, payment);
        
        // Update status
        db.update_outbound_status(0, PaymentStatus::Finalized).unwrap();
        let updated = db.get_outbound(0).unwrap().unwrap();
        assert_eq!(updated.status, PaymentStatus::Finalized);
    }
    
    #[test]
    fn test_inbound_payment() {
        let temp_dir = TempDir::new().unwrap();
        let db = StatusDb::open(&temp_dir.path().join("status.db")).unwrap();
        
        let payment = InboundPayment {
            uri: "https://pay.withzcash.com:65536/payment/v1#amount=1.0&key=test".into(),
            sweep_txid: None,
            status: PaymentStatus::InProgress,
            description: Some("Received payment".into()),
            amount_zat: 100_000_000,
            received_at: 1000,
            finalized_at: None,
        };
        
        // Store
        db.put_inbound(&payment).unwrap();
        
        // Retrieve
        let retrieved = db.get_inbound(&payment.uri).unwrap().unwrap();
        assert_eq!(retrieved, payment);
        
        // Update with sweep
        let sweep_txid = [2u8; 32];
        db.update_inbound_status(&payment.uri, PaymentStatus::Finalized, Some(sweep_txid)).unwrap();
        
        let updated = db.get_inbound(&payment.uri).unwrap().unwrap();
        assert_eq!(updated.status, PaymentStatus::Finalized);
        assert_eq!(updated.sweep_txid, Some(sweep_txid));
        assert!(updated.finalized_at.is_some());
    }
    
    #[test]
    fn test_list_by_status() {
        let temp_dir = TempDir::new().unwrap();
        let db = StatusDb::open(&temp_dir.path().join("status.db")).unwrap();
        
        // Add multiple payments
        for i in 0..5 {
            let status = if i < 2 {
                PaymentStatus::InProgress
            } else {
                PaymentStatus::Finalized
            };
            
            let payment = OutboundPayment {
                uri: format!("test://uri{}", i),
                index: i,
                txid: [i as u8; 32],
                status,
                description: None,
                amount_zat: 1000,
                created_at: 1000,
                updated_at: 1000,
            };
            
            db.put_outbound(&payment).unwrap();
        }
        
        // List by status
        let in_progress = db.list_outbound_by_status(PaymentStatus::InProgress).unwrap();
        assert_eq!(in_progress.len(), 2);
        
        let finalized = db.list_outbound_by_status(PaymentStatus::Finalized).unwrap();
        assert_eq!(finalized.len(), 3);
    }
    
    #[test]
    fn test_stats() {
        let temp_dir = TempDir::new().unwrap();
        let db = StatusDb::open(&temp_dir.path().join("status.db")).unwrap();
        
        // Add some payments
        for i in 0..3 {
            let outbound = OutboundPayment {
                uri: format!("test://out{}", i),
                index: i,
                txid: [i as u8; 32],
                status: if i == 0 { PaymentStatus::InProgress } else { PaymentStatus::Finalized },
                description: None,
                amount_zat: 1000,
                created_at: 1000,
                updated_at: 1000,
            };
            db.put_outbound(&outbound).unwrap();
            
            let inbound = InboundPayment {
                uri: format!("test://in{}", i),
                sweep_txid: None,
                status: PaymentStatus::InProgress,
                description: None,
                amount_zat: 1000,
                received_at: 1000,
                finalized_at: None,
            };
            db.put_inbound(&inbound).unwrap();
        }
        
        let stats = db.stats().unwrap();
        assert_eq!(stats.total_outbound, 3);
        assert_eq!(stats.total_inbound, 3);
        assert_eq!(stats.outbound_in_progress, 1);
        assert_eq!(stats.outbound_finalized, 2);
        assert_eq!(stats.inbound_in_progress, 3);
    }
    
    #[test]
    fn test_delete_payment() {
        let temp_dir = TempDir::new().unwrap();
        let db = StatusDb::open(&temp_dir.path().join("status.db")).unwrap();
        
        let payment = OutboundPayment {
            uri: "test://delete".into(),
            index: 0,
            txid: [1u8; 32],
            status: PaymentStatus::InProgress,
            description: None,
            amount_zat: 1000,
            created_at: 1000,
            updated_at: 1000,
        };
        
        db.put_outbound(&payment).unwrap();
        assert!(db.get_outbound(0).unwrap().is_some());
        
        db.delete_outbound(0).unwrap();
        assert!(db.get_outbound(0).unwrap().is_none());
        
        // URI index should also be cleaned up
        assert!(db.get_outbound_by_uri(&payment.uri).unwrap().is_none());
    }
}

