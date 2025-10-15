use serde::{Deserialize, Serialize};
use sled::{Db, IVec};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StatusDbError {
    #[error("db error: {0}")] Db(String),
    #[error("serde error: {0}")] Ser(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentStatus {
    InProgress,
    Finalizing,
    Finalized,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboundPayment {
    pub uri: String,
    pub index: u32,
    pub txid: [u8; 32],
    pub status: PaymentStatus,
}

pub struct StatusDb {
    db: Db,
}

impl StatusDb {
    pub fn open(path: &str) -> Result<Self, StatusDbError> {
        let db = sled::open(path).map_err(|e| StatusDbError::Db(e.to_string()))?;
        Ok(Self { db })
    }

    pub fn put_outbound(&self, payment: &OutboundPayment) -> Result<(), StatusDbError> {
        let key = Self::key_for(payment.index);
        let val = serde_cbor::to_vec(payment).map_err(|e| StatusDbError::Ser(e.to_string()))?;
        self.db.insert(key, IVec::from(val)).map_err(|e| StatusDbError::Db(e.to_string()))?;
        self.db.flush().map_err(|e| StatusDbError::Db(e.to_string()))?;
        Ok(())
    }

    pub fn get_outbound(&self, index: u32) -> Result<Option<OutboundPayment>, StatusDbError> {
        let key = Self::key_for(index);
        let Some(bytes) = self.db.get(key).map_err(|e| StatusDbError::Db(e.to_string()))? else { return Ok(None) };
        let payment: OutboundPayment = serde_cbor::from_slice(&bytes).map_err(|e| StatusDbError::Ser(e.to_string()))?;
        Ok(Some(payment))
    }

    pub fn get_outbound_by_uri(&self, uri: &str) -> Result<Option<OutboundPayment>, StatusDbError> {
        for item in self.db.scan_prefix(b"outbound:") {
            let (_k, v) = item.map_err(|e| StatusDbError::Db(e.to_string()))?;
            if let Ok(p) = serde_cbor::from_slice::<OutboundPayment>(&v) {
                if p.uri == uri { return Ok(Some(p)); }
            }
        }
        Ok(None)
    }

    pub fn update_status(&self, index: u32, status: PaymentStatus) -> Result<(), StatusDbError> {
        if let Some(mut p) = self.get_outbound(index)? {
            p.status = status;
            self.put_outbound(&p)?;
        }
        Ok(())
    }

    pub fn list_outbound(&self) -> Result<Vec<OutboundPayment>, StatusDbError> {
        let mut out = Vec::new();
        for item in self.db.scan_prefix(b"outbound:") {
            let (_k, v) = item.map_err(|e| StatusDbError::Db(e.to_string()))?;
            if let Ok(p) = serde_cbor::from_slice::<OutboundPayment>(&v) { out.push(p); }
        }
        Ok(out)
    }

    fn key_for(index: u32) -> Vec<u8> { format!("outbound:{:010}", index).into_bytes() }

    pub fn next_payment_index(&self) -> Result<u32, StatusDbError> {
        let key = b"next_index";
        let idx = match self.db.get(key).map_err(|e| StatusDbError::Db(e.to_string()))? {
            Some(bytes) => {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes);
                u32::from_be_bytes(arr)
            }
            None => 0,
        };
        let next = idx.checked_add(1).ok_or_else(|| StatusDbError::Db("index overflow".into()))?;
        self.db.insert(key, IVec::from(next.to_be_bytes().to_vec())).map_err(|e| StatusDbError::Db(e.to_string()))?;
        self.db.flush().map_err(|e| StatusDbError::Db(e.to_string()))?;
        Ok(idx)
    }
}


