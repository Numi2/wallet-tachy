use crate::zip324::FinalizeEngine;
use serde_json::json;

pub trait SpendBuilder {
    fn coin_type(&self) -> u32;
    fn derive_esk_child(&self, coin_type: u32, idx: u32) -> Result<[u8; 32], String>;
    fn build_output_to_ephemeral(&self, key: &[u8; 32], amount_zat: u64) -> Result<Vec<u8>, String>; // raw tx bytes
    fn funded_note_exists(&self, key: &[u8; 32], expected_amount_zat: u64) -> Result<bool, String>;
    fn sweep_with_key_to_wallet(&self, key: &[u8; 32], amount_zat: u64) -> Result<Vec<u8>, String>; // raw tx bytes
}

pub struct ZebraRpcEngine<B: SpendBuilder> {
    pub builder: B,
    pub zebra_rpc_url: String,
    pub zebra_rpc_user: Option<String>,
    pub zebra_rpc_pass: Option<String>,
}

impl<B: SpendBuilder> ZebraRpcEngine<B> {
    fn rpc_post(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let mut u = ureq::post(&self.zebra_rpc_url);
        if let (Some(user), Some(pass)) = (&self.zebra_rpc_user, &self.zebra_rpc_pass) {
            u = u.set("Authorization", &format!("Basic {}", base64::encode(format!("{}:{}", user, pass))));
        }
        let res = u.send_json(req).map_err(|e| e.to_string())?;
        let val: serde_json::Value = res.into_json().map_err(|e| e.to_string())?;
        if val.get("error").and_then(|e| if e.is_null() { None } else { Some(e) }).is_some() {
            return Err(val.get("error").unwrap().to_string());
        }
        Ok(val.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    fn broadcast_raw_tx(&self, raw_tx: &[u8]) -> Result<[u8; 32], String> {
        let hex_tx = hex::encode(raw_tx);
        let res = self.rpc_post("sendrawtransaction", json!([hex_tx]))?;
        let txid_hex = res.as_str().ok_or("bad txid")?;
        let mut out = [0u8; 32];
        let bytes = hex::decode(txid_hex).map_err(|e| e.to_string())?;
        if bytes.len() != 32 { return Err("txid size".into()); }
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

impl<B: SpendBuilder> FinalizeEngine for ZebraRpcEngine<B> {
    fn coin_type(&self) -> u32 { self.builder.coin_type() }

    fn next_unused_payment_index(&self) -> Result<u32, String> {
        // Not used by our current sender (we use DB), but keep for compatibility
        Ok(0)
    }

    fn derive_esk_child(&self, coin_type: u32, idx: u32) -> Result<[u8; 32], String> {
        self.builder.derive_esk_child(coin_type, idx)
    }

    fn build_tx_output_to_ephemeral(&self, key: &[u8; 32], amount_zat: u64) -> Result<[u8; 32], String> {
        let raw = self.builder.build_output_to_ephemeral(key, amount_zat)?;
        self.broadcast_raw_tx(&raw)
    }

    fn note_exists_and_unspent(&self, key: &[u8; 32], expected_amount_zat: u64) -> Result<bool, String> {
        self.builder.funded_note_exists(key, expected_amount_zat)
    }

    fn sweep_with_key_to_wallet_addr(&self, key: &[u8; 32], amount_zat: u64) -> Result<[u8; 32], String> {
        let raw = self.builder.sweep_with_key_to_wallet(key, amount_zat)?;
        self.broadcast_raw_tx(&raw)
    }
}


