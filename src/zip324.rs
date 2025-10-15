use bech32::{self, ToBase32, Variant, FromBase32};
use blake2b_simd::Params as Blake2bParams;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use crate::status_db::{StatusDb, PaymentStatus, OutboundPayment};

#[derive(Debug, Error)]
pub enum Zip324Error {
    #[error("invalid uri")] InvalidUri,
    #[error("missing field")] MissingField,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentCapabilityUri {
    pub amount_zec: String,
    pub desc: Option<String>,
    pub key_bech32: String,
}

pub fn derive_payment_key(esk_child: &[u8]) -> [u8; 32] {
    // BLAKE2b-256 with personalization "Zcash_PaymentURI"
    let mut state = Blake2bParams::new()
        .hash_length(32)
        .personal(b"Zcash_PaymentURI")
        .to_state();
    state.update(esk_child);
    let hash = state.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn bech32_encode_key(hrp: &str, key: &[u8]) -> String {
    bech32::encode(hrp, key.to_base32(), Variant::Bech32).expect("bech32 encode")
}

pub fn build_capability_uri(amount_zec: &str, desc: Option<&str>, key_bech32: &str) -> String {
    let mut fragment_parts: Vec<String> = vec![format!("amount={}", amount_zec)];
    if let Some(d) = desc { fragment_parts.push(format!("desc={}", urlencoding::encode(d))); }
    fragment_parts.push(format!("key={}", key_bech32));
    format!("https://pay.withzcash.com:65536/payment/v1#{}", fragment_parts.join("&"))
}

pub fn parse_capability_uri(uri: &str) -> Result<PaymentCapabilityUri, Zip324Error> {
    let parsed = Url::parse(uri).map_err(|_| Zip324Error::InvalidUri)?;
    // Enforce centralized deployment constraints: https, host whitelisted, invalid port 65536
    if parsed.scheme() != "https" { return Err(Zip324Error::InvalidUri); }
    if parsed.host_str() != Some("pay.withzcash.com") { return Err(Zip324Error::InvalidUri); }
    if parsed.port_or_known_default() != Some(65536) { return Err(Zip324Error::InvalidUri); }
    if parsed.fragment().is_none() { return Err(Zip324Error::InvalidUri); }
    let frag = parsed.fragment().unwrap();
    let mut amount: Option<String> = None;
    let mut desc: Option<String> = None;
    let mut key: Option<String> = None;
    for kv in frag.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            match k {
                "amount" => amount = Some(v.to_string()),
                "desc" => desc = Some(urlencoding::decode(v).unwrap_or_default().to_string()),
                "key" => key = Some(v.to_string()),
                _ => {}
            }
        }
    }
    Ok(PaymentCapabilityUri {
        amount_zec: amount.ok_or(Zip324Error::MissingField)?,
        desc,
        key_bech32: key.ok_or(Zip324Error::MissingField)?,
    })
}

pub const DEFAULT_FEE_ZAT: u64 = 1000; // 0.00001 ZEC

pub trait FinalizeEngine {
    fn coin_type(&self) -> u32; // SLIP-44 coin type for ZEC mainnet/testnet
    fn next_unused_payment_index(&self) -> Result<u32, String>;
    fn derive_esk_child(&self, coin_type: u32, idx: u32) -> Result<[u8; 32], String>;
    fn build_tx_output_to_ephemeral(&self, key: &[u8; 32], amount_zat: u64) -> Result<[u8; 32], String>; // returns txid
    fn note_exists_and_unspent(&self, key: &[u8; 32], expected_amount_zat: u64) -> Result<bool, String>;
    fn sweep_with_key_to_wallet_addr(&self, key: &[u8; 32], amount_zat: u64) -> Result<[u8; 32], String>;
}

pub fn sender_create_capability<E: FinalizeEngine>(
    engine: &E,
    db: &StatusDb,
    amount_zat: u64,
    desc: Option<&str>,
    hrp: &str,
) -> Result<OutboundPayment, String> {
    let idx = db.next_payment_index().map_err(|e| e.to_string())?;
    let esk_child = engine.derive_esk_child(engine.coin_type(), idx)?;
    let key = derive_payment_key(&esk_child);
    let funded = amount_zat.checked_add(DEFAULT_FEE_ZAT).ok_or("amount overflow")?;
    let txid = engine.build_tx_output_to_ephemeral(&key, funded)?;
    let key_b32 = bech32_encode_key(hrp, &key);
    let uri = build_capability_uri(&format_zat(amount_zat), desc, &key_b32);
    let record = OutboundPayment { uri: uri.clone(), index: idx, txid, status: PaymentStatus::InProgress };
    db.put_outbound(&record).map_err(|e| e.to_string())?;
    Ok(record)
}

pub fn recipient_finalize_capability<E: FinalizeEngine>(
    engine: &E,
    db: &StatusDb,
    uri: &str,
    hrp: &str,
) -> Result<[u8; 32], String> {
    let cap = parse_capability_uri(uri).map_err(|e| e.to_string())?;
    if !cap.key_bech32.starts_with(hrp) { return Err("wrong HRP".into()); }
    let (_, data, _var) = bech32::decode(&cap.key_bech32).map_err(|e| e.to_string())?;
    let key_bytes: Vec<u8> = bech32::FromBase32::from_base32(&data).map_err(|e| format!("b32: {e}"))?;
    if key_bytes.len() != 32 { return Err("bad key size".into()); }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    let amount_zat = parse_zec_amount_to_zat(&cap.amount_zec).map_err(|e| e.to_string())?;
    let expected = amount_zat.checked_add(DEFAULT_FEE_ZAT).ok_or("overflow")?;
    if !engine.note_exists_and_unspent(&key, expected)? { return Err("funded note not found".into()); }
    let txid = engine.sweep_with_key_to_wallet_addr(&key, amount_zat)?;
    // Store/update status if present by index is unknown here; use synthetic index 0
    // Caller should correlate by uri if needed
    // Update best-effort
    if let Ok(Some(mut existing)) = db.get_outbound_by_uri(uri) { existing.status = PaymentStatus::Finalizing; let _ = db.put_outbound(&existing); }
    Ok(txid)
}

pub fn format_zat(zat: u64) -> String {
    // 8 decimal places
    let whole = zat / 100_000_000;
    let frac = zat % 100_000_000;
    if frac == 0 { whole.to_string() } else { format!("{}.{}", whole, format!("{:08}", frac).trim_end_matches('0')) }
}

pub fn parse_zec_amount_to_zat(s: &str) -> Result<u64, &'static str> {
    if s.is_empty() { return Err("empty"); }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 { return Err("bad decimal"); }
    let whole: u64 = parts[0].parse().map_err(|_| "bad whole")?;
    let mut frac_val: u64 = 0;
    if parts.len() == 2 {
        let frac = parts[1];
        if frac.len() > 8 { return Err("too many decimals"); }
        let padded = format!("{:<0width$}", frac, width = 8).replace(' ', "0");
        frac_val = padded.parse().map_err(|_| "bad frac")?;
    }
    whole.checked_mul(100_000_000).and_then(|w| w.checked_add(frac_val)).ok_or("overflow")
}

// Recovery scanner: re-derive keys with gap limit and attempt to sweep any pending funds
pub fn recovery_scan_and_finalize<E: FinalizeEngine>(
    engine: &E,
    db: &StatusDb,
    start_index: u32,
    gap_limit: u32,
    hrp: &str,
) -> Result<Vec<[u8; 32]>, String> {
    let mut finalized: Vec<[u8; 32]> = Vec::new();
    let coin = engine.coin_type();
    let mut consecutive_empty = 0u32;
    let mut idx = start_index;
    while consecutive_empty < gap_limit {
        let esk_child = engine.derive_esk_child(coin, idx)?;
        let key = derive_payment_key(&esk_child);
        // We do not know the exact requested amount; try to match any record in DB
        let mut matched = false;
        for rec in db.list_outbound().map_err(|e| e.to_string())? {
            if !rec.uri.starts_with("https://pay.withzcash.com:65536/payment/v1#") { continue; }
            if let Ok(cap) = parse_capability_uri(&rec.uri) {
                if !cap.key_bech32.starts_with(hrp) { continue; }
                if let Ok((_, data, _)) = bech32::decode(&cap.key_bech32) {
                    if let Ok(kb) = bech32::FromBase32::from_base32::<Vec<u8>>(&data) {
                        if kb.as_slice() == key {
                            if let Ok(amount) = parse_zec_amount_to_zat(&cap.amount_zec) {
                                let expected = amount.saturating_add(DEFAULT_FEE_ZAT);
                                if engine.note_exists_and_unspent(&key, expected)? {
                                    let txid = engine.sweep_with_key_to_wallet_addr(&key, amount)?;
                                    finalized.push(txid);
                                    matched = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        if matched { consecutive_empty = 0; } else { consecutive_empty += 1; }
        idx = idx.checked_add(1).ok_or("index overflow")?;
    }
    Ok(finalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_roundtrip() {
        let key = [7u8; 32];
        let key_b32 = bech32_encode_key("zpaykey", &key);
        let uri = build_capability_uri("1.23", Some("hello"), &key_b32);
        let parsed = parse_capability_uri(&uri).unwrap();
        assert_eq!(parsed.amount_zec, "1.23");
        assert!(parsed.key_bech32.starts_with("zpaykey1"));
    }
}

