use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use zcash_address::{ZcashAddress, NetworkKind};
#[cfg(feature = "zip321_crate")]
use zip321 as zip321_crate;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Zip321Error {
    #[error("invalid scheme")] InvalidScheme,
    #[error("missing address")] MissingAddress,
    #[error("invalid parameter")] InvalidParam,
    #[error("invalid memo encoding")] InvalidMemo,
    #[error("network mismatch")] NetworkMismatch,
    #[error("unsupported sprout address")] UnsupportedSprout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientOutput {
    pub address: String,     // validated externally by wallet
    pub amount_zec: Option<String>, // decimal string per ZIP-321
    pub memo_b64url: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentRequest {
    pub recipients: Vec<RecipientOutput>,
}

impl PaymentRequest {
    pub fn parse(uri: &str, expected_network: Option<NetworkKind>) -> Result<Self, Zip321Error> {
        // Expect form: zcash:<addr>[,<addrN>] ? k[.i]=v
        let (scheme, rest) = uri.split_once(":").ok_or(Zip321Error::InvalidScheme)?;
        if scheme != "zcash" { return Err(Zip321Error::InvalidScheme); }
        let (path, query) = match rest.split_once('?') { Some((p, q)) => (p, Some(q)), None => (rest, None) };
        if path.is_empty() { return Err(Zip321Error::MissingAddress); }
        let addrs: Vec<String> = path.split(',').map(|s| s.to_string()).collect();
        let mut params: BTreeMap<(String, usize), String> = BTreeMap::new();
        if let Some(qs) = query {
            for pair in qs.split('&') {
                if pair.is_empty() { continue; }
                let (k, v) = match pair.split_once('=') { Some((k, v)) => (k, v), None => (pair, "") };
                // support suffix .i
                let mut base = k;
                let mut idx: usize = 0;
                if let Some((b, i)) = k.rsplit_once('.') {
                    if let Ok(n) = i.parse::<usize>() { base = b; idx = n; }
                }
                params.insert((base.to_string(), idx), v.to_string());
            }
        }

        let mut recipients = Vec::with_capacity(addrs.len());
        for (i, addr) in addrs.iter().enumerate() {
            if let Ok(parsed_addr) = ZcashAddress::try_from_encoded(addr) {
                if matches!(parsed_addr, ZcashAddress::Sprout {..}) { return Err(Zip321Error::UnsupportedSprout); }
                if let Some(net) = expected_network {
                    if parsed_addr.network_kind() != net { return Err(Zip321Error::NetworkMismatch); }
                }
            }
            let amount = params.get(&("amount".to_string(), i)).cloned();
            let label = params
                .get(&("label".to_string(), i))
                .map(|s| percent_decode_str(s).decode_utf8_lossy().to_string());
            let memo = params.get(&("memo".to_string(), i)).cloned();
            if let Some(m) = &memo {
                // Enforce base64url charset (no padding per ZIP-321)
                if !m.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' ) {
                    return Err(Zip321Error::InvalidMemo);
                }
            }
            recipients.push(RecipientOutput {
                address: addr.clone(),
                amount_zec: amount,
                memo_b64url: memo,
                label,
            });
        }
        Ok(PaymentRequest { recipients })
    }

    pub fn total_amount_zat(&self) -> Result<u64, Zip321Error> {
        let mut total: u64 = 0;
        for r in &self.recipients {
            if let Some(a) = &r.amount_zec {
                let zat = crate::zip324::parse_zec_amount_to_zat(a).map_err(|_| Zip321Error::InvalidParam)?;
                total = total.checked_add(zat).ok_or(Zip321Error::InvalidParam)?;
            }
        }
        Ok(total)
    }

    pub fn build(&self) -> String {
        // Single or multi-recipient per ZIP-321
        let path = self.recipients.iter().map(|r| r.address.clone()).collect::<Vec<_>>().join(",");
        let mut qs: Vec<String> = Vec::new();
        for (i, r) in self.recipients.iter().enumerate() {
            if let Some(a) = &r.amount_zec { qs.push(format!("amount.{}={}", i, a)); }
            if let Some(m) = &r.memo_b64url { qs.push(format!("memo.{}={}", i, m)); }
            if let Some(l) = &r.label { qs.push(format!("label.{}={}", i, percent_encode(l.as_bytes(), NON_ALPHANUMERIC))); }
        }
        if qs.is_empty() {
            format!("zcash:{}", path)
        } else {
            format!("zcash:{}?{}", path, qs.join("&"))
        }
    }

    #[cfg(feature = "zip321_crate")]
    pub fn to_zip321(&self) -> zip321_crate::TransactionRequest {
        let mut req = zip321_crate::TransactionRequest::default();
        for r in &self.recipients {
            let mut out = zip321_crate::TransactionRequestOutput::default();
            out.address = r.address.clone();
            out.amount = r.amount_zec.clone();
            out.memo = r.memo_b64url.clone();
            out.label = r.label.clone();
            req.outputs.push(out);
        }
        req
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_build_roundtrip() {
        let uri = "zcash:zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0r0jyg?amount.0=1.23&memo.0=SGVsbG8&label.0=Test%20Label";
        let pr = PaymentRequest::parse(uri, None).unwrap();
        assert_eq!(pr.recipients.len(), 1);
        assert_eq!(pr.recipients[0].amount_zec.as_deref(), Some("1.23"));
        let rebuilt = pr.build();
        assert!(rebuilt.starts_with("zcash:"));
    }
}

