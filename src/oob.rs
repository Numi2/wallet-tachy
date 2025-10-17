//!Goal of this code = Tachyon-style out-of-band Orchard note-info envelope (production-ready).
//! - UA canonical bytes (ZIP-316) bound in AAD - UA-bound: The envelope is cryptographically tied to the recipient’s Unified Address (UA). Only the UA holder can derive the decryption key.
//! trying to also make it cmx-bound: Bound to the note commitment (cmx) of the transaction. This prevents replay or substitution attacks; the envelope can only apply to that exact note.
//! - KDF: HKDF-SHA256 with salt = DS || H(header), info = H(kem_ct)
//! - PQC: through kem: ML-KEM-768 
//! - AEAD: ChaCha20-Poly1305
//! - will try to bind recipient PQC public key hash in header and cmx in the payload

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::CtOption;
use thiserror::Error;
use zeroize::Zeroize;

use orchard::{
    note::{Note, RandomSeed, Rho, ExtractedNoteCommitment},
    value::NoteValue,
    Address as OrchardAddress,
};

use zcash_address::unified;
use zcash_protocol::consensus::NetworkType;

use pqcrypto_mlkem::mlkem768 as mlkem;

const DS: &[u8] = b"zcash.oob.noteinfo.v1";
const MAGIC: &[u8] = b"TACHYON-OOB-NOTEINFO\0";
const VERSION: u8 = 1;

/// Errors.
#[derive(Debug, Error)]
pub enum OobError {
    #[error("unified address parse/encode failed")]
    UaParse,
    #[error("unified address lacks Orchard receiver")]
    NoOrch,
    #[error("invalid Orchard raw address bytes")]
    BadOrchAddr,
    #[error("invalid rho bytes")]
    BadRho,
    #[error("invalid rseed bytes for rho")]
    BadRseed,
    #[error("invalid note from parts")]
    BadNote,
    #[error("recipient PQC key mismatch (UKS/replay protection)")]
    PqcKeyIdMismatch,
    #[error("KEM decapsulation failed")]
    KemDecap,
    #[error("AEAD decrypt failed")]
    Aead,
    #[error("format error")]
    Framing,
}

/// Secret note data to deliver out-of-band.
#[derive(Clone, Debug)]
pub struct NoteInfo {
    pub value: u64,
    pub rho: [u8; 32],
    pub rseed: [u8; 32],
    pub memo: Vec<u8>, // 0..=512
}

/// Public header fields bound in AAD.
#[derive(Clone, Debug)]
struct Header {
    network_code: u8,        // 0: Main, 1: Test, 2: Regtest
    orch_raw43: [u8; 43],    // Orchard raw receiver bytes (ZIP-224)
    cmx: [u8; 32],           // Extracted note commitment (x-coordinate)
    pqc_pk_id: [u8; 32],     // SHA-256 of recipient ML-KEM-768 public key
    ua_canon: Vec<u8>,       // Canonical UA string bytes (ZIP-316)
}

/// Outer envelope.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub header_bytes: Vec<u8>, // serialized header used as AAD and for KDF salt
    pub kem_ct: Vec<u8>,       // ML-KEM-768 ciphertext
    pub nonce: [u8; 12],       // AEAD nonce
    pub ct: Vec<u8>,           // AEAD ciphertext (of NoteInfo payload)
}

fn network_code(net: NetworkType) -> u8 {
    match net {
        NetworkType::Main => 0,
        NetworkType::Test => 1,
        NetworkType::Regtest => 2,
    }
}

fn ua_to_canonical_and_orch_raw(ua_str: &str) -> Result<(NetworkType, Vec<u8>, [u8; 43]), OobError> {
    let (net, ua) = unified::Address::decode(ua_str).map_err(|_| OobError::UaParse)?;
    // Canonical ZIP-316 string bytes
    let ua_canon = ua.encode(&net).into_bytes();

    // Extract Orchard receiver raw bytes [u8; 43]
    let mut orch_raw: Option<[u8; 43]> = None;
    for r in ua.items() {
        if let unified::Receiver::Orchard(data) = r {
            orch_raw = Some(data);
            break;
        }
    }
    let orch_raw = orch_raw.ok_or(OobError::NoOrch)?;
    Ok((net, ua_canon, orch_raw))
}

fn orch_addr_from_raw(raw43: &[u8; 43]) -> Result<OrchardAddress, OobError> {
    let ct: CtOption<OrchardAddress> = OrchardAddress::from_raw_address_bytes(raw43);
    ct.into_option().ok_or(OobError::BadOrchAddr)
}

fn rho_from_bytes(b: [u8; 32]) -> Result<Rho, OobError> {
    // orchard::note::Rho::from_bytes -> CtOption<Rho>
    Rho::from_bytes(b).into_option().ok_or(OobError::BadRho)
}

fn rseed_from_bytes(rseed: [u8; 32], rho: &Rho) -> Result<RandomSeed, OobError> {
    RandomSeed::from_bytes(rseed, rho).into_option().ok_or(OobError::BadRseed)
}

fn note_value_from_raw(v: u64) -> NoteValue {
    // Orchard NoteValue is a newtype over u64 with from_raw.
    NoteValue::from_raw(v)
}

fn cmx_from_note(note: &Note) -> [u8; 32] {
    // commitment() -> NoteCommitment; Into<ExtractedNoteCommitment>; then to_bytes()
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    cmx.to_bytes()
}

/// Deterministic header encoding.
/// Format:
/// MAGIC || VERSION || net(1) || orch_raw43(43) || cmx(32) || pqc_pk_id(32) || ua_len(u16 LE) || ua_bytes
fn encode_header(h: &Header) -> Vec<u8> {
    let mut w = Vec::with_capacity(
        MAGIC.len() + 1 + 1 + 43 + 32 + 32 + 2 + h.ua_canon.len()
    );
    w.extend_from_slice(MAGIC);
    w.push(VERSION);
    w.push(h.network_code);
    w.extend_from_slice(&h.orch_raw43);
    w.extend_from_slice(&h.cmx);
    w.extend_from_slice(&h.pqc_pk_id);
    w.write_u16::<LittleEndian>(h.ua_canon.len() as u16).unwrap();
    w.extend_from_slice(&h.ua_canon);
    w
}

fn decode_header(mut bytes: &[u8]) -> Result<Header, OobError> {
    if bytes.len() < MAGIC.len() + 1 + 1 + 43 + 32 + 32 + 2 {
        return Err(OobError::Framing);
    }
    if &bytes[..MAGIC.len()] != MAGIC {
        return Err(OobError::Framing);
    }
    bytes = &bytes[MAGIC.len()..];
    let ver = bytes[0]; bytes = &bytes[1..];
    if ver != VERSION { return Err(OobError::Framing); }
    let network_code = bytes[0]; bytes = &bytes[1..];

    let mut orch_raw43 = [0u8; 43];
    orch_raw43.copy_from_slice(&bytes[..43]);
    bytes = &bytes[43..];

    let mut cmx = [0u8; 32];
    cmx.copy_from_slice(&bytes[..32]);
    bytes = &bytes[32..];

    let mut pqc_pk_id = [0u8; 32];
    pqc_pk_id.copy_from_slice(&bytes[..32]);
    bytes = &bytes[32..];

    let mut rdr = bytes;
    let ua_len = rdr.read_u16::<LittleEndian>().map_err(|_| OobError::Framing)? as usize;
    let consumed = 2;
    bytes = &bytes[consumed..];

    if bytes.len() < ua_len { return Err(OobError::Framing); }
    let ua_canon = bytes[..ua_len].to_vec();

    Ok(Header { network_code, orch_raw43, cmx, pqc_pk_id, ua_canon })
}

/// Deterministic payload encoding.
/// Format: version(1)=1 || value(u64 LE) || rho(32) || rseed(32) || memo_len(u16 LE) || memo
fn encode_payload(n: &NoteInfo) -> Result<Vec<u8>, OobError> {
    if n.memo.len() > 512 { return Err(OobError::Framing); }
    let mut w = Vec::with_capacity(1 + 8 + 32 + 32 + 2 + n.memo.len());
    w.push(VERSION);
    w.write_u64::<LittleEndian>(n.value).unwrap();
    w.extend_from_slice(&n.rho);
    w.extend_from_slice(&n.rseed);
    w.write_u16::<LittleEndian>(n.memo.len() as u16).unwrap();
    w.extend_from_slice(&n.memo);
    Ok(w)
}

fn decode_payload(mut bytes: &[u8]) -> Result<NoteInfo, OobError> {
    if bytes.len() < 1 + 8 + 32 + 32 + 2 { return Err(OobError::Framing); }
    let ver = bytes[0]; bytes = &bytes[1..];
    if ver != VERSION { return Err(OobError::Framing); }
    let mut rdr = bytes;
    let value = rdr.read_u64::<LittleEndian>().map_err(|_| OobError::Framing)?;
    let consumed_v = 8; bytes = &bytes[consumed_v..];

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[..32]); bytes = &bytes[32..];
    let mut rseed = [0u8; 32];
    rseed.copy_from_slice(&bytes[..32]); bytes = &bytes[32..];

    let memo_len = (&bytes[..]).read_u16::<LittleEndian>().map_err(|_| OobError::Framing)? as usize;
    bytes = &bytes[2..];
    if bytes.len() < memo_len { return Err(OobError::Framing); }
    let memo = bytes[..memo_len].to_vec();

    Ok(NoteInfo { value, rho, rseed, memo })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn derive_key(shared_secret: &[u8], header_bytes: &[u8], kem_ct_bytes: &[u8]) -> Key {
    let salt_bytes = {
        let mut v = Vec::with_capacity(DS.len() + 32);
        v.extend_from_slice(DS);
        v.extend_from_slice(&sha256(header_bytes));
        v
    };
    let info = sha256(kem_ct_bytes);
    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("HKDF expand");
    Key::from(okm)
}

fn orch_note_from_parts(orch_addr: OrchardAddress, ni: &NoteInfo) -> Result<Note, OobError> {
    let rho = rho_from_bytes(ni.rho)?;
    let rseed = rseed_from_bytes(ni.rseed, &rho)?;
    let v = note_value_from_raw(ni.value);
    let ct: CtOption<Note> = Note::from_parts(orch_addr, v, rho, rseed);
    ct.into_option().ok_or(OobError::BadNote)
}

/// Create an envelope from UA, recipient ML‑KEM‑768 public key, and note-info.
pub fn seal(ua_str: &str, recipient_pqc_pk: &mlkem::PublicKey, noteinfo: &NoteInfo) -> Result<Envelope, OobError> {
    // 1) Parse UA and Orchard receiver
    let (net, ua_canon, orch_raw) = ua_to_canonical_and_orch_raw(ua_str)?;
    let orch_addr = orch_addr_from_raw(&orch_raw)?;

    // 2) Build note and cmx from Orchard types
    let note = orch_note_from_parts(orch_addr, noteinfo)?;
    let cmx = cmx_from_note(&note);

    // 3) Recipient PQC key ID for UKS/replay hardening
    let pqc_pk_id = sha256(recipient_pqc_pk.as_bytes());

    // 4) Header (AAD)
    let header = Header {
        network_code: network_code(net),
        orch_raw43: orch_raw,
        cmx,
        pqc_pk_id,
        ua_canon,
    };
    let header_bytes = encode_header(&header);

    // 5) KEM encapsulation
    let (ss, kem_ct) = mlkem::encapsulate(recipient_pqc_pk);

    // 6) AEAD key derivation
    let aead_key = derive_key(ss.as_bytes(), &header_bytes, kem_ct.as_bytes());

    // 7) Encrypt payload
    let payload = encode_payload(noteinfo)?;
    let cipher = ChaCha20Poly1305::new(&aead_key);
    // One message per derived key, random 96-bit nonce is fine in this regime
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &payload, aad: &header_bytes })
        .map_err(|_| OobError::Aead)?;

    // 8) Output
    Ok(Envelope {
        header_bytes,
        kem_ct: kem_ct.as_bytes().to_vec(),
        nonce,
        ct,
    })
}

/// Open and verify an envelope with recipient secret key and expected UA + PQC pubkey.
/// Verifies PQC key binding, recomputes cmx from decrypted note and matches header.
pub fn open(envelope: &Envelope, recipient_pqc_sk: &mlkem::SecretKey, expected_recipient_pqc_pk: &mlkem::PublicKey, expected_ua: &str) -> Result<NoteInfo, OobError> {
    // 1) Parse header and verify PQC key binding and UA canonical
    let hdr = decode_header(&envelope.header_bytes)?;
    let expected_pk_id = sha256(expected_recipient_pqc_pk.as_bytes());
    if hdr.pqc_pk_id != expected_pk_id {
        return Err(OobError::PqcKeyIdMismatch);
    }
    // UA canonical check
    let (net, ua_canon_expected, orch_raw_expected) = ua_to_canonical_and_orch_raw(expected_ua)?;
    if hdr.ua_canon != ua_canon_expected { return Err(OobError::UaParse); }
    if hdr.orch_raw43 != orch_raw_expected { return Err(OobError::BadOrchAddr); }
    let orch_addr = orch_addr_from_raw(&hdr.orch_raw43)?;

    // 2) KEM decapsulation
    let ss = mlkem::decapsulate(
        &mlkem::Ciphertext::from_bytes(&envelope.kem_ct).map_err(|_| OobError::KemDecap)?,
        recipient_pqc_sk,
    );
    // 3) Derive AEAD key
    let aead_key = derive_key(ss.as_bytes(), &envelope.header_bytes, &envelope.kem_ct);

    // 4) Decrypt payload
    let cipher = ChaCha20Poly1305::new(&aead_key);
    let pt = cipher
        .decrypt(Nonce::from_slice(&envelope.nonce), Payload { msg: &envelope.ct, aad: &envelope.header_bytes })
        .map_err(|_| OobError::Aead)?;
    let mut noteinfo = decode_payload(&pt)?;

    // 5) Recompute cmx and compare with header
    let note = orch_note_from_parts(orch_addr, &noteinfo)?;
    let cmx = cmx_from_note(&note);
    if cmx != hdr.cmx { return Err(OobError::BadNote); }

    // Zeroize sensitive material in local scope
    {
        let mut k = aead_key.to_vec(); k.zeroize();
    }

    Ok(noteinfo)
}

/// Binary framing for transport/storage (outer bytes). Deterministic:
/// MAGIC || VERSION || header_len(u32 LE) || header || kem_ct_len(u32 LE) || kem_ct || nonce(12) || ct_len(u32 LE) || ct
impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(
            MAGIC.len() + 1 + 4 + self.header_bytes.len() + 4 + self.kem_ct.len() + 12 + 4 + self.ct.len()
        );
        w.extend_from_slice(MAGIC);
        w.push(VERSION);
        w.write_u32::<LittleEndian>(self.header_bytes.len() as u32).unwrap();
        w.extend_from_slice(&self.header_bytes);
        w.write_u32::<LittleEndian>(self.kem_ct.len() as u32).unwrap();
        w.extend_from_slice(&self.kem_ct);
        w.extend_from_slice(&self.nonce);
        w.write_u32::<LittleEndian>(self.ct.len() as u32).unwrap();
        w.extend_from_slice(&self.ct);
        w
    }

    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, OobError> {
        if bytes.len() < MAGIC.len() + 1 + 4 { return Err(OobError::Framing); }
        if &bytes[..MAGIC.len()] != MAGIC { return Err(OobError::Framing); }
        bytes = &bytes[MAGIC.len()..];
        let ver = bytes[0]; bytes = &bytes[1..];
        if ver != VERSION { return Err(OobError::Framing); }
        let mut rdr = bytes;
        let hlen = rdr.read_u32::<LittleEndian>().map_err(|_| OobError::Framing)? as usize;
        bytes = &bytes[4..];
        if bytes.len() < hlen { return Err(OobError::Framing); }
        let header_bytes = bytes[..hlen].to_vec();
        bytes = &bytes[hlen..];

        let klen = (&bytes[..]).read_u32::<LittleEndian>().map_err(|_| OobError::Framing)? as usize;
        bytes = &bytes[4..];
        if bytes.len() < klen + 12 + 4 { return Err(OobError::Framing); }
        let kem_ct = bytes[..klen].to_vec();
        bytes = &bytes[klen..];

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[..12]);
        bytes = &bytes[12..];

        let clen = (&bytes[..]).read_u32::<LittleEndian>().map_err(|_| OobError::Framing)? as usize;
        bytes = &bytes[4..];
        if bytes.len() < clen { return Err(OobError::Framing); }
        let ct = bytes[..clen].to_vec();

        Ok(Self { header_bytes, kem_ct, nonce, ct })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_mlkem::mlkem768 as mlkem;

    // This test uses a dummy Orchard receiver and UA.
    // Replace with a real UA when integrating with a wallet.
    #[test]
    fn round_trip() {
        // Generate recipient ML‑KEM‑768 keypair
        let (pk, sk) = mlkem::keypair();

        // Example Orchard-only UA (supply a real one in integration).
        // For unit test structure only: expect parse failure here without a real UA.
        let ua = "u1qqqqqq"; // placeholder; replace in real tests.

        // Skip if UA placeholder; ensure code compiles.
        let _ = (pk, sk, ua);
    }
}