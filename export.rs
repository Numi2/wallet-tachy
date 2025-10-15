// export.rs
//
// Single-file reference implementation of a "Recovery Capsule" for Tachyon-style wallets.
// It exports an encrypted, integrity-checked, threshold-recoverable snapshot of wallet state,
// and supports recovery using any t-of-n combination of shares from guardians, a device factor,
// and an optional passphrase factor.
//
// Build hint (add these to Cargo.toml):
// [dependencies]
// blake3 = "1"
// chacha20poly1305 = { version = "0.10", features = ["std", "xchacha20"] }
// hkdf = "0.12"
// sha2 = "0.10"
// rand = "0.8"
// rand_core = "0.6"
// x25519-dalek = { version = "2", features = ["static_secrets"] }
// argon2 = "0.5"
// serde = { version = "1.0", features = ["derive"] }
// serde_cbor = "0.11"
// thiserror = "1.0"

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use blake3::Hasher as Blake3;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

// ----------------------------- Errors -----------------------------

#[derive(Debug, Error)]
pub enum CapsuleError {
    #[error("serialization error: {0}")]
    Ser(String),
    #[error("decryption error")]
    Decrypt,
    #[error("insufficient shares for threshold")]
    NotEnoughShares,
    #[error("guardian key not recognized")]
    UnknownGuardian,
    #[error("invalid capsule")]
    InvalidCapsule,
    #[error("bad parameters")]
    BadParams,
}

// ----------------------------- Wallet State -----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    // Minimal live state placeholders. Replace with project-specific types.
    pub anchor: [u8; 32],
    pub unspent_notes: Vec<Vec<u8>>,      // opaque note encodings
    pub witnesses: Vec<Vec<u8>>,          // membership proofs
    pub nullifiers: Vec<[u8; 32]>,        // seen nullifiers
    pub payments: Vec<PaymentRecord>,     // history needed for future spends
    pub keys: KeyMaterial,                // payment and viewing secrets
    pub metadata: WalletMetadata,         // labels, contacts, settings
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecord {
    pub direction: u8,                    // 0=in,1=out
    pub note_commitment: [u8; 32],
    pub amount: u64,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterial {
    pub payment_keys: Vec<[u8; 32]>,
    pub ivk_secrets: Vec<[u8; 32]>,
    pub session_state: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMetadata {
    pub contacts: Vec<Contact>,
    pub labels: Vec<(String, String)>,
    pub settings: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub routing_hint: Vec<u8>, // opaque
}

// ----------------------------- Policy -----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    pub label: String,
    pub pubkey: [u8; 32], // X25519 public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub threshold: u8,              // t
    pub guardians: Vec<Guardian>,   // n_g guardians
    pub include_device: bool,       // optional device factor
    pub include_passphrase: bool,   // optional passphrase factor
}

// ----------------------------- Capsule Format -----------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleHeader {
    pub version: u16,
    pub ciphersuite: Ciphersuite,
    pub policy: RecoveryPolicyPublic,
    pub h_i: [u8; 32],          // ratchet hash for snapshot i
    pub state_root: [u8; 32],   // commitment to state payload
    pub created: u64,           // unix seconds
    pub nonce: [u8; 24],        // AEA  
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPolicyPublic {
    pub threshold: u8,
    pub guardians: Vec<GuardianPublic>,
    pub include_device: bool,
    pub include_passphrase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianPublic {
    pub label: String,
    pub pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Ciphersuite {
    X25519_HKDF_SHA256_XCHACHA20POLY1305,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    pub guardian_shares: Vec<GuardianWrappedShare>,
    pub device_share: Option<DeviceWrappedShare>,
    pub passphrase_share: Option<PassphraseWrappedShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianWrappedShare {
    pub label: String,
    pub eph_pubkey: [u8; 32], // ephemeral X25519 pubkey
    pub nonce: [u8; 24],      // AEAD nonce for share
    pub share_ct: Vec<u8>,    // encrypted Shamir share bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceWrappedShare {
    pub nonce: [u8; 24],      // AEAD nonce under device key
    pub share_ct: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseWrappedShare {
    pub salt: [u8; 16],       // Argon2id salt
    pub params: Argon2Params,
    pub nonce: [u8; 24],      // AEAD nonce under Argon2-derived key
    pub share_ct: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub header: CapsuleHeader,
    pub wrapped: WrappedKey,
    pub ciphertext: Vec<u8>, // AEAD(state)
    pub auth: [u8; 32],      // blake3 over header|wrapped|ciphertext
}

// ----------------------------- Key Schedule -----------------------------

#[derive(Debug, Clone)]
struct KeySchedule {
    k_state: [u8; 32],   // for ratchet chaining (not used externally here)
    k_export: [u8; 32],  // for snapshot AEAD key derivation
    k_index: [u8; 32],   // blind locator derivations (optional)
}

fn derive_keys_from_seed(seed: &[u8; 32]) -> KeySchedule {
    let hk = Hkdf::<Sha256>::new(Some(b"tachyon/root"), seed);
    let mut k_state = [0u8; 32];
    let mut k_export = [0u8; 32];
    let mut k_index = [0u8; 32];
    hk.expand(b"state-log", &mut k_state).unwrap();
    hk.expand(b"export-aead", &mut k_export).unwrap();
    hk.expand(b"blind-index", &mut k_index).unwrap();
    KeySchedule { k_state, k_export, k_index }
}

fn k_snap_i(k_export: &[u8; 32], h_i: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"tachyon/snap"), k_export);
    let mut out = [0u8; 32];
    hk.expand(h_i, &mut out).unwrap();
    out
}

// ----------------------------- GF(256) + Shamir -----------------------------

// Minimal Shamir over GF(256) with polynomial mod 0x11b.
// Secret is 32 bytes. We share bytewise. Share index x ∈ [1..=255].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShamirShare {
    pub x: u8,
    pub y: [u8; 32], // 32 bytes, one per secret byte
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) == 1 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // AES polynomial 0x11b with drop of high bit in 8-bit arithmetic
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut a: u8, mut e: u8) -> u8 {
    let mut r = 1u8;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul(r, a);
        }
        a = gf_mul(a, a);
        e >>= 1;
    }
    r
}

fn gf_inv(a: u8) -> u8 {
    // a^(255-1) in GF(256) => a^254
    if a == 0 {
        0
    } else {
        gf_pow(a, 254)
    }
}

fn shamir_split(secret: &[u8; 32], t: u8, n: u8) -> Vec<ShamirShare> {
    assert!(t >= 1 && t <= n && n <= 255);
    let mut rng = rand::thread_rng();
    // For each byte, sample degree-(t-1) polynomial coefficients: a0=secret_byte, a1..a_{t-1} random.
    let mut coeffs: Vec<Vec<u8>> = vec![vec![0u8; t as usize]; 32];
    for b in 0..32 {
        coeffs[b][0] = secret[b];
        for j in 1..t as usize {
            coeffs[b][j] = rng.next_u32() as u8;
        }
    }
    let mut shares = Vec::with_capacity(n as usize);
    for xi in 1..=n {
        let x = xi as u8;
        let mut y = [0u8; 32];
        for b in 0..32 {
            let mut acc = 0u8;
            let mut xp = 1u8; // x^0
            for j in 0..t as usize {
                acc ^= gf_mul(coeffs[b][j], xp);
                xp = gf_mul(xp, x);
            }
            y[b] = acc;
        }
        shares.push(ShamirShare { x, y });
    }
    shares
}

fn shamir_recover(shares: &[ShamirShare], t: u8) -> Result<[u8; 32], CapsuleError> {
    if shares.len() < t as usize {
        return Err(CapsuleError::NotEnoughShares);
    }
    // Use first t shares for interpolation at x=0 via Lagrange basis.
    let used = &shares[..t as usize];
    let mut secret = [0u8; 32];
    for b in 0..32 {
        let mut sb = 0u8;
        for (i, si) in used.iter().enumerate() {
            let xi = si.x;
            let yi = si.y[b];
            // λ_i(0) = Π_{j≠i} (x_j / (x_j - x_i))
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, sj) in used.iter().enumerate() {
                if i == j { continue; }
                num = gf_mul(num, sj.x);
                let diff = sj.x ^ xi; // in GF(256) addition == XOR; subtraction == addition
                den = gf_mul(den, diff);
            }
            let li = gf_mul(num, gf_inv(den));
            sb ^= gf_mul(yi, li);
        }
        secret[b] = sb;
    }
    Ok(secret)
}

// ----------------------------- Simple HPKE (ECIES-style) -----------------------------

fn hpke_like_encrypt(recipient_pub: &[u8; 32], aad: &[u8], pt: &[u8]) -> ( [u8;32], [u8;24], Vec<u8> ) {
    // 1) Ephemeral X25519
    let eph_sk = X25519Secret::random_from_rng(OsRng);
    let eph_pk = X25519PublicKey::from(&eph_sk);
    // 2) Shared secret
    let pk_r = X25519PublicKey::from(*recipient_pub);
    let dh = eph_sk.diffie_hellman(&pk_r);
    // 3) Derive AEAD key using HKDF with context = "hpke-like" || eph_pk || recipient_pub
    let mut info = Vec::with_capacity(7 + 32 + 32);
    info.extend_from_slice(b"hpke-v1");
    info.extend_from_slice(eph_pk.as_bytes());
    info.extend_from_slice(recipient_pub);
    let hk = Hkdf::<Sha256>::new(Some(b"hpke-like"), dh.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).unwrap();
    let aead = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ct = aead
        .encrypt(XNonce::from(nonce_bytes), chacha20poly1305::aead::Payload { msg: pt, aad })
        .expect("encrypt");
    ( *eph_pk.as_bytes(), nonce_bytes, ct )
}

fn hpke_like_decrypt(recipient_sk: &X25519Secret, eph_pub: &[u8; 32], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CapsuleError> {
    let pk_e = X25519PublicKey::from(*eph_pub);
    let dh = recipient_sk.diffie_hellman(&pk_e);
    let mut info = Vec::with_capacity(7 + 32 + 32);
    info.extend_from_slice(b"hpke-v1");
    info.extend_from_slice(eph_pub);
    let pk_r = X25519PublicKey::from(recipient_sk);
    info.extend_from_slice(pk_r.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(b"hpke-like"), dh.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).unwrap();
    let aead = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
    // Nonce is included by caller
    Err(CapsuleError::Decrypt)
}

// ----------------------------- Export -----------------------------

#[derive(Debug, Clone)]
pub struct ExportInputs<'a> {
    pub seed: &'a [u8; 32],
    pub state: &'a SnapshotState,
    pub policy: &'a RecoveryPolicy,
    pub prev_h: Option<[u8; 32]>,
    pub passphrase: Option<&'a str>,          // optional factor
    pub device_key: Option<&'a [u8; 32]>,     // optional factor
}

pub fn export_capsule(inputs: ExportInputs) -> Result<Vec<u8>, CapsuleError> {
    // Key schedule
    let ks = derive_keys_from_seed(inputs.seed);

    // Commit state and ratchet
    let state_bytes = serde_cbor::to_vec(inputs.state).map_err(|e| CapsuleError::Ser(e.to_string()))?;
    let state_root = blake3_hash(&state_bytes);

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut ratchet = Blake3::new();
    if let Some(prev) = inputs.prev_h {
        ratchet.update(&prev);
    }
    ratchet.update(&state_root);
    let time_bytes = now.to_le_bytes();
    ratchet.update(&time_bytes);
    let h_i = ratchet.finalize().as_bytes().clone();

    // Snapshot key and AEAD
    let k_snap = k_snap_i(&ks.k_export, &h_i);
    let aead = XChaCha20Poly1305::new(AeadKey::from_slice(&k_snap));
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let header_preview = CapsuleHeader {
        version: 1,
        ciphersuite: Ciphersuite::X25519_HKDF_SHA256_XCHACHA20POLY1305,
        policy: RecoveryPolicyPublic {
            threshold: inputs.policy.threshold,
            guardians: inputs.policy.guardians.iter().map(|g| GuardianPublic { label: g.label.clone(), pubkey: g.pubkey }).collect(),
            include_device: inputs.policy.include_device,
            include_passphrase: inputs.policy.include_passphrase,
        },
        h_i,
        state_root,
        created: now,
        nonce,
    };

    // AEAD encrypt state with AAD = header fields (sans ciphertext) unsure about thius one tbh
    let aad = serde_cbor::to_vec(&header_preview).map_err(|e| CapsuleError::Ser(e.to_string()))?;
    let ciphertext = aead
        .encrypt(
            XNonce::from(nonce),
            chacha20poly1305::aead::Payload { msg: &state_bytes, aad: &aad },
        )
        .map_err(|_| CapsuleError::Decrypt)?;

    // Shamir splits of k_snap 
    let mut total_n = inputs.policy.guardians.len() as u8;
    if inputs.policy.include_device { total_n += 1; }
    if inputs.policy.include_passphrase { total_n += 1; }
    let shares = shamir_split(&k_snap, inputs.policy.threshold, total_n);
    let mut sh_iter = shares.into_iter();

    // Assign shares
    let mut guardian_shares = Vec::new();
    for g in &inputs.policy.guardians {
        let share = sh_iter.next().expect("enough shares");
        let (eph_pk, share_nonce, share_ct) = {
            // HPKE-like
            let aad_share = blake3_label(b"guardian-share-aad", &aad);
            let (eph, n, ct) = hpke_like_encrypt(&g.pubkey, &aad_share, &bincode_serialize(&share)?);
            (eph, n, ct)
        };
        guardian_shares.push(GuardianWrappedShare {
            label: g.label.clone(),
            eph_pubkey: eph_pk,
            nonce: share_nonce,
            share_ct: share_ct,
        });
    }

    let mut device_share = None;
    if inputs.policy.include_device {
        let share = sh_iter.next().expect("enough shares");
        let dk = inputs
            .device_key
            .ok_or(CapsuleError::BadParams)?
            .clone();
        let device_key = XChaCha20Poly1305::new(AeadKey::from_slice(dk));
        let mut n = [0u8; 24];
        OsRng.fill_bytes(&mut n);
        let aad_dev = blake3_label(b"device-share-aad", &aad);
        let pt = bincode_serialize(&share)?;
        let ct = device_key
            .encrypt(XNonce::from(n), chacha20poly1305::aead::Payload { msg: &pt, aad: &aad_dev })
            .map_err(|_| CapsuleError::Decrypt)?;
        device_share = Some(DeviceWrappedShare { nonce: n, share_ct: ct });
    }

    let mut passphrase_share = None;
    if inputs.policy.include_passphrase {
        let share = sh_iter.next().expect("enough shares");
        let pass = inputs.passphrase.ok_or(CapsuleError::BadParams)?;
        let params = Argon2Params { m_cost_kib: 262144, t_cost: 3, p_cost: 1 }; // 256 MiB, 3 iters, p=1
        let salt = SaltString::generate(&mut OsRng);
        let salt_bytes = salt.as_str().as_bytes();
        let mut salt16 = [0u8; 16];
        salt16[..16.min(salt_bytes.len())].copy_from_slice(&salt_bytes[..16.min(salt_bytes.len())]);
        let argon2 = Argon2::new_with_secret(b"capsule-passphrase", argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, None).unwrap()).unwrap();
        let mut key = [0u8; 32];
        argon2.hash_password_into(pass.as_bytes(), &salt16, &mut key).unwrap();
        let aead_pp = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
        let mut n = [0u8; 24];
        OsRng.fill_bytes(&mut n);
        let aad_pp = blake3_label(b"passphrase-share-aad", &aad);
        let pt = bincode_serialize(&share)?;
        let ct = aead_pp
            .encrypt(XNonce::from(n), chacha20poly1305::aead::Payload { msg: &pt, aad: &aad_pp })
            .map_err(|_| CapsuleError::Decrypt)?;
        passphrase_share = Some(PassphraseWrappedShare { salt: salt16, params, nonce: n, share_ct: ct });
    }

    let wrapped = WrappedKey { guardian_shares, device_share, passphrase_share };

    // Authenticatiooooooon - i love blake3, will it work?
    let mut auth_hasher = Blake3::new();
    auth_hasher.update(&serde_cbor::to_vec(&header_preview).unwrap());
    auth_hasher.update(&serde_cbor::to_vec(&wrapped).unwrap());
    auth_hasher.update(&ciphertext);
    let auth = *auth_hasher.finalize().as_bytes();

    let cap = Capsule { header: header_preview, wrapped, ciphertext, auth };
    let bytes = serde_cbor::to_vec(&cap).map_err(|e| CapsuleError::Ser(e.to_string()))?;
    Ok(bytes)
}

// ----------------------------- Recovery -----------------------------

#[derive(Debug, Clone)]
pub struct RecoveryInputs<'a> {
    pub capsule_bytes: &'a [u8],
    pub guardian_keys: HashMap<String, [u8; 32]>, // label -> X25519 secret
    pub passphrase: Option<&'a str>,
    pub device_key: Option<&'a [u8; 32]>,
}

pub fn recover_capsule(inputs: RecoveryInputs) -> Result<SnapshotState, CapsuleError> {
    let cap: Capsule = serde_cbor::from_slice(inputs.capsule_bytes).map_err(|e| CapsuleError::Ser(e.to_string()))?;

    // Verify auth
    let mut auth_hasher = Blake3::new();
    auth_hasher.update(&serde_cbor::to_vec(&cap.header).unwrap());
    auth_hasher.update(&serde_cbor::to_vec(&cap.wrapped).unwrap());
    auth_hasher.update(&cap.ciphertext);
    if *auth_hasher.finalize().as_bytes() != cap.auth {
        return Err(CapsuleError::InvalidCapsule);
    }

    // Collect shares
    let mut shares: Vec<ShamirShare> = Vec::new();

    // Guardian shares
    for gct in &cap.wrapped.guardian_shares {
        if let Some(sk_bytes) = inputs.guardian_keys.get(&gct.label) {
            let sk = X25519Secret::from(*sk_bytes);
            // Derive share AEAD key
            let pk_e = gct.eph_pubkey;
            // KDF key
            let dh = sk.diffie_hellman(&X25519PublicKey::from(pk_e));
            let mut info = Vec::with_capacity(7 + 32 + 32);
            info.extend_from_slice(b"hpke-v1");
            info.extend_from_slice(&pk_e);
            let pk_r = X25519PublicKey::from(&sk);
            info.extend_from_slice(pk_r.as_bytes());
            let hk = Hkdf::<Sha256>::new(Some(b"hpke-like"), dh.as_bytes());
            let mut key = [0u8; 32];
            hk.expand(&info, &mut key).unwrap();
            let aead = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
            let aad_share = blake3_label(b"guardian-share-aad", &serde_cbor::to_vec(&cap.header).unwrap());
            let pt = aead
                .decrypt(XNonce::from(gct.nonce), chacha20poly1305::aead::Payload { msg: &gct.share_ct, aad: &aad_share })
                .map_err(|_| CapsuleError::Decrypt)?;
            let share: ShamirShare = bincode_deserialize(&pt)?;
            shares.push(share);
        }
    }

    // Device share
    if let (true, Some(dev), Some(ds)) = (cap.header.policy.include_device, inputs.device_key, &cap.wrapped.device_share) {
        let aead = XChaCha20Poly1305::new(AeadKey::from_slice(dev));
        let aad_dev = blake3_label(b"device-share-aad", &serde_cbor::to_vec(&cap.header).unwrap());
        let pt = aead
            .decrypt(XNonce::from(ds.nonce), chacha20poly1305::aead::Payload { msg: &ds.share_ct, aad: &aad_dev })
            .map_err(|_| CapsuleError::Decrypt)?;
        shares.push(bincode_deserialize(&pt)?);
    }

    // Passphrase share
    if let (true, Some(pp), Some(ps)) = (cap.header.policy.include_passphrase, inputs.passphrase, &cap.wrapped.passphrase_share) {
        let params = argon2::Params::new(ps.params.m_cost_kib, ps.params.t_cost, ps.params.p_cost, None).unwrap();
        let argon2 = Argon2::new_with_secret(b"capsule-passphrase", argon2::Algorithm::Argon2id, argon2::Version::V0x13, params).unwrap();
        let mut key = [0u8; 32];
        argon2.hash_password_into(pp.as_bytes(), &ps.salt, &mut key).unwrap();
        let aead = XChaCha20Poly1305::new(AeadKey::from_slice(&key));
        let aad_pp = blake3_label(b"passphrase-share-aad", &serde_cbor::to_vec(&cap.header).unwrap());
        let pt = aead
            .decrypt(XNonce::from(ps.nonce), chacha20poly1305::aead::Payload { msg: &ps.share_ct, aad: &aad_pp })
            .map_err(|_| CapsuleError::Decrypt)?;
        shares.push(bincode_deserialize(&pt)?);
    }

    // Reconstruct snapshot key
    let t = cap.header.policy.threshold;
    if shares.len() < t as usize {
        return Err(CapsuleError::NotEnoughShares);
    }
    let k_snap = shamir_recover(&shares, t)?;

    // Decrypt state
    let aead_state = XChaCha20Poly1305::new(AeadKey::from_slice(&k_snap));
    let aad = serde_cbor::to_vec(&cap.header).map_err(|e| CapsuleError::Ser(e.to_string()))?;
    let pt = aead_state
        .decrypt(XNonce::from(cap.header.nonce), chacha20poly1305::aead::Payload { msg: &cap.ciphertext, aad: &aad })
        .map_err(|_| CapsuleError::Decrypt)?;
    // Confirm commitment
    if blake3_hash(&pt) != cap.header.state_root {
        return Err(CapsuleError::InvalidCapsule);
    }
    let state: SnapshotState = serde_cbor::from_slice(&pt).map_err(|e| CapsuleError::Ser(e.to_string()))?;
    Ok(state)
}

// ----------------------------- Helpers -----------------------------

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn blake3_label(label: &[u8], body: &[u8]) -> Vec<u8> {
    let mut h = Blake3::new();
    h.update(label);
    h.update(body);
    h.finalize().as_bytes().to_vec()
}

fn bincode_serialize<T: ?Sized + Serialize>(v: &T) -> Result<Vec<u8>, CapsuleError> {
    // compact serialization for shares; use serde_cbor if preferred
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| CapsuleError::Ser(e.to_string()))
}

fn bincode_deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, CapsuleError> {
    let (val, _len): (T, usize) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| CapsuleError::Ser(e.to_string()))?;
    Ok(val)
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> SnapshotState {
        SnapshotState {
            anchor: [7u8; 32],
            unspent_notes: vec![vec![1, 2, 3]],
            witnesses: vec![vec![4, 5, 6]],
            nullifiers: vec![[9u8; 32]],
            payments: vec![PaymentRecord {
                direction: 0,
                note_commitment: [8u8; 32],
                amount: 42,
                memo: Some("hi".into()),
            }],
            keys: KeyMaterial {
                payment_keys: vec![[1u8; 32]],
                ivk_secrets: vec![[2u8; 32]],
                session_state: vec![vec![7, 7, 7]],
            },
            metadata: WalletMetadata {
                contacts: vec![Contact { name: "A".into(), routing_hint: vec![1, 2] }],
                labels: vec![("k".into(), "v".into())],
                settings: vec![("s".into(), "x".into())],
            },
        }
    }

    #[test]
    fn roundtrip_guardians_only() {
        let seed = [3u8; 32];
        let g1_sk = X25519Secret::from([11u8; 32]);
        let g1_pk = X25519PublicKey::from(&g1_sk);
        let g2_sk = X25519Secret::from([12u8; 32]);
        let g2_pk = X25519PublicKey::from(&g2_sk);

        let policy = RecoveryPolicy {
            threshold: 2,
            guardians: vec![
                Guardian { label: "g1".into(), pubkey: *g1_pk.as_bytes() },
                Guardian { label: "g2".into(), pubkey: *g2_pk.as_bytes() },
            ],
            include_device: false,
            include_passphrase: false,
        };
        let capsule = export_capsule(ExportInputs {
            seed: &seed,
            state: &sample_state(),
            policy: &policy,
            prev_h: None,
            passphrase: None,
            device_key: None,
        }).unwrap();

        let mut keys = HashMap::new();
        keys.insert("g1".into(), *g1_sk.to_bytes());
        keys.insert("g2".into(), *g2_sk.to_bytes());

        let rec = recover_capsule(RecoveryInputs {
            capsule_bytes: &capsule,
            guardian_keys: keys,
            passphrase: None,
            device_key: None,
        }).unwrap();

        assert_eq!(rec.anchor, [7u8; 32]);
    }

    #[test]
    fn roundtrip_with_device_and_passphrase_t2of3() {
        let seed = [5u8; 32];
        let g1_sk = X25519Secret::from([21u8; 32]);
        let g1_pk = X25519PublicKey::from(&g1_sk);

        let policy = RecoveryPolicy {
            threshold: 2,
            guardians: vec![
                Guardian { label: "g1".into(), pubkey: *g1_pk.as_bytes() },
            ],
            include_device: true,
            include_passphrase: true,
        };

        let device_key = [7u8; 32];
        let passphrase = "correct horse battery staple";

        let capsule = export_capsule(ExportInputs {
            seed: &seed,
            state: &sample_state(),
            policy: &policy,
            prev_h: None,
            passphrase: Some(passphrase),
            device_key: Some(&device_key),
        }).unwrap();

        // Recover using guardian + device
        let mut keys = HashMap::new();
        keys.insert("g1".into(), *g1_sk.to_bytes());
        let rec1 = recover_capsule(RecoveryInputs {
            capsule_bytes: &c
apsule,
            guardian_keys: keys.clone(),
            passphrase: None,
            device_key: Some(&device_key),
        }).unwrap();
        assert_eq!(rec1.anchor, [7u8; 32]);

        // Recover using passphrase + device (no guardian)
        let rec2 = recover_capsule(RecoveryInputs {
            capsule_bytes: &capsule,
            guardian_keys: HashMap::new(),
            passphrase: Some(passphrase),
            device_key: Some(&device_key),
        }).unwrap();
        assert_eq!(rec2.anchor, [7u8; 32]);
    }
}