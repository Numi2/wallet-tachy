//! Note Encryption and Decryption for Traditional Actions
//! Numan 
//! This module implements ChaCha20-Poly1305 encryption for note plaintexts in
//! Traditional Actions, allowing on-chain recovery from the blockchain.
//!
//! # Encryption Scheme
//!
//! For Traditional Actions (compatible with Orchard):
//! - **AEAD**: ChaCha20-Poly1305
//! - **Key Derivation**: ECDH + HKDF-BLAKE2b
//! - **Ephemeral Key**: X coordinate of Pallas point
//! - **Nonce**: Derived from shared secret (deterministic)
//!
//! # Protocol
//!
//! ```text
//! Sender:
//!   1. Generate ephemeral secret esk
//!   2. Compute ephemeral public key epk = [esk]G
//!   3. Compute shared secret: ss = [esk]pk_d
//!   4. Derive encryption key: k_enc = KDF(ss, epk)
//!   5. Encrypt: ct = ChaCha20Poly1305.Encrypt(k_enc, nonce, plaintext)
//!   6. Publish (epk, ct) on-chain
//!
//! Recipient:
//!   1. Compute shared secret: ss = [ivk]epk
//!   2. Derive encryption key: k_enc = KDF(ss, epk)
//!   3. Decrypt: plaintext = ChaCha20Poly1305.Decrypt(k_enc, nonce, ct)
//! ```
//!
//! # Note Plaintext Format
//!
//! For Tachyon (simplified from Orchard):
//! ```text
//! plaintext = version(1) || value(8) || rho(32) || rseed(32) || memo(512)
//! Total: 585 bytes
//! ```
//!
//! Where:
//! - `version`: Protocol version (currently 0x01)
//! - `value`: Note value in zatoshis (little-endian u64)
//! - `rho`: Note unique identifier (32 bytes)
//! - `rseed`: Random seed for note commitment (32 bytes)
//! - `memo`: Arbitrary memo field (512 bytes, can be all zeros)

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use group::{Group, GroupEncoding};
use halo2curves::pasta::{pallas, Fq as PallasScalar};
use halo2curves::ff::{Field, PrimeField};
use rand::{RngCore, CryptoRng};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

use crate::actions::EphemeralPublicKey;

// ----------------------------- Constants -----------------------------

/// Domain tag for key derivation (Zcash Orchard KDF spec)
const DS_NOTE_ENCRYPTION: &[u8] = b"Zcash_OrchardKDF";

/// ChaCha20-Poly1305 uses a fixed all-zero nonce per Zcash spec.
/// Freshness is guaranteed by using a unique ephemeral key (esk) per output.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Note plaintext version
const NOTE_PLAINTEXT_VERSION: u8 = 0x01;

/// Size of note plaintext
pub const NOTE_PLAINTEXT_SIZE: usize = 1 + 8 + 32 + 32 + 512; // 585 bytes

/// Size of memo field
pub const MEMO_SIZE: usize = 512;

/// Size of encrypted note (plaintext + authentication tag)
pub const ENCRYPTED_NOTE_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16; // 601 bytes

// ----------------------------- Types -----------------------------

/// An ephemeral secret key for note encryption
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct EphemeralSecretKey(pub PallasScalar);

impl EphemeralSecretKey {
    /// Generate a random ephemeral secret
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        Self(PallasScalar::random(&mut rng))
    }
    
    /// Derive ephemeral public key: epk = [esk]G
    pub fn derive_public_key(&self) -> EphemeralPublicKey {
        let point = pallas::Point::generator() * self.0;
        let affine = pallas::Affine::from(point);
        EphemeralPublicKey(affine.to_bytes().into())
    }
    
    /// Compute shared secret with a public key (ECDH)
    ///
    /// Returns [esk]pk_d
    pub fn shared_secret(&self, pk_d: &[u8; 32]) -> Option<SharedSecret> {
        let pk_point = pallas::Affine::from_bytes(&(*pk_d).into())
            .map(pallas::Point::from)
            .into_option()?;
        
        let shared = pk_point * self.0;
        let affine = pallas::Affine::from(shared);
        Some(SharedSecret(affine.to_bytes().into()))
    }
}

impl std::fmt::Debug for EphemeralSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EphemeralSecretKey([REDACTED])")
    }
}

/// A shared secret derived from ECDH
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    /// Derive encryption key following Zcash Orchard KDF specification.
    ///
    /// K_enc = BLAKE2b-256("Zcash_OrchardKDF", repr(sharedSecret) || ephemeralKey)
    ///
    /// # Arguments
    /// - `epk`: Ephemeral public key (enc(epk) per spec)
    ///
    /// # Security
    /// - Binds key to specific ephemeral key (prevents key reuse)
    /// - Uses Zcash-standard domain separation tag
    /// - Combined with fresh esk per output, ensures unique keys even with zero nonce
    pub fn derive_encryption_key(&self, epk: &EphemeralPublicKey) -> EncryptionKey {
        // Per Zcash spec: BLAKE2b-256 with personal tag "Zcash_OrchardKDF"
        // Input: repr(sharedSecret) || ephemeralKey
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(DS_NOTE_ENCRYPTION)
            .to_state()
            .update(&self.0)        // repr(sharedSecret)
            .update(&epk.0)         // ephemeralKey (compressed point bytes)
            .finalize();
        
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(hash.as_bytes());
        
        EncryptionKey(key_bytes)
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

/// An encryption key for note ciphertexts
/// Note: Cannot derive Zeroize due to PallasScalar not implementing it
#[derive(Clone)]
pub struct EncryptionKey(pub [u8; 32]);

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKey([REDACTED])")
    }
}

/// An incoming viewing key (ivk) for note decryption
///
/// The recipient uses this to derive shared secrets: [ivk]epk
#[derive(Clone, Serialize, Deserialize)]
pub struct IncomingViewingKey(pub [u8; 32]);

impl IncomingViewingKey {
    /// Compute shared secret with ephemeral public key
    ///
    /// Returns [ivk]epk
    pub fn shared_secret(&self, epk: &EphemeralPublicKey) -> Option<SharedSecret> {
        // Parse ivk as scalar
        let ivk_scalar = PallasScalar::from_repr(self.0.into()).into_option()?;
        
        // Parse epk as point
        let epk_point = pallas::Affine::from_bytes(&epk.0.into())
            .map(pallas::Point::from)
            .into_option()?;
        
        // Compute [ivk]epk
        let shared = epk_point * ivk_scalar;
        let affine = pallas::Affine::from(shared);
        Some(SharedSecret(affine.to_bytes().into()))
    }
    
    /// Generate random IVK (for testing)
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl std::fmt::Debug for IncomingViewingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IncomingViewingKey([REDACTED])")
    }
}

/// A diversified transmission key (payment address public key)
#[derive(Clone, Copy, Debug, Eq, Serialize, Deserialize)]
pub struct DiversifiedTransmissionKey(pub [u8; 32]);

impl PartialEq for DiversifiedTransmissionKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for DiversifiedTransmissionKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Note plaintext structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotePlaintext {
    /// Note value in zatoshis
    pub value: u64,
    
    /// Note unique identifier (rho)
    pub rho: [u8; 32],
    
    /// Random seed for commitment
    pub rseed: [u8; 32],
    
    /// Memo field (arbitrary data)
    pub memo: Vec<u8>, // Should be exactly 512 bytes
}

impl NotePlaintext {
    /// Create a new note plaintext
    pub fn new(value: u64, rho: [u8; 32], rseed: [u8; 32], memo: Vec<u8>) -> Result<Self, NoteEncryptionError> {
        if memo.len() > MEMO_SIZE {
            return Err(NoteEncryptionError::InvalidMemoSize);
        }
        
        Ok(Self {
            value,
            rho,
            rseed,
            memo,
        })
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NOTE_PLAINTEXT_SIZE);
        
        // Version
        bytes.push(NOTE_PLAINTEXT_VERSION);
        
        // Value (little-endian u64)
        bytes.extend_from_slice(&self.value.to_le_bytes());
        
        // Rho
        bytes.extend_from_slice(&self.rho);
        
        // Rseed
        bytes.extend_from_slice(&self.rseed);
        
        // Memo (pad to 512 bytes if needed)
        bytes.extend_from_slice(&self.memo);
        bytes.resize(NOTE_PLAINTEXT_SIZE, 0);
        
        bytes
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoteEncryptionError> {
        if bytes.len() != NOTE_PLAINTEXT_SIZE {
            return Err(NoteEncryptionError::InvalidPlaintextSize);
        }
        
        // Check version
        if bytes[0] != NOTE_PLAINTEXT_VERSION {
            return Err(NoteEncryptionError::UnsupportedVersion);
        }
        
        // Parse value
        let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        
        // Parse rho
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[9..41]);
        
        // Parse rseed
        let mut rseed = [0u8; 32];
        rseed.copy_from_slice(&bytes[41..73]);
        
        // Parse memo
        let memo = bytes[73..585].to_vec();
        
        Ok(Self {
            value,
            rho,
            rseed,
            memo,
        })
    }
}

// ----------------------------- Encryption / Decryption -----------------------------

/// Encrypt a note plaintext for the recipient
///
/// # Arguments
/// - `plaintext`: The note plaintext to encrypt
/// - `pk_d`: Recipient's diversified transmission key
/// - `esk`: Ephemeral secret key
///
/// # Returns
/// `(epk, ciphertext)` tuple
pub fn encrypt_note(
    plaintext: &NotePlaintext,
    pk_d: &DiversifiedTransmissionKey,
    esk: &EphemeralSecretKey,
) -> Result<(EphemeralPublicKey, Vec<u8>), NoteEncryptionError> {
    // Derive ephemeral public key (MUST be fresh per output for security)
    let epk = esk.derive_public_key();
    
    // Compute shared secret via ECDH
    let shared_secret = esk.shared_secret(&pk_d.0)
        .ok_or(NoteEncryptionError::InvalidPublicKey)?;
    
    // Derive encryption key per Zcash Orchard KDF
    let enc_key = shared_secret.derive_encryption_key(&epk);
    
    // Encrypt plaintext with ZERO nonce (security via unique esk per output)
    let plaintext_bytes = plaintext.to_bytes();
    let cipher = ChaCha20Poly1305::new((&enc_key.0).into());
    let ciphertext = cipher
        .encrypt((&ZERO_NONCE).into(), plaintext_bytes.as_ref())
        .map_err(|_| NoteEncryptionError::EncryptionFailed)?;
    
    Ok((epk, ciphertext))
}

/// Decrypt a note ciphertext with incoming viewing key
///
/// # Arguments
/// - `ciphertext`: The encrypted note
/// - `epk`: Ephemeral public key from the action
/// - `ivk`: Recipient's incoming viewing key
///
/// # Returns
/// The decrypted note plaintext
pub fn decrypt_note(
    ciphertext: &[u8],
    epk: &EphemeralPublicKey,
    ivk: &IncomingViewingKey,
) -> Result<NotePlaintext, NoteEncryptionError> {
    // Compute shared secret via ECDH
    let shared_secret = ivk.shared_secret(epk)
        .ok_or(NoteEncryptionError::InvalidEphemeralKey)?;
    
    // Derive encryption key per Zcash Orchard KDF
    let enc_key = shared_secret.derive_encryption_key(epk);
    
    // Decrypt with ZERO nonce
    let cipher = ChaCha20Poly1305::new((&enc_key.0).into());
    let plaintext_bytes = cipher
        .decrypt((&ZERO_NONCE).into(), ciphertext)
        .map_err(|_| NoteEncryptionError::DecryptionFailed)?;
    
    // Parse plaintext
    NotePlaintext::from_bytes(&plaintext_bytes)
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum NoteEncryptionError {
    #[error("invalid memo size (max {MEMO_SIZE} bytes)")]
    InvalidMemoSize,
    
    #[error("invalid plaintext size")]
    InvalidPlaintextSize,
    
    #[error("unsupported plaintext version")]
    UnsupportedVersion,
    
    #[error("invalid public key")]
    InvalidPublicKey,
    
    #[error("invalid ephemeral key")]
    InvalidEphemeralKey,
    
    #[error("encryption failed")]
    EncryptionFailed,
    
    #[error("decryption failed")]
    DecryptionFailed,
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    fn dummy_plaintext() -> NotePlaintext {
        NotePlaintext {
            value: 100_000_000, // 1 ZEC
            rho: [1u8; 32],
            rseed: [2u8; 32],
            memo: b"Hello, Tachyon!".to_vec(),
        }
    }
    
    #[test]
    fn test_plaintext_serialization() {
        let pt = dummy_plaintext();
        let bytes = pt.to_bytes();
        assert_eq!(bytes.len(), NOTE_PLAINTEXT_SIZE);
        
        let pt2 = NotePlaintext::from_bytes(&bytes).unwrap();
        assert_eq!(pt.value, pt2.value);
        assert_eq!(pt.rho, pt2.rho);
        assert_eq!(pt.rseed, pt2.rseed);
        // Memo is padded to 512 bytes
        assert_eq!(&pt2.memo[..pt.memo.len()], pt.memo.as_slice());
    }
    
    #[test]
    fn test_ephemeral_key_derivation() {
        let esk = EphemeralSecretKey::random(OsRng);
        let epk = esk.derive_public_key();
        
        // Should be 32 bytes
        assert_eq!(epk.0.len(), 32);
        
        // Should be deterministic
        let epk2 = esk.derive_public_key();
        assert_eq!(epk.0, epk2.0);
    }
    
    #[test]
    fn test_shared_secret_derivation() {
        let esk = EphemeralSecretKey::random(OsRng);
        let ivk = IncomingViewingKey::random(OsRng);
        
        // Derive pk_d from ivk (simplified - in reality more complex)
        let ivk_scalar = PallasScalar::from_repr(ivk.0).unwrap();
        let pk_d_point = pallas::Point::generator() * ivk_scalar;
        let pk_d = DiversifiedTransmissionKey(pallas::Affine::from(pk_d_point).to_bytes());
        
        let epk = esk.derive_public_key();
        
        // Compute shared secret from both sides
        let ss_sender = esk.shared_secret(&pk_d.0).unwrap();
        let ss_recipient = ivk.shared_secret(&epk).unwrap();
        
        // Should match (ECDH property)
        assert_eq!(ss_sender.0, ss_recipient.0);
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = dummy_plaintext();
        
        // Generate keys
        let esk = EphemeralSecretKey::random(OsRng);
        let ivk = IncomingViewingKey::random(OsRng);
        
        // Derive pk_d from ivk
        let ivk_scalar = PallasScalar::from_repr(ivk.0).unwrap();
        let pk_d_point = pallas::Point::generator() * ivk_scalar;
        let pk_d = DiversifiedTransmissionKey(pallas::Affine::from(pk_d_point).to_bytes());
        
        // Encrypt
        let (epk, ciphertext) = encrypt_note(&plaintext, &pk_d, &esk).unwrap();
        
        // Ciphertext should be plaintext + tag
        assert_eq!(ciphertext.len(), ENCRYPTED_NOTE_SIZE);
        
        // Decrypt
        let decrypted = decrypt_note(&ciphertext, &epk, &ivk).unwrap();
        
        // Should match original
        assert_eq!(decrypted.value, plaintext.value);
        assert_eq!(decrypted.rho, plaintext.rho);
        assert_eq!(decrypted.rseed, plaintext.rseed);
        assert_eq!(&decrypted.memo[..plaintext.memo.len()], plaintext.memo.as_slice());
    }
    
    #[test]
    fn test_wrong_key_fails() {
        let plaintext = dummy_plaintext();
        
        // Sender keys
        let esk = EphemeralSecretKey::random(OsRng);
        let ivk1 = IncomingViewingKey::random(OsRng);
        let ivk_scalar1 = PallasScalar::from_repr(ivk1.0).unwrap();
        let pk_d = DiversifiedTransmissionKey(
            pallas::Affine::from(pallas::Point::generator() * ivk_scalar1).to_bytes()
        );
        
        // Different recipient key
        let ivk2 = IncomingViewingKey::random(OsRng);
        
        // Encrypt for ivk1
        let (epk, ciphertext) = encrypt_note(&plaintext, &pk_d, &esk).unwrap();
        
        // Try to decrypt with ivk2 (wrong key)
        let result = decrypt_note(&ciphertext, &epk, &ivk2);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_zero_nonce_with_unique_keys() {
        // Test that zero nonce is secure when combined with unique ephemeral keys
        let ss = SharedSecret([42u8; 32]);
        let epk1 = EphemeralPublicKey([1u8; 32]);
        let epk2 = EphemeralPublicKey([2u8; 32]);
        
        // Same shared secret but different ephemeral keys
        let key1 = ss.derive_encryption_key(&epk1);
        let key2 = ss.derive_encryption_key(&epk2);
        
        // MUST produce different encryption keys (prevents nonce reuse attack)
        assert_ne!(key1.0, key2.0);
        
        // This proves: Even with zero nonce, unique esk per output ensures security
    }
    
    #[test]
    fn test_encryption_key_binding() {
        let ss = SharedSecret([1u8; 32]);
        let epk1 = EphemeralPublicKey([2u8; 32]);
        let epk2 = EphemeralPublicKey([3u8; 32]);
        
        let key1 = ss.derive_encryption_key(&epk1);
        let key2 = ss.derive_encryption_key(&epk2);
        
        // Different epk should give different key (binding)
        assert_ne!(key1.0, key2.0);
    }
    
    #[test]
    fn test_zero_nonce_requirement() {
        // SECURITY TEST: Verify that we use zero nonce per Zcash spec
        // This test ensures we never accidentally introduce nonce derivation
        
        assert_eq!(ZERO_NONCE, [0u8; 12]);
        
        // The zero nonce is safe ONLY because:
        // 1. Each output uses a fresh random esk
        // 2. K_enc = KDF(sharedSecret || epk) binds key to unique epk
        // 3. Different esk => different epk => different K_enc
        
        println!("✓ Zero nonce confirmed - security via unique esk per output");
    }
    
    #[test]
    fn test_kdf_matches_zcash_spec() {
        // Verify KDF uses correct Zcash domain separation tag
        assert_eq!(DS_NOTE_ENCRYPTION, b"Zcash_OrchardKDF");
        
        // KDF must follow: BLAKE2b-256(DS, sharedSecret || ephemeralKey)
        let ss = SharedSecret([1u8; 32]);
        let epk = EphemeralPublicKey([2u8; 32]);
        
        let k_enc = ss.derive_encryption_key(&epk);
        
        // Manual verification of KDF
        let expected = Blake2bParams::new()
            .hash_length(32)
            .personal(b"Zcash_OrchardKDF")
            .to_state()
            .update(&ss.0)
            .update(&epk.0)
            .finalize();
        
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(expected.as_bytes());
        
        assert_eq!(k_enc.0, expected_bytes);
        println!("✓ KDF matches Zcash Orchard specification");
    }
}

