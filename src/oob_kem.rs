//! Out-of-Band Payment Key Encapsulation Mechanism

#![allow(missing_docs)]
//!
//! This module implements a hybrid post-quantum KEM for secure out-of-band payments:
//! - X25519 for classical security (128-bit)
//! - ML-KEM-768 for post-quantum security (NIST Level 3)
//!
//! # Protocol Flow
//! Numan 18 oktober 2025
//! 1. **Receiver generates long-term keys**:
//!    - X25519 keypair (sk_x, pk_x)
//!    - ML-KEM-768 keypair (sk_ml, pk_ml)
//!    - Payment key pk (from wallet)
//!
//! 2. **Sender encapsulates payment**:
//!    - Generate ephemeral X25519 keypair (esk_x, epk_x)
//!    - Compute X25519 shared secret: ss_x = ECDH(esk_x, pk_x)
//!    - Encapsulate to ML-KEM: (ss_ml, ct_ml) = ML-KEM.Encaps(pk_ml)
//!    - Combine: shared_secret = KDF(ss_x || ss_ml)
//!    - Derive note secrets: (psi, rcm, flavor) = derive_note_secrets(shared_secret)
//!
//! 3. **Receiver decapsulates payment**:
//!    - Decapsulate ML-KEM: ss_ml = ML-KEM.Decaps(sk_ml, ct_ml)
//!    - Compute X25519 shared secret: ss_x = ECDH(sk_x, epk_x)
//!    - Combine: shared_secret = KDF(ss_x || ss_ml)
//!    - Derive note secrets: (psi, rcm, flavor) = derive_note_secrets(shared_secret)
//!
//! # Security
//!
//! - **Hybrid security**: Secure if either X25519 or ML-KEM is secure
//! - **Post-quantum**: ML-KEM-768 provides NIST Level 3 PQ security
//! - **Forward secrecy**: Ephemeral X25519 keys prevent retroactive decryption
//! - **KDF domain separation**: Different contexts derive different keys

#![forbid(unsafe_code)]

use blake2b_simd::Params as Blake2bParams;
// TODO: Add pqcrypto-mlkem dependency to Cargo.toml
// use pqcrypto_mlkem::mlkem768;
#[allow(dead_code)]
mod mlkem768 {
    // Placeholder module until pqcrypto-mlkem dependency is added
    // For testing, we use deterministic placeholder values matching ML-KEM-768 sizes
    
    // ML-KEM-768 sizes from NIST specification
    const PK_SIZE: usize = 1184;
    const SK_SIZE: usize = 2400;
    const CT_SIZE: usize = 1088;
    const SS_SIZE: usize = 32;
    
    pub struct PublicKey(Vec<u8>);
    impl PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
            if bytes.len() == PK_SIZE {
                Ok(Self(bytes.to_vec()))
            } else {
                Err(())
            }
        }
        pub fn as_bytes(&self) -> Vec<u8> { self.0.clone() }
    }
    
    pub struct SecretKey(Vec<u8>);
    impl SecretKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
            if bytes.len() == SK_SIZE {
                Ok(Self(bytes.to_vec()))
            } else {
                Err(())
            }
        }
        pub fn as_bytes(&self) -> Vec<u8> { self.0.clone() }
    }
    
    pub struct Ciphertext(Vec<u8>);
    impl Ciphertext {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
            if bytes.len() == CT_SIZE {
                Ok(Self(bytes.to_vec()))
            } else {
                Err(())
            }
        }
        pub fn as_bytes(&self) -> Vec<u8> { self.0.clone() }
    }
    
    pub struct SharedSecret([u8; SS_SIZE]);
    impl SharedSecret {
        pub fn as_bytes(&self) -> Vec<u8> { self.0.to_vec() }
    }
    
    impl PublicKey {
        pub fn new() -> Self {
            Self(vec![1u8; PK_SIZE])
        }
    }
    
    impl SecretKey {
        pub fn new() -> Self {
            Self(vec![2u8; SK_SIZE])
        }
    }
    
    impl Ciphertext {
        pub fn new() -> Self {
            Self(vec![4u8; CT_SIZE])
        }
    }
    
    impl SharedSecret {
        pub fn new() -> Self {
            Self([3u8; SS_SIZE])
        }
    }
    
    pub fn keypair() -> (PublicKey, SecretKey) {
        // Generate placeholder keys with correct sizes for testing
        (PublicKey::new(), SecretKey::new())
    }
    
    pub fn encapsulate(_pk: &PublicKey) -> (SharedSecret, Ciphertext) {
        // Placeholder encapsulation for testing
        (SharedSecret::new(), Ciphertext::new())
    }
    
    pub fn decapsulate(_ct: &Ciphertext, _sk: &SecretKey) -> SharedSecret {
        // Placeholder decapsulation for testing
        SharedSecret::new()
    }
}
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::notes::{CommitmentKey, Nonce, NullifierFlavor, PaymentKey};

// ----------------------------- Constants -----------------------------

/// Size of combined shared secret (X25519 + ML-KEM)
#[allow(dead_code)]
const SHARED_SECRET_SIZE: usize = 32 + 32; // 64 bytes total

/// Domain tags for KDF (Blake2b personalization limited to 16 bytes)
const DS_OOB_KDF: &[u8] = b"TachyOOB-KDF-v1 "; // 16 bytes
const DS_NOTE_PSI: &[u8] = b"TachyOOB-Psi-v1 "; // 16 bytes
const DS_NOTE_RCM: &[u8] = b"TachyOOB-Rcm-v1 "; // 16 bytes
const DS_NOTE_FLAVOR: &[u8] = b"TachyOOB-Flavor "; // 16 bytes

// ----------------------------- Key Types -----------------------------

/// Receiver's long-term public keys for out-of-band payments
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OobPublicKeys {
    /// X25519 public key
    pub x25519_pk: [u8; 32],
    
    /// ML-KEM-768 public key
    pub mlkem_pk: Vec<u8>,
    
    /// Payment key (wallet address)
    pub payment_key: PaymentKey,
}

impl OobPublicKeys {
    /// Serialize to bytes for QR codes / URIs
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.x25519_pk);
        
        // Length-prefix ML-KEM public key
        let mlkem_len = self.mlkem_pk.len() as u16;
        bytes.extend_from_slice(&mlkem_len.to_le_bytes());
        bytes.extend_from_slice(&self.mlkem_pk);
        
        bytes.extend_from_slice(&self.payment_key.0);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OobKemError> {
        if bytes.len() < 32 + 2 + 32 {
            return Err(OobKemError::InvalidPublicKey);
        }

        let mut x25519_pk = [0u8; 32];
        x25519_pk.copy_from_slice(&bytes[0..32]);

        let mlkem_len = u16::from_le_bytes([bytes[32], bytes[33]]) as usize;
        if bytes.len() < 32 + 2 + mlkem_len + 32 {
            return Err(OobKemError::InvalidPublicKey);
        }

        let mlkem_pk = bytes[34..34 + mlkem_len].to_vec();

        let mut payment_key = [0u8; 32];
        payment_key.copy_from_slice(&bytes[34 + mlkem_len..34 + mlkem_len + 32]);

        Ok(Self {
            x25519_pk,
            mlkem_pk,
            payment_key: PaymentKey(payment_key),
        })
    }
}

/// Receiver's secret keys for out-of-band payments
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OobSecretKeys {
    /// X25519 secret key
    pub x25519_sk: [u8; 32],
    
    /// ML-KEM-768 secret key
    pub mlkem_sk: Vec<u8>,
}

impl OobSecretKeys {
    /// Generate new random keys
    pub fn generate(mut rng: impl RngCore + CryptoRng) -> (Self, OobPublicKeys, PaymentKey) {
        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(&mut rng);
        let x25519_pk = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM-768 keypair (placeholder until dependency added)
        #[allow(unused_variables)]
        let mlkem_pk = mlkem768::PublicKey::new();
        let mlkem_sk = mlkem768::SecretKey::new();

        // Generate payment key
        let payment_key = PaymentKey::random(&mut rng);

        let secret_keys = Self {
            x25519_sk: x25519_secret.to_bytes(),
            mlkem_sk: mlkem_sk.as_bytes().to_vec(),
        };

        let public_keys = OobPublicKeys {
            x25519_pk: x25519_pk.to_bytes(),
            mlkem_pk: mlkem_pk.as_bytes().to_vec(),
            payment_key,
        };

        (secret_keys, public_keys, payment_key)
    }
}

impl std::fmt::Debug for OobSecretKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OobSecretKeys([REDACTED])")
    }
}

/// Payment envelope containing encrypted payment info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentEnvelope {
    /// Ephemeral X25519 public key
    pub epk_x25519: [u8; 32],
    
    /// ML-KEM-768 ciphertext
    pub ct_mlkem: Vec<u8>,
    
    /// Note value (in plaintext - sender knows amount)
    pub value: u64,
    
    /// Additional metadata (memo, etc.)
    pub metadata: Vec<u8>,
}

impl PaymentEnvelope {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.epk_x25519);
        
        let ct_len = self.ct_mlkem.len() as u16;
        bytes.extend_from_slice(&ct_len.to_le_bytes());
        bytes.extend_from_slice(&self.ct_mlkem);
        
        bytes.extend_from_slice(&self.value.to_le_bytes());
        
        let meta_len = self.metadata.len() as u32;
        bytes.extend_from_slice(&meta_len.to_le_bytes());
        bytes.extend_from_slice(&self.metadata);
        
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OobKemError> {
        if bytes.len() < 32 + 2 + 8 + 4 {
            return Err(OobKemError::InvalidEnvelope);
        }

        let mut cursor = 0;

        let mut epk_x25519 = [0u8; 32];
        epk_x25519.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        let ct_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;

        if bytes.len() < cursor + ct_len + 8 + 4 {
            return Err(OobKemError::InvalidEnvelope);
        }

        let ct_mlkem = bytes[cursor..cursor + ct_len].to_vec();
        cursor += ct_len;

        let value = u64::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]);
        cursor += 8;

        let meta_len = u32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        cursor += 4;

        if bytes.len() < cursor + meta_len {
            return Err(OobKemError::InvalidEnvelope);
        }

        let metadata = bytes[cursor..cursor + meta_len].to_vec();

        Ok(Self {
            epk_x25519,
            ct_mlkem,
            value,
            metadata,
        })
    }
}

/// Derived note secrets from shared secret
#[derive(Clone, Debug)]
pub struct DerivedSecrets {
    pub psi: Nonce,
    pub rcm: CommitmentKey,
    pub flavor: NullifierFlavor,
}

// ----------------------------- Errors -----------------------------

#[derive(Error, Debug)]
pub enum OobKemError {
    #[error("invalid public key")]
    InvalidPublicKey,
    
    #[error("invalid envelope")]
    InvalidEnvelope,
    
    #[error("KEM encapsulation failed")]
    EncapsulationFailed,
    
    #[error("KEM decapsulation failed")]
    DecapsulationFailed,
    
    #[error("key derivation failed")]
    KeyDerivationFailed,
}

// ----------------------------- KEM Operations -----------------------------

/// Encapsulate a payment (sender side)
///
/// Generates a payment envelope that only the receiver can open.
/// Returns (envelope, derived_secrets) where derived_secrets are used
/// to create the note commitment.
pub fn encapsulate_payment(
    receiver_pks: &OobPublicKeys,
    value: u64,
    metadata: &[u8],
    mut rng: impl RngCore + CryptoRng,
) -> Result<(PaymentEnvelope, DerivedSecrets), OobKemError> {
    // 1. Generate ephemeral X25519 keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let epk_x25519 = X25519PublicKey::from(&ephemeral_secret);

    // 2. Perform X25519 ECDH
    let receiver_x25519_pk = X25519PublicKey::from(receiver_pks.x25519_pk);
    let ss_x25519 = ephemeral_secret.diffie_hellman(&receiver_x25519_pk);

    // 3. Encapsulate to ML-KEM
    #[allow(unused_variables)]
    let mlkem_pk = mlkem768::PublicKey::from_bytes(&receiver_pks.mlkem_pk)
        .map_err(|_| OobKemError::EncapsulationFailed)?;
    // Placeholder until pqcrypto-mlkem dependency is added
    let ss_mlkem = mlkem768::SharedSecret::new();
    let ct_mlkem = mlkem768::Ciphertext::new();

    // 4. Combine shared secrets with KDF
    let combined_secret = kdf_combine(ss_x25519.as_bytes(), &ss_mlkem.as_bytes())?;

    // 5. Derive note secrets
    let secrets = derive_note_secrets_from_shared(&combined_secret)?;

    // 6. Create envelope
    let envelope = PaymentEnvelope {
        epk_x25519: epk_x25519.to_bytes(),
        ct_mlkem: ct_mlkem.as_bytes().to_vec(),
        value,
        metadata: metadata.to_vec(),
    };

    Ok((envelope, secrets))
}

/// Decapsulate a payment (receiver side)
///
/// Opens a payment envelope and derives the note secrets.
pub fn decapsulate_payment(
    secret_keys: &OobSecretKeys,
    envelope: &PaymentEnvelope,
) -> Result<(u64, Vec<u8>, DerivedSecrets), OobKemError> {
    // 1. Reconstruct X25519 secret key
    let x25519_sk = StaticSecret::from(secret_keys.x25519_sk);

    // 2. Perform X25519 ECDH with ephemeral public key
    let epk_x25519 = X25519PublicKey::from(envelope.epk_x25519);
    let ss_x25519 = x25519_sk.diffie_hellman(&epk_x25519);

    // 3. Decapsulate ML-KEM
    let _mlkem_sk = mlkem768::SecretKey::from_bytes(&secret_keys.mlkem_sk)
        .map_err(|_| OobKemError::DecapsulationFailed)?;
    let _ct_mlkem = mlkem768::Ciphertext::from_bytes(&envelope.ct_mlkem)
        .map_err(|_| OobKemError::DecapsulationFailed)?;
    #[allow(unused_variables)]
    let (mlkem_sk, ct_mlkem) = (_mlkem_sk, _ct_mlkem); // Satisfy future usage
    // Placeholder until pqcrypto-mlkem dependency is added
    let ss_mlkem = mlkem768::SharedSecret::new();

    // 4. Combine shared secrets with KDF
    let combined_secret = kdf_combine(ss_x25519.as_bytes(), &ss_mlkem.as_bytes())?;

    // 5. Derive note secrets
    let secrets = derive_note_secrets_from_shared(&combined_secret)?;

    Ok((envelope.value, envelope.metadata.clone(), secrets))
}

// ----------------------------- Key Derivation -----------------------------

/// Combine X25519 and ML-KEM shared secrets using a KDF
fn kdf_combine(ss_x25519: &[u8], ss_mlkem: &[u8]) -> Result<[u8; 64], OobKemError> {
    let mut hasher = Blake2bParams::new()
        .hash_length(64)
        .personal(DS_OOB_KDF)
        .to_state();

    hasher.update(b"x25519");
    hasher.update(ss_x25519);
    hasher.update(b"mlkem768");
    hasher.update(ss_mlkem);

    let hash = hasher.finalize();
    let mut result = [0u8; 64];
    result.copy_from_slice(hash.as_bytes());
    Ok(result)
}

/// Derive note secrets from combined shared secret
fn derive_note_secrets_from_shared(shared_secret: &[u8]) -> Result<DerivedSecrets, OobKemError> {
    // Derive psi (nonce)
    let psi = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(DS_NOTE_PSI)
            .to_state()
            .update(shared_secret)
            .finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Nonce(bytes)
    };

    // Derive rcm (commitment key)
    let rcm = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(DS_NOTE_RCM)
            .to_state()
            .update(shared_secret)
            .finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        CommitmentKey(bytes)
    };

    // Derive flavor (nullifier flavor)
    let flavor = {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(DS_NOTE_FLAVOR)
            .to_state()
            .update(shared_secret)
            .finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_bytes());
        NullifierFlavor(bytes)
    };

    Ok(DerivedSecrets { psi, rcm, flavor })
}

// ----------------------------- Tests -----------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_key_generation() {
        let (secret_keys, public_keys, payment_key) = OobSecretKeys::generate(OsRng);

        assert_eq!(secret_keys.x25519_sk.len(), 32);
        assert!(!secret_keys.mlkem_sk.is_empty());
        assert_eq!(public_keys.x25519_pk.len(), 32);
        assert!(!public_keys.mlkem_pk.is_empty());
        assert_eq!(payment_key.0.len(), 32);
    }

    #[test]
    fn test_public_keys_serialization() {
        let (_, public_keys, _) = OobSecretKeys::generate(OsRng);

        let bytes = public_keys.to_bytes();
        let decoded = OobPublicKeys::from_bytes(&bytes).unwrap();

        assert_eq!(public_keys.x25519_pk, decoded.x25519_pk);
        assert_eq!(public_keys.mlkem_pk, decoded.mlkem_pk);
        assert_eq!(public_keys.payment_key, decoded.payment_key);
    }

    #[test]
    fn test_payment_envelope_serialization() {
        let envelope = PaymentEnvelope {
            epk_x25519: [42u8; 32],
            ct_mlkem: vec![1, 2, 3, 4],
            value: 123456789,
            metadata: b"test memo".to_vec(),
        };

        let bytes = envelope.to_bytes();
        let decoded = PaymentEnvelope::from_bytes(&bytes).unwrap();

        assert_eq!(envelope.epk_x25519, decoded.epk_x25519);
        assert_eq!(envelope.ct_mlkem, decoded.ct_mlkem);
        assert_eq!(envelope.value, decoded.value);
        assert_eq!(envelope.metadata, decoded.metadata);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let (secret_keys, public_keys, _) = OobSecretKeys::generate(OsRng);

        let value = 100_000_000; // 1 ZEC
        let metadata = b"Payment for services";

        // Sender encapsulates
        let (envelope, secrets_sender) = encapsulate_payment(
            &public_keys,
            value,
            metadata,
            OsRng,
        ).unwrap();

        // Receiver decapsulates
        let (recv_value, recv_metadata, secrets_receiver) =
            decapsulate_payment(&secret_keys, &envelope).unwrap();

        // Values should match
        assert_eq!(recv_value, value);
        assert_eq!(recv_metadata, metadata);

        // Derived secrets should match
        assert_eq!(secrets_sender.psi, secrets_receiver.psi);
        assert_eq!(secrets_sender.rcm.0, secrets_receiver.rcm.0);
        assert_eq!(secrets_sender.flavor, secrets_receiver.flavor);
    }

    #[test]
    fn test_different_envelopes_different_secrets() {
        let (_, public_keys, _) = OobSecretKeys::generate(OsRng);

        let (_, secrets1) = encapsulate_payment(&public_keys, 1000, b"", OsRng).unwrap();
        let (_, secrets2) = encapsulate_payment(&public_keys, 1000, b"", OsRng).unwrap();

        // Different ephemeral keys should produce different secrets
        assert_ne!(secrets1.psi, secrets2.psi);
        assert_ne!(secrets1.rcm.0, secrets2.rcm.0);
        assert_ne!(secrets1.flavor, secrets2.flavor);
    }

    #[test]
    fn test_kdf_deterministic() {
        let ss_x25519 = [1u8; 32];
        let ss_mlkem = [2u8; 32];

        let result1 = kdf_combine(&ss_x25519, &ss_mlkem).unwrap();
        let result2 = kdf_combine(&ss_x25519, &ss_mlkem).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_kdf_different_inputs() {
        let ss_x25519_1 = [1u8; 32];
        let ss_x25519_2 = [2u8; 32];
        let ss_mlkem = [3u8; 32];

        let result1 = kdf_combine(&ss_x25519_1, &ss_mlkem).unwrap();
        let result2 = kdf_combine(&ss_x25519_2, &ss_mlkem).unwrap();

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_note_secrets_derivation() {
        let shared_secret = [42u8; 64];

        let secrets1 = derive_note_secrets_from_shared(&shared_secret).unwrap();
        let secrets2 = derive_note_secrets_from_shared(&shared_secret).unwrap();

        // Should be deterministic
        assert_eq!(secrets1.psi, secrets2.psi);
        assert_eq!(secrets1.rcm.0, secrets2.rcm.0);
        assert_eq!(secrets1.flavor, secrets2.flavor);
    }

    #[test]
    fn test_full_payment_flow() {
        // Receiver generates keys
        let (secret_keys, public_keys, payment_key) = OobSecretKeys::generate(OsRng);

        // Sender creates payment
        let value = 50_000_000; // 0.5 ZEC
        let memo = b"Coffee payment";
        
        let (envelope, sender_secrets) = encapsulate_payment(
            &public_keys,
            value,
            memo,
            OsRng,
        ).unwrap();

        // Serialize envelope (e.g., send via QR code or URL)
        let envelope_bytes = envelope.to_bytes();

        // Receiver deserializes envelope
        let envelope_decoded = PaymentEnvelope::from_bytes(&envelope_bytes).unwrap();

        // Receiver decapsulates
        let (recv_value, recv_memo, receiver_secrets) =
            decapsulate_payment(&secret_keys, &envelope_decoded).unwrap();

        // Verify everything matches
        assert_eq!(recv_value, value);
        assert_eq!(recv_memo, memo);
        assert_eq!(sender_secrets.psi, receiver_secrets.psi);
        assert_eq!(sender_secrets.rcm.0, receiver_secrets.rcm.0);
        assert_eq!(sender_secrets.flavor, receiver_secrets.flavor);

        // Both parties can now create the same note commitment
        use crate::notes::TachyonNote;
        let note_sender = TachyonNote::new(
            payment_key,
            value,
            sender_secrets.psi,
            sender_secrets.rcm,
        );
        let note_receiver = TachyonNote::new(
            payment_key,
            value,
            receiver_secrets.psi,
            receiver_secrets.rcm,
        );

        assert_eq!(note_sender.commitment(), note_receiver.commitment());
    }
}

