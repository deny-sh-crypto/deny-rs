//! # deny-sh
//!
//! Deniable encryption library — algorithm-compatible with the TypeScript and Python deny.sh SDKs.
//!
//! ## Algorithm
//!
//! **Encrypt:**
//! 1. Derive AES-256 key from password1 + password2 via scrypt
//! 2. Prepend 4-byte LE plaintext length to plaintext (inside encrypted zone)
//! 3. XOR (length + plaintext) with control data
//! 4. AES-256-CTR encrypt the result
//! 5. Prepend: salt (32 bytes) + IV (16 bytes) as unencrypted header
//!
//! **Decrypt:**
//! 1. Extract salt + IV from header
//! 2. Re-derive AES-256 key from passwords + salt
//! 3. AES-256-CTR decrypt payload
//! 4. XOR with control data
//! 5. Read 4-byte length prefix, trim plaintext to that length
//!
//! **Deniable decryption:**
//! Given ciphertext + passwords + desired fake plaintext:
//! 1. AES decrypt to get intermediate (= length+plaintext XOR controlData)
//! 2. Construct fake payload = 4-byte-length(fake) + fake plaintext + random padding
//! 3. New control data = intermediate XOR fake payload
//! 4. Now decrypting with new control file produces the fake plaintext

use aes::Aes256;
use cipher::generic_array::GenericArray;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

// --- Constants ---

/// Salt length in bytes
pub const SALT_LENGTH: usize = 32;
/// IV length in bytes
pub const IV_LENGTH: usize = 16;
/// AES-256 key length in bytes
pub const KEY_LENGTH: usize = 32;
/// Header length: salt + IV
pub const HEADER_LENGTH: usize = SALT_LENGTH + IV_LENGTH; // 48
/// Length prefix size (4-byte little-endian u32)
const LENGTH_PREFIX: usize = 4;

// scrypt parameters
const SCRYPT_LOG_N: u8 = 14; // N = 2^14 = 16384
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

// --- Error types ---

#[derive(Debug, Error)]
pub enum Error {
    #[error("Control data ({control_len} bytes) must be >= plaintext + 4 bytes ({required} bytes)")]
    ControlDataTooShort { control_len: usize, required: usize },

    #[error("Ciphertext too short - missing header")]
    CiphertextTooShort,

    #[error("Desired plaintext ({plaintext_len} bytes) is too long for this ciphertext")]
    PlaintextTooLong { plaintext_len: usize },

    #[error("Payload too short")]
    PayloadTooShort,

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
}

// --- Type alias for AES-256-CTR ---
//
// Node.js crypto and PyCryptodome both use a big-endian 128-bit counter
// that starts from the full IV value. The `ctr` crate's Ctr128BE does the same.
type Aes256Ctr = Ctr128BE<Aes256>;

// --- Key Derivation ---

/// Derive AES-256 key from two passwords using scrypt.
///
/// Combines both passwords via SHA-256 hashing to avoid length ambiguities:
/// `scrypt(SHA-256(pw1) || SHA-256(pw2), salt, ...)`
pub fn derive_key(password1: &str, password2: &str, salt: &[u8]) -> Vec<u8> {
    // SHA-256 each password
    let pw1_hash = Sha256::digest(password1.as_bytes());
    let pw2_hash = Sha256::digest(password2.as_bytes());

    // Concatenate: pw1_hash || pw2_hash (64 bytes)
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&pw1_hash);
    combined.extend_from_slice(&pw2_hash);

    // scrypt KDF
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, KEY_LENGTH)
        .expect("valid scrypt params");
    let mut key = vec![0u8; KEY_LENGTH];
    scrypt::scrypt(&combined, salt, &params, &mut key).expect("scrypt derivation");
    key
}

// --- Control Data ---

/// Generate cryptographically secure random control data.
pub fn generate_control_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut data);
    data
}

// --- Internal helpers ---

/// XOR two byte slices. Returns a Vec of length min(a.len(), b.len()).
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().min(b.len());
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(a[i] ^ b[i]);
    }
    result
}

/// Build the inner payload: 4-byte LE length prefix + data.
fn build_payload(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut payload = Vec::with_capacity(LENGTH_PREFIX + data.len());
    payload.extend_from_slice(&len.to_le_bytes());
    payload.extend_from_slice(data);
    payload
}

/// Extract plaintext from inner payload (4-byte LE length + data).
fn extract_payload(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() < LENGTH_PREFIX {
        return Err(Error::PayloadTooShort);
    }
    let length = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if length > payload.len() - LENGTH_PREFIX {
        // Length exceeds available data — likely wrong password or control file
        return Ok(payload[LENGTH_PREFIX..].to_vec());
    }
    Ok(payload[LENGTH_PREFIX..LENGTH_PREFIX + length].to_vec())
}

// --- Core Encryption ---

/// Encrypt plaintext using dual passwords and a control file.
///
/// If `control_data` is `None`, random control data is generated.
///
/// Returns `(ciphertext, control_data)` where ciphertext format is:
/// `salt(32) + iv(16) + AES-256-CTR(length_prefix + plaintext XOR control_data)`
pub fn encrypt(
    plaintext: &[u8],
    password1: &str,
    password2: &str,
    control_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Build inner payload with length prefix
    let payload = build_payload(plaintext);

    // Generate or validate control data
    let control: Vec<u8> = match control_data {
        Some(cd) => {
            if cd.len() < payload.len() {
                return Err(Error::ControlDataTooShort {
                    control_len: cd.len(),
                    required: payload.len(),
                });
            }
            cd.to_vec()
        }
        None => generate_control_data(payload.len()),
    };

    // Generate random salt and IV
    let mut salt = [0u8; SALT_LENGTH];
    let mut iv = [0u8; IV_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut iv);

    // Derive key
    let key = derive_key(password1, password2, &salt);

    // XOR payload with control data (the deniability layer)
    let control_slice = &control[..payload.len()];
    let xored = xor_bytes(&payload, control_slice);

    // AES-256-CTR encrypt
    let mut cipher = Aes256Ctr::new(GenericArray::from_slice(&key), GenericArray::from_slice(&iv));
    let mut encrypted = xored;
    cipher.apply_keystream(&mut encrypted);

    // Pack: salt || iv || encrypted
    let mut result = Vec::with_capacity(HEADER_LENGTH + encrypted.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&encrypted);

    Ok((result, control))
}

/// Decrypt ciphertext using dual passwords and the original control file.
///
/// Returns the decrypted plaintext.
pub fn decrypt(
    ciphertext: &[u8],
    password1: &str,
    password2: &str,
    control_data: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < HEADER_LENGTH {
        return Err(Error::CiphertextTooShort);
    }

    // Extract header
    let salt = &ciphertext[..SALT_LENGTH];
    let iv = &ciphertext[SALT_LENGTH..HEADER_LENGTH];
    let encrypted_data = &ciphertext[HEADER_LENGTH..];

    // Derive key
    let key = derive_key(password1, password2, salt);

    // AES-256-CTR decrypt
    let mut cipher = Aes256Ctr::new(GenericArray::from_slice(&key), GenericArray::from_slice(&iv));
    let mut decrypted = encrypted_data.to_vec();
    cipher.apply_keystream(&mut decrypted);

    // XOR with control data to recover payload
    let control_slice = &control_data[..decrypted.len().min(control_data.len())];
    let payload = xor_bytes(&decrypted, control_slice);

    // Extract plaintext from payload
    extract_payload(&payload)
}

/// Generate a new control file that makes existing ciphertext decrypt
/// to a completely different plaintext.
///
/// Given:
/// - Original ciphertext (encrypted with password1 + password2 + original control data)
/// - The same passwords
/// - A desired fake plaintext
///
/// Returns new control data such that
/// `decrypt(ciphertext, pw1, pw2, new_control) == desired_plaintext`
pub fn generate_deniable_control(
    ciphertext: &[u8],
    password1: &str,
    password2: &str,
    desired_plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < HEADER_LENGTH {
        return Err(Error::CiphertextTooShort);
    }

    // Extract header
    let salt = &ciphertext[..SALT_LENGTH];
    let iv = &ciphertext[SALT_LENGTH..HEADER_LENGTH];
    let encrypted_data = &ciphertext[HEADER_LENGTH..];

    // Build fake payload with length prefix
    let fake_payload = build_payload(desired_plaintext);

    if fake_payload.len() > encrypted_data.len() {
        return Err(Error::PlaintextTooLong {
            plaintext_len: desired_plaintext.len(),
        });
    }

    // Derive key (same as used for encryption)
    let key = derive_key(password1, password2, salt);

    // AES decrypt to get intermediate (= original payload XOR original control data)
    let mut cipher = Aes256Ctr::new(GenericArray::from_slice(&key), GenericArray::from_slice(&iv));
    let mut intermediate = encrypted_data.to_vec();
    cipher.apply_keystream(&mut intermediate);

    // Pad fake payload to match intermediate length with random bytes
    let padded_fake = if fake_payload.len() < intermediate.len() {
        let mut padded = Vec::with_capacity(intermediate.len());
        padded.extend_from_slice(&fake_payload);
        let mut padding = vec![0u8; intermediate.len() - fake_payload.len()];
        rand::rngs::OsRng.fill_bytes(&mut padding);
        padded.extend_from_slice(&padding);
        padded
    } else {
        fake_payload
    };

    // New control data = intermediate XOR fake payload
    let new_control = xor_bytes(&intermediate, &padded_fake);

    Ok(new_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0u8; 32];
        let k1 = derive_key("pass1", "pass2", &salt);
        let k2 = derive_key("pass1", "pass2", &salt);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_xor_bytes() {
        let a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0, 0x55];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![0xF0, 0xF0, 0xFF]);
    }

    #[test]
    fn test_build_extract_payload() {
        let data = b"hello";
        let payload = build_payload(data);
        assert_eq!(payload.len(), 4 + 5);
        let extracted = extract_payload(&payload).unwrap();
        assert_eq!(extracted, data);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let msg = b"Meet Me At 2pm Tomorrow";
        let (ct, ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
        let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
        assert_eq!(pt, msg);
    }
}
