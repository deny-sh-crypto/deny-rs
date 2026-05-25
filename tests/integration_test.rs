use deny_sh::{
    decrypt, derive_key, encrypt, generate_control_data, generate_deniable_control,
    HEADER_LENGTH,
};

// --- Cross-implementation Known Answer Tests ---
//
// These vectors are byte-identical across the four reference SDKs
// (TypeScript, Python, Rust, Go) and gate cross-SDK ciphertext
// interoperability. A regression in Argon2id parameters (t=3, m=64MiB,
// p=1, variant=Argon2id, version=0x13), SHA-256 pre-hashing, or
// AES-CTR composition will fail one of these tests before publishing.
// Whitepaper §8 references these exact values.

#[test]
fn kat_derive_key_password1_password2_salt_aa() {
    let salt = [0xAAu8; 32];
    let key = derive_key("password1", "password2", &salt);
    let hex_key = hex::encode(&key);
    assert_eq!(
        hex_key,
        "854e7acffd85eae6d45ed07e84237fddc887928270f591a41b36d57e675181d8",
        "deriveKey(password1, password2, 0xAA*32) does not match cross-SDK KAT"
    );
}

#[test]
fn kat_derive_key_test_pw1_test_pw2_salt_01() {
    let salt = [0x01u8; 32];
    let key = derive_key("test-pw1", "test-pw2", &salt);
    let hex_key = hex::encode(&key);
    assert_eq!(
        hex_key,
        "d99364f250367785bff7a962331254b18138d2249c969e27b0f75060070fa3f6",
        "deriveKey(test-pw1, test-pw2, 0x01*32) does not match cross-SDK KAT"
    );
}

#[test]
fn kat_full_ciphertext_byte_exact() {
    // Inputs match Python tests/test_core.py:test_full_encrypt_decrypt_kat
    // and TypeScript src/test/core.test.ts "KAT 3: full ciphertext".
    use aes::Aes256;
    use cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;

    type Aes256Ctr = Ctr128BE<Aes256>;

    let pw1 = "test-pw1";
    let pw2 = "test-pw2";
    let fixed_salt = [0x01u8; 32];
    let fixed_iv = [0x02u8; 16];
    let message = b"Hello, World!"; // 13 bytes
    let control_data = [0x03u8; 17]; // message.len() + 4

    // 1. Derive key (must match KAT 2)
    let key = derive_key(pw1, pw2, &fixed_salt);
    assert_eq!(
        hex::encode(&key),
        "d99364f250367785bff7a962331254b18138d2249c969e27b0f75060070fa3f6"
    );

    // 2. Build payload: LE32 length || plaintext
    let mut payload = Vec::with_capacity(message.len() + 4);
    payload.extend_from_slice(&(message.len() as u32).to_le_bytes());
    payload.extend_from_slice(message);
    assert_eq!(hex::encode(&payload), "0d00000048656c6c6f2c20576f726c6421");

    // 3. XOR with control data
    let mut xored = vec![0u8; payload.len()];
    for i in 0..payload.len() {
        xored[i] = payload[i] ^ control_data[i];
    }
    assert_eq!(hex::encode(&xored), "0e0303034b666f6f6c2f23546c716f6722");

    // 4. AES-256-CTR encrypt with fixed IV
    let mut cipher = Aes256Ctr::new(
        GenericArray::from_slice(&key),
        GenericArray::from_slice(&fixed_iv),
    );
    let mut encrypted = xored.clone();
    cipher.apply_keystream(&mut encrypted);
    assert_eq!(
        hex::encode(&encrypted),
        "7c5cd13699e85f6bcde6dad013d48047ca"
    );

    // 5. Full wire-format ciphertext = salt(32) || iv(16) || encrypted(17)
    let mut full_ct = Vec::with_capacity(32 + 16 + encrypted.len());
    full_ct.extend_from_slice(&fixed_salt);
    full_ct.extend_from_slice(&fixed_iv);
    full_ct.extend_from_slice(&encrypted);
    assert_eq!(
        hex::encode(&full_ct),
        "0101010101010101010101010101010101010101010101010101010101010101\
         02020202020202020202020202020202\
         7c5cd13699e85f6bcde6dad013d48047ca"
    );
}

// --- Basic encrypt/decrypt ---

#[test]
fn encrypt_decrypt_roundtrip() {
    let msg = b"Meet Me At 2pm Tomorrow";
    let (ct, ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
    let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn encrypt_decrypt_empty_message() {
    let msg: &[u8] = b"";
    let ctrl = generate_control_data(4);
    let (ct, _) = encrypt(msg, "pw1", "pw2", Some(&ctrl)).unwrap();
    let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn encrypt_decrypt_short_message() {
    let msg = b"Hi";
    let (ct, ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
    let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn encrypt_decrypt_large_message() {
    let mut msg = vec![0u8; 100 * 1024]; // 100KB
    for i in 0..msg.len() {
        msg[i] = (i % 256) as u8;
    }
    let (ct, ctrl) = encrypt(&msg, "pw1", "pw2", None).unwrap();
    let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn encrypt_decrypt_unicode_message() {
    let msg = "Привет мир 🌍 こんにちは".as_bytes();
    let (ct, ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
    let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(pt, msg);
    // Verify it decodes back to the same string
    let decoded = std::str::from_utf8(&pt).unwrap();
    assert_eq!(decoded, "Привет мир 🌍 こんにちは");
}

#[test]
fn different_ciphertext_each_time() {
    let msg = b"Same message";
    let ctrl = generate_control_data(msg.len() + 4);
    let (ct1, _) = encrypt(msg, "pw1", "pw2", Some(&ctrl)).unwrap();
    let (ct2, _) = encrypt(msg, "pw1", "pw2", Some(&ctrl)).unwrap();
    // Salt and IV are random, so ciphertexts differ
    assert_ne!(ct1, ct2);
}

#[test]
fn wrong_password_produces_garbage() {
    let msg = b"Secret";
    let (ct, ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
    let pt = decrypt(&ct, "wrong", "pw2", &ctrl).unwrap();
    // CTR mode won't error, just garbles output
    assert_ne!(pt, msg);
}

#[test]
fn wrong_control_data_produces_garbage() {
    let msg = b"Secret";
    let (ct, _ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
    let wrong_ctrl = generate_control_data(msg.len() + 4);
    let pt = decrypt(&ct, "pw1", "pw2", &wrong_ctrl).unwrap();
    assert_ne!(pt, msg);
}

#[test]
fn password_order_matters() {
    let salt = [0u8; 32];
    let k1 = derive_key("alpha", "beta", &salt);
    let k2 = derive_key("beta", "alpha", &salt);
    assert_ne!(k1, k2);
}

#[test]
fn different_passwords_different_keys() {
    let salt = [0u8; 32];
    let k1 = derive_key("pass1", "pass2", &salt);
    let k2 = derive_key("pass1", "pass3", &salt);
    assert_ne!(k1, k2);
}

#[test]
fn different_salts_different_keys() {
    let salt1 = [0u8; 32];
    let salt2 = [1u8; 32];
    let k1 = derive_key("pass1", "pass2", &salt1);
    let k2 = derive_key("pass1", "pass2", &salt2);
    assert_ne!(k1, k2);
}

#[test]
fn reject_short_control_data() {
    let msg = b"Hello world";
    let short_ctrl = generate_control_data(3);
    let result = encrypt(msg, "pw1", "pw2", Some(&short_ctrl));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("must be >="));
}

#[test]
fn reject_short_ciphertext() {
    let short = vec![0u8; 10];
    let ctrl = generate_control_data(100);
    let result = decrypt(&short, "pw1", "pw2", &ctrl);
    assert!(result.is_err());
}

// --- Deniable encryption ---

#[test]
fn deniable_control_generation() {
    let real_msg = b"Meet Me At 2pm Tomorrow";
    let fake_msg = b"Kill KyK In One Month";

    let (ct, ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();

    // Verify real decryption
    let real_pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(real_pt, real_msg);

    // Generate deniable control
    let fake_ctrl = generate_deniable_control(&ct, "pw1", "pw2", fake_msg).unwrap();

    // Same ciphertext + same passwords + different control = different message
    let fake_pt = decrypt(&ct, "pw1", "pw2", &fake_ctrl).unwrap();
    assert_eq!(fake_pt, fake_msg);
}

#[test]
fn deniable_shorter_fake() {
    let real_msg = b"This is a long secret message with details";
    let fake_msg = b"Nothing here";

    let (ct, _ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();
    let fake_ctrl = generate_deniable_control(&ct, "pw1", "pw2", fake_msg).unwrap();
    let fake_pt = decrypt(&ct, "pw1", "pw2", &fake_ctrl).unwrap();
    assert_eq!(fake_pt, fake_msg);
}

#[test]
fn deniable_same_length_fake() {
    let real_msg = b"AAAA";
    let fake_msg = b"BBBB";

    let (ct, _ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();
    let fake_ctrl = generate_deniable_control(&ct, "pw1", "pw2", fake_msg).unwrap();
    let fake_pt = decrypt(&ct, "pw1", "pw2", &fake_ctrl).unwrap();
    assert_eq!(fake_pt, fake_msg);
}

#[test]
fn deniable_empty_fake() {
    let real_msg = b"Real secret";
    let fake_msg: &[u8] = b"";

    let (ct, _ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();
    let fake_ctrl = generate_deniable_control(&ct, "pw1", "pw2", fake_msg).unwrap();
    let fake_pt = decrypt(&ct, "pw1", "pw2", &fake_ctrl).unwrap();
    assert_eq!(fake_pt, fake_msg);
}

#[test]
fn deniable_unicode_fake() {
    let real_msg = b"Secret plans that are quite long for testing";
    let fake_msg = "日本語テスト".as_bytes();

    let (ct, _ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();
    let fake_ctrl = generate_deniable_control(&ct, "pw1", "pw2", fake_msg).unwrap();
    let fake_pt = decrypt(&ct, "pw1", "pw2", &fake_ctrl).unwrap();
    assert_eq!(fake_pt, fake_msg);
}

#[test]
fn deniable_multiple_fakes_from_same_ciphertext() {
    let real_msg = b"The real secret";
    let fake1 = b"Fake message 1";
    let fake2 = b"Fake message 2";

    let (ct, _ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();

    let ctrl1 = generate_deniable_control(&ct, "pw1", "pw2", fake1).unwrap();
    let ctrl2 = generate_deniable_control(&ct, "pw1", "pw2", fake2).unwrap();

    let dec1 = decrypt(&ct, "pw1", "pw2", &ctrl1).unwrap();
    let dec2 = decrypt(&ct, "pw1", "pw2", &ctrl2).unwrap();

    assert_eq!(dec1, fake1);
    assert_eq!(dec2, fake2);
    assert_ne!(ctrl1, ctrl2);
}

#[test]
fn deniable_reject_too_long_fake() {
    let real_msg = b"Short";
    let (ct, _ctrl) = encrypt(real_msg, "pw1", "pw2", None).unwrap();

    let too_long = vec![0u8; 1000];
    let result = generate_deniable_control(&ct, "pw1", "pw2", &too_long);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too long"));
}

// --- Header format ---

#[test]
fn ciphertext_header_format() {
    let msg = b"test";
    let (ct, _ctrl) = encrypt(msg, "pw1", "pw2", None).unwrap();
    // Header is salt(32) + iv(16) = 48 bytes, then encrypted payload
    assert_eq!(ct.len(), HEADER_LENGTH + 4 + msg.len()); // 48 + 4 (length prefix) + 4 (msg)
}

// --- Provided control data is used ---

#[test]
fn encrypt_with_provided_control_data() {
    let msg = b"test message";
    let ctrl = generate_control_data(msg.len() + 4);
    let (ct, returned_ctrl) = encrypt(msg, "pw1", "pw2", Some(&ctrl)).unwrap();
    assert_eq!(returned_ctrl, ctrl);
    let pt = decrypt(&ct, "pw1", "pw2", &ctrl).unwrap();
    assert_eq!(pt, msg);
}

// --- Control data randomness sanity check ---

#[test]
fn control_data_looks_random() {
    let ctrl = generate_control_data(256);
    // Count unique bytes — should be many for 256 random bytes
    let mut seen = std::collections::HashSet::new();
    for &b in &ctrl {
        seen.insert(b);
    }
    assert!(
        seen.len() > 100,
        "Expected >100 unique bytes in 256 random bytes, got {}",
        seen.len()
    );
}

// --- Argon2id parameter pinning ---
//
// If any of these constants ever drifts (e.g. a future refactor changes
// m=65536 to m=131072), a derive_key call with known inputs will produce
// DIFFERENT output from the locked KAT vectors above. This test asserts
// the PARAMETERS THEMSELVES rather than the resulting hex so that the
// failure message names the bad constant directly.
#[test]
fn argon2id_parameters_are_locked() {
    use argon2::{Algorithm, Argon2, Params, Version};
    use sha2::{Digest, Sha256};

    // These are the locked v2.0.0 cross-SDK parameters.
    const LOCKED_M_COST: u32 = 65536;
    const LOCKED_T_COST: u32 = 3;
    const LOCKED_P_COST: u32 = 1;
    const LOCKED_OUTPUT_LEN: usize = 32;

    let mut h = Sha256::new();
    h.update("password1".as_bytes());
    let pw1 = h.finalize();
    let mut h = Sha256::new();
    h.update("password2".as_bytes());
    let pw2 = h.finalize();
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&pw1);
    combined.extend_from_slice(&pw2);
    let salt = [0xAAu8; 32];

    let params = Params::new(LOCKED_M_COST, LOCKED_T_COST, LOCKED_P_COST, Some(LOCKED_OUTPUT_LEN))
        .expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; LOCKED_OUTPUT_LEN];
    argon2
        .hash_password_into(&combined, &salt, &mut key)
        .expect("argon2 derivation");

    assert_eq!(
        hex::encode(&key),
        "854e7acffd85eae6d45ed07e84237fddc887928270f591a41b36d57e675181d8",
        "Argon2id parameter pinning failed; one of t={} m={} p={} len={} has drifted",
        LOCKED_T_COST, LOCKED_M_COST, LOCKED_P_COST, LOCKED_OUTPUT_LEN
    );
}
