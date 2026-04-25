use deny_sh::{
    decrypt, derive_key, encrypt, generate_control_data, generate_deniable_control,
    HEADER_LENGTH,
};

// --- KAT vectors from TypeScript tests ---

#[test]
fn kat_derive_key_password1_password2_salt_aa() {
    let salt = [0xAAu8; 32];
    let key = derive_key("password1", "password2", &salt);
    let hex_key = hex::encode(&key);
    assert!(
        hex_key.starts_with("73dd642b"),
        "Expected key starting with 73dd642b, got {}",
        hex_key
    );
}

#[test]
fn kat_derive_key_test_pw1_test_pw2_salt_01() {
    let salt = [0x01u8; 32];
    let key = derive_key("test-pw1", "test-pw2", &salt);
    let hex_key = hex::encode(&key);
    assert!(
        hex_key.starts_with("ed672cc0"),
        "Expected key starting with ed672cc0, got {}",
        hex_key
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
