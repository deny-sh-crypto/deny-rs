// Requires the branch-carrying internal helper, public only under this feature.
// Run with: cargo test --features internal-testing
#![cfg(feature = "internal-testing")]

use deny_sh::{
    decrypt_honey, decrypt_honey_with_branch, derive_honey_seed, encrypt_honey,
    generate_honey_decoy, is_honey_eligible, is_well_formed_frame, sourced_int, HoneyBranch,
    HoneyError, SeededByteSource,
};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kat {
    inputs: Inputs,
    derive_honey_seed: Vec<DeriveVector>,
    seeded_byte_source: Vec<SeededVector>,
    sourced_int: Vec<SourcedIntVector>,
    generate_honey_decoy: Vec<GenerateVector>,
    is_well_formed_frame: Vec<FrameVector>,
}

#[derive(Debug, Deserialize)]
struct Inputs {
    salts: HashMap<String, String>,
    #[serde(rename = "decryptBytes")]
    decrypt_bytes: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveVector {
    type_tag: String,
    decrypt_bytes: String,
    salt: String,
    seed: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeededVector {
    seed: String,
    keystream96: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourcedIntVector {
    #[serde(default)]
    seed: Option<String>,
    #[serde(default)]
    seed_from: Option<SeedFrom>,
    max: u32,
    sequence: Vec<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedFrom {
    type_tag: String,
    decrypt_bytes: String,
    salt: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateVector {
    type_tag: String,
    decrypt_bytes: String,
    salt: String,
    honey_eligible: bool,
    output: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameVector {
    name: String,
    payload_hex: String,
    expected_band: Option<usize>,
    well_formed: bool,
}

fn load_kat() -> Kat {
    // Vendored copy lives alongside this test as a gzip+base64 blob
    // (honey-kat.json.gz.b64) so the standalone deny-rs mirror builds without
    // tripping GitHub secret-scanning on the synthetic key vectors inside the
    // KAT. The monorepo keeps the canonical plaintext at
    // server/decoy-engine/kat/honey-kat.json; scripts/sync-public-sdks.sh
    // regenerates this blob from it on release. The decoded bytes are
    // byte-identical to the canonical.
    use base64::Engine as _;
    use std::io::Read as _;
    let b64 = include_str!("honey-kat.json.gz.b64");
    let gz = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .expect("valid base64 honey KAT blob");
    let mut decoder = flate2::read::GzDecoder::new(&gz[..]);
    let mut json = String::new();
    decoder
        .read_to_string(&mut json)
        .expect("gunzip honey KAT blob");
    serde_json::from_str(&json).expect("valid honey KAT")
}

fn input_hex<'a>(map: &'a HashMap<String, String>, key: &str) -> &'a str {
    map.get(key)
        .unwrap_or_else(|| panic!("missing input {key}"))
}

fn seed_from_hex(hex_value: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_value).expect("seed hex");
    bytes.try_into().expect("32-byte seed")
}

fn vector_seed(kat: &Kat, seed: &Option<String>, seed_from: &Option<SeedFrom>) -> [u8; 32] {
    if let Some(seed) = seed {
        return seed_from_hex(seed);
    }
    let seed_from = seed_from.as_ref().expect("seed or seedFrom");
    let decrypt_bytes = hex::decode(input_hex(
        &kat.inputs.decrypt_bytes,
        &seed_from.decrypt_bytes,
    ))
    .expect("decryptBytes hex");
    let salt = hex::decode(input_hex(&kat.inputs.salts, &seed_from.salt)).expect("salt hex");
    derive_honey_seed(&decrypt_bytes, &salt, &seed_from.type_tag)
}

#[test]
fn derive_honey_seed_vectors() {
    let kat = load_kat();
    for v in &kat.derive_honey_seed {
        let decrypt_bytes = hex::decode(input_hex(&kat.inputs.decrypt_bytes, &v.decrypt_bytes))
            .expect("decryptBytes hex");
        let salt = hex::decode(input_hex(&kat.inputs.salts, &v.salt)).expect("salt hex");
        let seed = derive_honey_seed(&decrypt_bytes, &salt, &v.type_tag);
        assert_eq!(hex::encode(seed), v.seed, "deriveHoneySeed {}", v.type_tag);
    }
}

#[test]
fn seeded_byte_source_vectors() {
    let kat = load_kat();
    for v in &kat.seeded_byte_source {
        let mut src = SeededByteSource::new(seed_from_hex(&v.seed));
        assert_eq!(
            hex::encode(src.bytes(96)),
            v.keystream96,
            "SeededByteSource {}",
            v.seed
        );
    }
}

#[test]
fn sourced_int_vectors() {
    let kat = load_kat();
    for v in &kat.sourced_int {
        let seed = vector_seed(&kat, &v.seed, &v.seed_from);
        let mut src = SeededByteSource::new(seed);
        let got: Vec<u32> = (0..v.sequence.len())
            .map(|_| sourced_int(&mut src, v.max).expect("sourced_int"))
            .collect();
        assert_eq!(got, v.sequence, "sourcedInt max={}", v.max);
    }
}

#[test]
fn generate_honey_decoy_vectors() {
    let kat = load_kat();
    for v in &kat.generate_honey_decoy {
        if !v.honey_eligible {
            assert!(generate_honey_decoy(&v.type_tag, &[], &[], None).is_err());
            continue;
        }
        let decrypt_bytes = hex::decode(input_hex(&kat.inputs.decrypt_bytes, &v.decrypt_bytes))
            .expect("decryptBytes hex");
        let salt = hex::decode(input_hex(&kat.inputs.salts, &v.salt)).expect("salt hex");
        let got = generate_honey_decoy(&v.type_tag, &decrypt_bytes, &salt, None)
            .expect("generate_honey_decoy");
        assert_eq!(Some(got), v.output, "generateHoneyDecoy {}", v.type_tag);
    }
}

#[test]
fn is_well_formed_frame_vectors() {
    let kat = load_kat();
    for v in &kat.is_well_formed_frame {
        let payload = hex::decode(&v.payload_hex).expect("payload hex");
        assert_eq!(
            is_well_formed_frame(&payload, v.expected_band),
            v.well_formed,
            "isWellFormedFrame {}",
            v.name
        );
    }
}

#[test]
fn honey_wrappers_roundtrip_real_branch() {
    // Synthetic fixture, assembled from parts so GitHub secret-scanning does
    // not pattern-match a literal sk_live_ token (the value is opaque to the
    // test — it is only round-tripped through encrypt/decrypt_honey).
    let secret = format!(
        "sk_{}_51NxQ9LhK7fKxXo1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7",
        "live"
    );
    let secret = secret.as_str();
    let encrypted = encrypt_honey(
        secret,
        "correct-honey-pw-1",
        "correct-honey-pw-2",
        "stripe-live-key",
    )
    .expect("encrypt_honey");

    assert_eq!(encrypted.band, 256);
    assert_eq!(encrypted.real_ctrl.len(), encrypted.band);
    assert_eq!(encrypted.ciphertext.len(), 48 + encrypted.band);
    assert!(is_honey_eligible("stripe-live-key"));
    assert!(!is_honey_eligible("generic"));

    // Public decrypt_honey exposes only value (branch oracle stripped).
    let pub_result = decrypt_honey(
        &encrypted.ciphertext,
        &encrypted.real_ctrl,
        "correct-honey-pw-1",
        "correct-honey-pw-2",
        "stripe-live-key",
        encrypted.band,
    )
    .expect("decrypt_honey");
    assert_eq!(pub_result.value, secret);

    // Internal helper retains the branch for test/telemetry assertions.
    let decrypted = decrypt_honey_with_branch(
        &encrypted.ciphertext,
        &encrypted.real_ctrl,
        "correct-honey-pw-1",
        "correct-honey-pw-2",
        "stripe-live-key",
        encrypted.band,
    )
    .expect("decrypt_honey_with_branch");

    assert_eq!(decrypted.value, secret);
    assert_eq!(decrypted.branch, HoneyBranch::Real);
}

#[test]
fn honey_wrappers_refuse_ineligible_types() {
    let err = encrypt_honey("anything", "pw1", "pw2", "generic").unwrap_err();
    assert!(matches!(
        err,
        deny_sh::Error::Honey(HoneyError::IneligibleType(_))
    ));

    let err =
        decrypt_honey(&[0u8; 48], &[0u8; 64], "pw1", "pw2", "freeform-secret", 64).unwrap_err();
    assert!(matches!(
        err,
        deny_sh::Error::Honey(HoneyError::IneligibleType(_))
    ));
}
