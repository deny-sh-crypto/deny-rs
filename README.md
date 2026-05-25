# deny-sh (Rust)

Deniable encryption library, algorithm-compatible with the [TypeScript](https://www.npmjs.com/package/deny-sh), [Go](https://pkg.go.dev/github.com/deny-sh-crypto/deny-go), and [Python](https://pypi.org/project/deny-sh/) deny.sh SDKs. Ciphertext is byte-for-byte compatible across all four languages.

Part of the **Encrypt pillar** of [deny.sh](https://deny.sh), the deniability infrastructure. Apache 2.0, zero copyleft, free for any use.

## What is deniable encryption?

The same ciphertext decrypts to **different messages** depending on which control file you provide. When the bytes leak (a stolen backup, a seized device, a prompt-injected AI agent), the control file in the obvious place opens the ciphertext to a plausible decoy. The real control file is somewhere else. There is no way, cryptographically or forensically, to tell which decryption produced the "real" plaintext.

## Install

```toml
[dependencies]
deny-sh = "1"
```

## Usage

```rust
use deny_sh::{encrypt, decrypt, generate_deniable_control};

// Encrypt
let (ciphertext, control_data) = encrypt(
    b"seed phrase here",
    "password1",
    "password2",
    None,  // auto-generate control data
).unwrap();

// Decrypt with real control file → real message
let plaintext = decrypt(&ciphertext, "password1", "password2", &control_data).unwrap();
assert_eq!(plaintext, b"seed phrase here");

// Generate deniable control file → decoy message
let fake_control = generate_deniable_control(
    &ciphertext,
    "password1",
    "password2",
    b"decoy seed phrase",
).unwrap();

// Same ciphertext + same passwords + different control = different message
let decoy = decrypt(&ciphertext, "password1", "password2", &fake_control).unwrap();
assert_eq!(decoy, b"decoy seed phrase");
```

### Multiple decoys from one ciphertext

There is no per-ciphertext cap on the number of decoys. Derive a fresh control file for each cover story, sized to fit within the original real plaintext envelope:

```rust
// Encrypt a longer real seed phrase so decoys have room
let real = b"abandon ability able about above absent absorb abstract absurd ab";
let (ciphertext, real_control) = encrypt(real, "password1", "password2", None).unwrap();

let stories: Vec<&[u8]> = vec![
    b"meeting moved to wednesday",
    b"taxi receipts october 2026",
    b"vegetable risotto recipe",
];

for story in &stories {
    let cover = generate_deniable_control(&ciphertext, "password1", "password2", story).unwrap();
    let recovered = decrypt(&ciphertext, "password1", "password2", &cover).unwrap();
    assert_eq!(&recovered[..], *story);
}

// The real plaintext is still recoverable with the real control file
let original = decrypt(&ciphertext, "password1", "password2", &real_control).unwrap();
assert_eq!(&original[..], &real[..]);
```

The practical upper bound on plaintext length per decoy is the inner-payload envelope: ciphertext length minus 48-byte header minus 4-byte length prefix. Pad the real plaintext to your largest expected cover-story length at encrypt time so every decoy fits.

## API

```rust
pub fn encrypt(
    plaintext: &[u8],
    password1: &str,
    password2: &str,
    control_data: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), Error>

pub fn decrypt(
    ciphertext: &[u8],
    password1: &str,
    password2: &str,
    control_data: &[u8],
) -> Result<Vec<u8>, Error>

pub fn generate_deniable_control(
    ciphertext: &[u8],
    password1: &str,
    password2: &str,
    desired_plaintext: &[u8],
) -> Result<Vec<u8>, Error>

pub fn generate_control_data(size: usize) -> Vec<u8>

pub fn derive_key(password1: &str, password2: &str, salt: &[u8]) -> Vec<u8>
```

## Algorithm

- **KDF:** Argon2id v0x13 (t=3, m=65536 KiB, p=1, 32-byte output) on SHA-256(pw1) || SHA-256(pw2)
- **Cipher:** AES-256-CTR
- **Deniability:** XOR with control data, 4-byte LE length prefix inside encrypted zone
- **Format:** salt(32) + iv(16) + ciphertext

Cross-compatible: ciphertext from any SDK (TypeScript, Python, Go, Rust) can be decrypted by any other. Full wire format and KAT vectors: [deny.sh/sdks](https://deny.sh/sdks).

## Threat model

deny.sh defends against **passive ciphertext leak**: an adversary gets the encrypted artefact (lost laptop, cloud breach, prompt-injected agent) and tries to read it. The construction guarantees that whatever the adversary decrypts is indistinguishable from any other decryption.

It is **not** designed to resist an adaptive adversary who can compel you to perform multiple decryptions, demand additional passwords iteratively, or run forensic side-channel analysis on the host hardware. Full threat model: [deny.sh/threat-model](https://deny.sh/threat-model). Cryptographic argument: [deny.sh/whitepaper](https://deny.sh/whitepaper) §5.

The primitive is intentionally unauthenticated. Wrong passwords return garbage, not an error. If you need decryption to fail loudly on wrong inputs, add a caller-side integrity check (magic bytes + SHA-256 fingerprint) on the plaintext.

## Dependencies

- `aes`: AES block cipher
- `ctr`: CTR mode
- `cipher`: StreamCipher trait
- `argon2`: Argon2id KDF
- `sha2`: SHA-256
- `rand`: OS random
- `thiserror`: error types

No `unsafe` code. Rust 2021 edition, minimum Rust 1.70.

## Tests

30 tests covering:
- Encrypt/decrypt roundtrip (empty, short, long, unicode)
- KAT vectors matching TypeScript/Python
- Deniable control generation and verification
- Multiple fake messages from one ciphertext
- Wrong password/control produces garbage
- Password order matters
- Error handling

```bash
cargo test
```

## License

Apache License 2.0. See [LICENSE](LICENSE). Free for commercial and proprietary use. See [deny.sh/licensing](https://deny.sh/licensing).

## Reporting vulnerabilities

Found a bug in the crypto or the SDK? Email security@deny.sh (PGP fingerprint and disclosure policy at [deny.sh/disclosure](https://deny.sh/disclosure)). Please give us a reasonable window before public disclosure.
