# deny-sh (Rust)

Deniable encryption library — algorithm-compatible with the [TypeScript](https://www.npmjs.com/package/deny-sh) and [Python](https://pypi.org/project/deny-sh/) deny.sh SDKs.

## What is deniable encryption?

The same ciphertext decrypts to **different messages** depending on which control file you provide. Under duress, hand over a decoy control file — the adversary gets a plausible fake message. The real message stays hidden. There is no way to prove which control file is "real."

## Install

```toml
[dependencies]
deny-sh = "0.1"
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

- **KDF:** scrypt (N=16384, r=8, p=1) on SHA-256(pw1) || SHA-256(pw2)
- **Cipher:** AES-256-CTR
- **Deniability:** XOR with control data, 4-byte LE length prefix inside encrypted zone
- **Format:** salt(32) + iv(16) + ciphertext

Cross-compatible: ciphertext from any SDK (TypeScript, Python, Rust) can be decrypted by any other.

## Dependencies

- `aes` — AES block cipher
- `ctr` — CTR mode
- `cipher` — StreamCipher trait
- `scrypt` — scrypt KDF
- `sha2` — SHA-256
- `rand` — OS random
- `thiserror` — error types

No `unsafe` code. Rust 2021 edition, minimum Rust 1.70.

## Tests

29 tests covering:
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

AGPL-3.0. [Commercial licenses](https://deny.sh/pricing) available.
