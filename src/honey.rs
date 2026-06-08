use sha2::{Digest, Sha256};
use thiserror::Error;

const HONEY_DOMAIN: &[u8] = b"deny-sh/honey/v1";
const ALNUM: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALNUM_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
const HEX: &str = "0123456789abcdef";
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PRINTABLE: &str =
    " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
const NI_FIRST: &str = "ABCEGHJKLMNOPRSTWXYZ";
const NI_SECOND: &str = "ABCEGHJKLMNPRSTWXYZ";
const BIP39_WORDLIST: &str = include_str!("bip39_english.txt");

#[derive(Debug, Error)]
pub enum HoneyError {
    #[error("unsupported honey type (post-v1): {0}")]
    UnsupportedHoneyType(String),

    #[error("Honey Mode is not supported for unstructured type \"{0}\"")]
    IneligibleType(String),

    #[error("generated decoy exceeds real value length")]
    GeneratedDecoyTooLong,

    #[error("sourcedInt: rejection sampling exceeded bound")]
    RejectionSamplingExceeded,

    #[error("invalid BIP-39 entropy length")]
    InvalidBip39EntropyLength,
}

pub type HoneyResult<T> = Result<T, HoneyError>;

pub fn is_honey_eligible(type_tag: &str) -> bool {
    // Unstructured fallback types + post-v1 structured types whose cross-SDK byte
    // parity is not yet proven (jwt/uri generators build JSON / multi-branch
    // connection strings). HONEY-MODE-SPEC marks the post-v1 set "stub to throw"
    // until a byte-exact port lands. Must match the TS HONEY_INELIGIBLE set.
    !matches!(
        type_tag,
        "generic" | "freeform-secret" | "jwt-token" | "postgres-uri" | "mongodb-uri"
    )
}

pub fn derive_honey_seed(decrypt_bytes: &[u8], salt: &[u8], type_tag: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HONEY_DOMAIN);
    h.update([0x00]);
    h.update(decrypt_bytes);
    h.update([0x00]);
    h.update(salt);
    h.update([0x00]);
    h.update(type_tag.as_bytes());
    h.finalize().into()
}

#[derive(Clone, Debug)]
pub struct SeededByteSource {
    seed: [u8; 32],
    counter: u32,
    buffer: [u8; 32],
    buf_pos: usize,
    has_buffer: bool,
}

impl SeededByteSource {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0u8; 32],
            buf_pos: 32,
            has_buffer: false,
        }
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(self.seed);
        h.update(self.counter.to_be_bytes());
        self.buffer = h.finalize().into();
        self.buf_pos = 0;
        self.has_buffer = true;
        self.counter = self.counter.wrapping_add(1);
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        if n == 0 {
            return Vec::new();
        }
        let mut out = vec![0u8; n];
        let mut written = 0;
        while written < n {
            if !self.has_buffer || self.buf_pos >= self.buffer.len() {
                self.refill();
            }
            let take = (n - written).min(self.buffer.len() - self.buf_pos);
            out[written..written + take]
                .copy_from_slice(&self.buffer[self.buf_pos..self.buf_pos + take]);
            self.buf_pos += take;
            written += take;
        }
        out
    }
}

pub fn sourced_int(src: &mut SeededByteSource, max: u32) -> HoneyResult<u32> {
    if max == 0 {
        return Ok(0);
    }
    let limit = (u32::MAX as u64 + 1) / max as u64 * max as u64;
    for _ in 0..128 {
        let b = src.bytes(4);
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
        if v < limit {
            return Ok((v % max as u64) as u32);
        }
    }
    Err(HoneyError::RejectionSamplingExceeded)
}

pub fn generate_honey_decoy(
    type_tag: &str,
    decrypt_bytes: &[u8],
    salt: &[u8],
    real_length_hint: Option<usize>,
) -> HoneyResult<String> {
    if !is_honey_eligible(type_tag) {
        return Err(HoneyError::IneligibleType(type_tag.to_string()));
    }
    let len_hint =
        real_length_hint.unwrap_or_else(|| default_length_for_type(type_tag).unwrap_or(32));
    let dummy_real = dummy_real_for_type(type_tag, len_hint)?;
    let seed = derive_honey_seed(decrypt_bytes, salt, type_tag);
    let mut src = SeededByteSource::new(seed);
    generate_local_decoy(&dummy_real, type_tag, &mut src)
}

pub fn is_well_formed_frame(payload: &[u8], expected_band: Option<usize>) -> bool {
    if payload.len() < 4 {
        return false;
    }
    let length = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let fits_payload = length <= payload.len().saturating_sub(4);
    if !fits_payload {
        return false;
    }
    match expected_band {
        Some(band) => length <= band.saturating_sub(4),
        None => true,
    }
}

fn default_length_for_type(type_tag: &str) -> Option<usize> {
    Some(match type_tag {
        "stripe-test-key" => 32,
        "stripe-live-key" => 107,
        "github-pat-classic" => 40,
        "github-pat-fine" => 93,
        "openai-key" => 51,
        "anthropic-key" => 108,
        "resend-key" => 36,
        "aws-access-key" => 20,
        "bip39-phrase" => 200,
        "jwt-token" => 300,
        "iban" => 22,
        "credit-card" => 16,
        "private-key-pem" => 1700,
        "postgres-uri" => 80,
        "mongodb-uri" => 90,
        "slack-bot-token" => 57,
        "slack-user-token" => 65,
        "discord-bot-token" => 72,
        "digitalocean-pat" => 71,
        "twilio-auth-token" => 34,
        "sendgrid-key" => 69,
        "huggingface-token" => 40,
        "npm-publish-token" => 40,
        "pypi-token" => 156,
        "gitlab-pat" => 26,
        "mailgun-api-key" => 36,
        "linear-api-key" => 51,
        "notion-token" => 50,
        "shopify-token" => 38,
        "square-token" => 64,
        "cloudflare-api-token" => 40,
        "ethereum-private-key" => 64,
        "bitcoin-wif" => 51,
        "solana-private-key" => 88,
        "uk-nhs-number" => 10,
        "us-ssn" => 11,
        "uk-ni-number" => 9,
        "phone-e164" => 15,
        _ => return None,
    })
}

fn dummy_real_for_type(type_tag: &str, len_hint: usize) -> HoneyResult<String> {
    match type_tag {
        "bip39-phrase" => {
            Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())
        }
        "jwt-token" => {
            let body_len = 1usize.max(len_hint.saturating_sub("e30..".len()));
            let first = 1usize.max(body_len / 2);
            Ok(format!(
                "e30.{}.{}",
                "x".repeat(first),
                "x".repeat(body_len.saturating_sub(first))
            ))
        }
        "credit-card" => Ok("4".repeat(len_hint)),
        "iban" => Ok(format!(
            "GB{}",
            "0".repeat(len_hint.saturating_sub(2))
        )),
        "postgres-uri" => Ok(format!(
            "postgres://{}",
            "x".repeat(len_hint.saturating_sub("postgres://".len()))
        )),
        "mongodb-uri" => Ok(format!(
            "mongodb://{}",
            "x".repeat(len_hint.saturating_sub("mongodb://".len()))
        )),
        "phone-e164" => Ok(format!(
            "+{}",
            "1".repeat(len_hint.saturating_sub(1))
        )),
        "stripe-test-key"
        | "stripe-live-key"
        | "github-pat-classic"
        | "github-pat-fine"
        | "openai-key"
        | "anthropic-key"
        | "resend-key"
        | "aws-access-key"
        | "private-key-pem"
        | "slack-bot-token"
        | "slack-user-token"
        | "discord-bot-token"
        | "digitalocean-pat"
        | "twilio-auth-token"
        | "sendgrid-key"
        | "huggingface-token"
        | "npm-publish-token"
        | "pypi-token"
        | "gitlab-pat"
        | "mailgun-api-key"
        | "linear-api-key"
        | "notion-token"
        | "shopify-token"
        | "square-token"
        | "cloudflare-api-token"
        | "ethereum-private-key"
        | "bitcoin-wif"
        | "solana-private-key"
        | "uk-nhs-number"
        | "us-ssn"
        | "uk-ni-number" => Ok("x".repeat(len_hint)),
        _ => Err(HoneyError::UnsupportedHoneyType(type_tag.to_string())),
    }
}

fn generate_local_decoy(
    real_value: &str,
    type_tag: &str,
    src: &mut SeededByteSource,
) -> HoneyResult<String> {
    let real_len = real_value.len();
    match type_tag {
        "stripe-test-key" => token("sk_test_", real_len, ALNUM, 24, None, src),
        "stripe-live-key" => token("sk_live_", real_len, ALNUM, 24, None, src),
        "github-pat-classic" => token("ghp_", real_len, ALNUM, 36, Some(36), src),
        "github-pat-fine" => token("github_pat_", real_len, &format!("{ALNUM}_"), 60, None, src),
        "openai-key" => token(
            if real_value.starts_with("sk-proj-") {
                "sk-proj-"
            } else {
                "sk-"
            },
            real_len,
            BASE64URL,
            40,
            None,
            src,
        ),
        "anthropic-key" => token(
            if real_value.starts_with("sk-ant-api03-") {
                "sk-ant-api03-"
            } else {
                "sk-ant-"
            },
            real_len,
            BASE64URL,
            80,
            None,
            src,
        ),
        "resend-key" => token("re_", real_len, &format!("{ALNUM}_"), 20, None, src),
        "aws-access-key" => {
            let prefix = if real_value.starts_with("ASIA") {
                "ASIA"
            } else {
                "AKIA"
            };
            let body_len = bounded_len(real_len, 4, 16, Some(16))?;
            Ok(format!("{prefix}{}", chars(ALNUM_UPPER, body_len, src)?))
        }
        "bip39-phrase" => {
            let count = real_value.split_whitespace().count();
            random_words(count, real_len, src)
        }
        "jwt-token" => random_jwt(real_value, src),
        "iban" => random_iban(real_value, src),
        "credit-card" => random_credit_card(real_value, src),
        "private-key-pem" => random_private_key_pem(real_value, src),
        "postgres-uri" => random_uri(real_value, "postgres://", src),
        "mongodb-uri" => random_uri(real_value, "mongodb://", src),
        "slack-bot-token" => Ok(format!(
            "xoxb-{}-{}-{}",
            digits(11, src)?,
            digits(11, src)?,
            chars(
                ALNUM,
                bounded_len(real_len, "xoxb-".len() + 11 + 1 + 11 + 1, 24, None)?,
                src
            )?
        )),
        "slack-user-token" => Ok(format!(
            "xoxp-{}-{}-{}-{}",
            digits(11, src)?,
            digits(11, src)?,
            digits(11, src)?,
            chars(
                ALNUM,
                bounded_len(real_len, "xoxp-".len() + 11 + 1 + 11 + 1 + 11 + 1, 24, None)?,
                src
            )?
        )),
        "discord-bot-token" => random_discord_bot_token(real_value, src),
        "digitalocean-pat" => token("dop_v1_", real_len, HEX, 64, Some(64), src),
        "twilio-auth-token" => token("SK", real_len, HEX, 32, Some(32), src),
        "sendgrid-key" => {
            if real_len < 69 {
                return Err(HoneyError::GeneratedDecoyTooLong);
            }
            Ok(format!(
                "SG.{}.{}",
                segment(22, BASE64URL, src)?,
                segment(43, BASE64URL, src)?
            ))
        }
        "huggingface-token" => token(
            "hf_",
            real_len,
            ALNUM,
            30usize.min(1usize.max(real_len.saturating_sub(3))),
            None,
            src,
        ),
        "npm-publish-token" => token("npm_", real_len, ALNUM, 36, Some(36), src),
        "pypi-token" => token("pypi-AgE", real_len, BASE64URL, 80, None, src),
        "gitlab-pat" => token("glpat-", real_len, BASE64URL, 20, Some(20), src),
        "mailgun-api-key" => token("key-", real_len, HEX, 32, Some(32), src),
        "linear-api-key" => token("lin_api_", real_len, ALNUM, 40, Some(40), src),
        "notion-token" => {
            let prefix = if real_value.starts_with("ntn_") {
                "ntn_"
            } else {
                "secret_"
            };
            token(
                prefix,
                real_len,
                ALNUM,
                43usize.min(1usize.max(real_len.saturating_sub(prefix.len()))),
                None,
                src,
            )
        }
        "shopify-token" => token("shpat_", real_len, HEX, 32, Some(32), src),
        "square-token" => {
            if real_value.starts_with("sq0atp-") {
                token("sq0atp-", real_len, BASE64URL, 22, Some(22), src)
            } else {
                token("EAAA", real_len, BASE64URL, 60, None, src)
            }
        }
        "cloudflare-api-token" => chars(BASE64URL, real_len, src),
        "ethereum-private-key" => {
            if real_value.starts_with("0x") {
                token("0x", real_len, HEX, 64, Some(64), src)
            } else {
                let len = bounded_len(real_len, 0, 64, Some(64))?;
                chars(HEX, len, src)
            }
        }
        "bitcoin-wif" => random_bitcoin_wif(real_len, src),
        "solana-private-key" => random_solana_private_key(real_len, src),
        "uk-nhs-number" => digits(real_value.split_whitespace().collect::<String>().len(), src),
        "us-ssn" => Ok(format!(
            "{}-{}-{}",
            100 + sourced_int(src, 799)?,
            10 + sourced_int(src, 90)?,
            1000 + sourced_int(src, 9000)?
        )),
        "uk-ni-number" => {
            let first = char_at(NI_FIRST, sourced_int(src, NI_FIRST.len() as u32)? as usize);
            let second = char_at(
                NI_SECOND,
                sourced_int(src, NI_SECOND.len() as u32)? as usize,
            );
            let middle = digits(6, src)?;
            let suffix = char_at("ABCD", sourced_int(src, 4)? as usize);
            Ok(format!("{first}{second}{middle}{suffix}"))
        }
        "phone-e164" => {
            let no_plus_len = real_value.strip_prefix('+').unwrap_or(real_value).len();
            let len = 8usize.max(15usize.min(no_plus_len));
            let out = format!("+{}{}", 1 + sourced_int(src, 9)?, digits(len - 1, src)?);
            if out.len() > real_len {
                return Err(HoneyError::GeneratedDecoyTooLong);
            }
            Ok(out)
        }
        "generic" | "freeform-secret" => chars(PRINTABLE, real_len, src),
        _ => Err(HoneyError::UnsupportedHoneyType(type_tag.to_string())),
    }
}

fn bounded_len(
    real_len: usize,
    prefix_len: usize,
    min_body: usize,
    fixed_body: Option<usize>,
) -> HoneyResult<usize> {
    if let Some(body) = fixed_body {
        if prefix_len + body > real_len {
            return Err(HoneyError::GeneratedDecoyTooLong);
        }
        return Ok(body);
    }
    let body_len = min_body.max(real_len.saturating_sub(prefix_len));
    if prefix_len + body_len > real_len {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    Ok(body_len)
}

fn token(
    prefix: &str,
    real_len: usize,
    alphabet: &str,
    min_body: usize,
    fixed_body: Option<usize>,
    src: &mut SeededByteSource,
) -> HoneyResult<String> {
    let body_len = bounded_len(real_len, prefix.len(), min_body, fixed_body)?;
    Ok(format!("{prefix}{}", chars(alphabet, body_len, src)?))
}

fn chars(alphabet: &str, len: usize, src: &mut SeededByteSource) -> HoneyResult<String> {
    let alphabet_chars: Vec<char> = alphabet.chars().collect();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let idx = sourced_int(src, alphabet_chars.len() as u32)? as usize;
        out.push(alphabet_chars[idx]);
    }
    Ok(out)
}

fn char_at(alphabet: &str, idx: usize) -> char {
    alphabet.as_bytes()[idx] as char
}

fn digits(len: usize, src: &mut SeededByteSource) -> HoneyResult<String> {
    chars("0123456789", len, src)
}

fn segment(len: usize, alphabet: &str, src: &mut SeededByteSource) -> HoneyResult<String> {
    chars(alphabet, 1usize.max(len), src)
}

fn split_lengths(real: &str, parts: usize) -> Vec<usize> {
    let segs: Vec<&str> = real.split('.').collect();
    if segs.len() == parts {
        return segs.iter().map(|s| 1usize.max(s.len())).collect();
    }
    let base = 1usize.max(real.len() / parts);
    (0..parts)
        .map(|i| {
            if i == parts - 1 {
                1usize.max(real.len().saturating_sub(base * (parts - 1)))
            } else {
                base
            }
        })
        .collect()
}

fn random_jwt(real: &str, src: &mut SeededByteSource) -> HoneyResult<String> {
    let mut lengths = split_lengths(real, 3);
    let min_header = "e30";
    lengths[0] = lengths[0].max(min_header.len());
    let header_pad_len = lengths[0].saturating_sub(min_header.len());
    let out = format!(
        "{}{}.{}.{}",
        min_header,
        if header_pad_len > 0 {
            segment(header_pad_len, BASE64URL, src)?
        } else {
            String::new()
        },
        segment(lengths[1], BASE64URL, src)?,
        segment(lengths[2], BASE64URL, src)?
    );
    if out.len() > real.len() {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    Ok(out)
}

fn random_iban(real: &str, src: &mut SeededByteSource) -> HoneyResult<String> {
    let clean = real
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if clean.len() < 15 {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    let cc = if clean.len() >= 2 && clean[..2].chars().all(|c| c.is_ascii_uppercase()) {
        &clean[..2]
    } else {
        "GB"
    };
    let bban = chars(ALNUM_UPPER, clean.len() - 4, src)?;
    let check = iban_check_digits(cc, &bban);
    Ok(format!("{cc}{check}{bban}"))
}

fn random_credit_card(real: &str, src: &mut SeededByteSource) -> HoneyResult<String> {
    let mut layout: Vec<char> = real.chars().collect();
    let digit_positions: Vec<usize> = layout
        .iter()
        .enumerate()
        .filter_map(|(i, c)| if c.is_ascii_digit() { Some(i) } else { None })
        .collect();
    if digit_positions.len() < 2 {
        for c in &mut layout {
            if c.is_ascii_digit() {
                *c = char_at("0123456789", sourced_int(src, 10)? as usize);
            }
        }
        return Ok(layout.into_iter().collect());
    }
    for pos in digit_positions.iter().take(digit_positions.len() - 1) {
        layout[*pos] = char_at("0123456789", sourced_int(src, 10)? as usize);
    }
    let body_digits: String = digit_positions
        .iter()
        .take(digit_positions.len() - 1)
        .map(|p| layout[*p])
        .collect();
    let check_digit = luhn_check_digit(&body_digits);
    let last = digit_positions[digit_positions.len() - 1];
    layout[last] = char::from_digit(check_digit, 10).unwrap();
    Ok(layout.into_iter().collect())
}

fn random_private_key_pem(real: &str, src: &mut SeededByteSource) -> HoneyResult<String> {
    let begin = "-----BEGIN PRIVATE KEY-----\n";
    let end = "\n-----END PRIVATE KEY-----";
    if real.len() < begin.len() + end.len() + 1 {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    let budget = real.len() - begin.len() - end.len();
    Ok(format!("{begin}{}{end}", chars(BASE64URL, budget, src)?))
}

fn random_uri(
    real: &str,
    fallback_scheme: &str,
    src: &mut SeededByteSource,
) -> HoneyResult<String> {
    let scheme = scheme_prefix(real).unwrap_or(fallback_scheme);
    let host = format!(
        "{}.example.test",
        chars("abcdefghijklmnopqrstuvwxyz", 8, src)?
    );
    let user = format!("u{}", chars(ALNUM, 5, src)?);
    let pass = format!("p{}", chars(ALNUM, 8, src)?);
    let path = format!("/{}", chars("abcdefghijklmnopqrstuvwxyz", 6, src)?);
    let mut out = format!("{scheme}{user}:{pass}@{host}{path}");
    if out.len() > real.len() {
        out = format!("{scheme}{host}");
    }
    if out.len() > real.len() {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    Ok(out)
}

fn scheme_prefix(real: &str) -> Option<&str> {
    let idx = real.find("://")?;
    if idx == 0 {
        return None;
    }
    let scheme = &real[..idx];
    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')) {
        return None;
    }
    Some(&real[..idx + 3])
}

fn random_discord_bot_token(real: &str, src: &mut SeededByteSource) -> HoneyResult<String> {
    let real_len = real.len();
    let mut lengths = split_lengths(real, 3);
    lengths[0] = 23usize.max(28usize.min(lengths[0]));
    lengths[1] = 6usize.max(7usize.min(lengths[1]));
    lengths[2] = 27usize.max(38usize.min(real_len.saturating_sub(lengths[0] + lengths[1] + 2)));
    let out = format!(
        "{}.{}.{}",
        segment(lengths[0], BASE64URL, src)?,
        segment(lengths[1], BASE64URL, src)?,
        segment(lengths[2], BASE64URL, src)?
    );
    if out.len() > real_len {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    Ok(out)
}

fn luhn_check_digit(body_digits: &str) -> u32 {
    let mut sum = 0u32;
    let mut alternate = true;
    for b in body_digits.as_bytes().iter().rev() {
        let mut d = (b - b'0') as u32;
        if alternate {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alternate = !alternate;
    }
    (10 - (sum % 10)) % 10
}

fn iban_check_digits(country_code: &str, bban: &str) -> String {
    let rearranged = format!("{}{}00", bban.to_uppercase(), country_code.to_uppercase());
    let remainder = iban_mod97_remainder(&rearranged);
    let check = 98 - remainder;
    if check < 10 {
        format!("0{check}")
    } else {
        check.to_string()
    }
}

fn iban_mod97_remainder(rearranged: &str) -> u32 {
    let mut remainder = 0u32;
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            remainder = (remainder * 10 + ch.to_digit(10).unwrap()) % 97;
        } else if ch.is_ascii_uppercase() {
            let n = ch as u32 - 55;
            for d in n.to_string().chars() {
                remainder = (remainder * 10 + d.to_digit(10).unwrap()) % 97;
            }
        }
    }
    remainder
}

fn random_words(count: usize, budget: usize, src: &mut SeededByteSource) -> HoneyResult<String> {
    if ![12, 15, 18, 21, 24].contains(&count) {
        return Err(HoneyError::UnsupportedHoneyType(
            "bip39 non-standard word count (post-v1)".to_string(),
        ));
    }
    let ent_bytes = (count * 11 - (count * 11) / 33) / 8;
    // The decoy must fit `budget` (== the real phrase's char length). Naive
    // `<= budget` rejection biases decoys SHORTER than the real value, which a
    // length/transition-rate classifier exploits. Prefer a phrase whose length
    // EXACTLY equals the budget so the decoy length distribution matches the
    // real distribution. Mirrors the TS reference (256 attempts, prefer-exact).
    let mut best_fit = String::new();
    for _ in 0..256 {
        let entropy = src.bytes(ent_bytes);
        let phrase = bip39_from_entropy(&entropy, count)?;
        if phrase.len() == budget {
            return Ok(phrase);
        }
        if phrase.len() <= budget && phrase.len() > best_fit.len() {
            best_fit = phrase;
        }
    }
    if !best_fit.is_empty() {
        return Ok(best_fit);
    }
    Err(HoneyError::GeneratedDecoyTooLong)
}

pub fn bip39_from_entropy(entropy: &[u8], word_count: usize) -> HoneyResult<String> {
    let ent_bits = entropy.len() * 8;
    let cs_bits = ent_bits / 32;
    if (ent_bits + cs_bits) / 11 != word_count {
        return Err(HoneyError::InvalidBip39EntropyLength);
    }
    let hash = Sha256::digest(entropy);
    let words: Vec<&str> = BIP39_WORDLIST.lines().collect();
    if words.len() != 2048 {
        return Err(HoneyError::InvalidBip39EntropyLength);
    }
    let bit_at = |idx: usize| -> u8 {
        if idx < ent_bits {
            (entropy[idx / 8] >> (7 - (idx % 8))) & 1
        } else {
            let hidx = idx - ent_bits;
            (hash[hidx / 8] >> (7 - (hidx % 8))) & 1
        }
    };
    let mut out = Vec::with_capacity(word_count);
    for i in 0..word_count {
        let mut idx = 0usize;
        for j in 0..11 {
            idx = (idx << 1) | bit_at(i * 11 + j) as usize;
        }
        out.push(words[idx]);
    }
    Ok(out.join(" "))
}

fn random_bitcoin_wif(real_len: usize, src: &mut SeededByteSource) -> HoneyResult<String> {
    if real_len < 51 {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    let compressed = real_len >= 52;
    let mut payload = vec![0u8; if compressed { 34 } else { 33 }];
    payload[0] = 0x80;
    payload[1..33].copy_from_slice(&src.bytes(32));
    if compressed {
        payload[33] = 0x01;
    }
    let wif = base58_check_encode(&payload);
    if wif.len() <= real_len {
        return Ok(wif);
    }
    for _ in 0..16 {
        payload[1..33].copy_from_slice(&src.bytes(32));
        let retry = base58_check_encode(&payload);
        if retry.len() <= real_len {
            return Ok(retry);
        }
    }
    Err(HoneyError::GeneratedDecoyTooLong)
}

fn random_solana_private_key(real_len: usize, src: &mut SeededByteSource) -> HoneyResult<String> {
    if real_len < 87 {
        return Err(HoneyError::GeneratedDecoyTooLong);
    }
    for _ in 0..16 {
        let enc = base58_encode(&src.bytes(64));
        if enc.len() >= 87 && enc.len() <= real_len {
            return Ok(enc);
        }
    }
    Err(HoneyError::GeneratedDecoyTooLong)
}

pub fn base58_check_encode(payload: &[u8]) -> String {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut full = Vec::with_capacity(payload.len() + 4);
    full.extend_from_slice(payload);
    full.extend_from_slice(&second[..4]);
    base58_encode(&full)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut digits = vec![0u32];
    for &byte in bytes {
        let mut carry = byte as u32;
        for digit in &mut digits {
            carry += *digit << 8;
            *digit = carry % 58;
            carry /= 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for &byte in bytes {
        if byte == 0 {
            out.push('1');
        } else {
            break;
        }
    }
    let alphabet = BASE58.as_bytes();
    for digit in digits.iter().rev() {
        out.push(alphabet[*digit as usize] as char);
    }
    out
}
