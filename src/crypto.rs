//! Wire-compatible cryptographic primitives used by network.py.
//!
//! Uses pure-Rust curve implementations for X25519/X448 and Ed25519/Ed448 so
//! Windows builds do not require a separately installed OpenSSL SDK.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use cx448::{Signature as Ed448Signature, SigningKey as Ed448SigningKey, VerifyingKey as Ed448VerifyingKey};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub const SALT_SIZE: usize = 64;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_SALT_SIZE: usize = 32;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_OVERHEAD: usize = AES_GCM_IV_SIZE + AES_GCM_SALT_SIZE + AES_GCM_TAG_SIZE;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid framed key")]
    InvalidKey,
    #[error("wrong key algorithm")]
    WrongAlgorithm,
    #[error("wrong key kind")]
    WrongKeyKind,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("invalid TOTP code")]
    InvalidTotp,
    #[error("password is too weak (zxcvbn guesses_log10 must be > 9)")]
    WeakPassword,
    #[error("password must not be empty")]
    EmptyPassword,
    #[error("invalid salt")]
    InvalidSalt,
    #[error("random source failed: {0}")]
    Random(String),
    #[error("KDF failed: {0}")]
    Kdf(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    X25519,
    Ed25519,
    X448,
    Ed448,
}

impl KeyKind {
    pub fn base_tag(self) -> u8 {
        match self {
            Self::X25519 => 0,
            Self::Ed25519 => 2,
            Self::X448 => 4,
            Self::Ed448 => 6,
        }
    }

    pub fn public_len(self) -> usize {
        match self {
            Self::X25519 | Self::Ed25519 => 32,
            Self::X448 => 56,
            Self::Ed448 => 57,
        }
    }

    fn from_tag(tag: u8) -> CryptoResult<(Self, bool)> {
        match tag {
            0 => Ok((Self::X25519, false)),
            1 => Ok((Self::X25519, true)),
            2 => Ok((Self::Ed25519, false)),
            3 => Ok((Self::Ed25519, true)),
            4 => Ok((Self::X448, false)),
            5 => Ok((Self::X448, true)),
            6 => Ok((Self::Ed448, false)),
            7 => Ok((Self::Ed448, true)),
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

pub fn random_bytes(len: usize) -> CryptoResult<Vec<u8>> {
    let mut value = vec![0u8; len];
    getrandom(&mut value).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(value)
}

pub fn gen_salt() -> CryptoResult<Vec<u8>> {
    random_bytes(SALT_SIZE)
}

/// Exact `basic_kdf` primary branch: BLAKE3(master || salt), XOF output.
pub fn basic_kdf(master: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(master);
    hasher.update(salt);
    let mut output = vec![0u8; length];
    hasher.finalize_xof().fill(&mut output);
    output
}

/// Python's round() uses ties-to-even.  The level formulas are retained as
/// written in the clean-room specification rather than replaced by a table.
fn python_round(value: f64) -> u32 {
    let floor = value.floor();
    let fraction = value - floor;
    let rounded = if fraction < 0.5 {
        floor
    } else if fraction > 0.5 {
        floor + 1.0
    } else if (floor as u64) % 2 == 0 {
        floor
    } else {
        floor + 1.0
    };
    rounded as u32
}

pub fn kdf(password: &[u8], salt: &[u8], level: i32) -> CryptoResult<Vec<u8>> {
    if salt.len() < 8 {
        return Err(CryptoError::InvalidSalt);
    }
    let l = level as f64;
    let time_cost = python_round(3.0 + 0.7 * l - 0.12 * l * l / 10.0).max(1);
    let memory_cost = python_round(131072.0 + 39321.6 * l).max(8);
    let params = Params::new(memory_cost, time_cost, 1, Some(512))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; 512];
    argon
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(output)
}

pub fn kdf_fast(password: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>> {
    kdf(password, salt, 0)
}

pub fn kdf_slow(password: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>> {
    kdf(password, salt, 10)
}

pub fn check_password_strength(password: &str) -> CryptoResult<()> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    let estimate = zxcvbn::zxcvbn(password, &[]);
    if estimate.guesses_log10() <= 9.0 {
        return Err(CryptoError::WeakPassword);
    }
    Ok(())
}

pub fn derive_at_rest_key(password: &str, salt: &[u8]) -> CryptoResult<Vec<u8>> {
    check_password_strength(password)?;
    if salt.len() != SALT_SIZE {
        return Err(CryptoError::InvalidSalt);
    }
    kdf_slow(password.as_bytes(), salt)
}

fn to_array<const N: usize>(raw: &[u8]) -> CryptoResult<[u8; N]> {
    raw.try_into().map_err(|_| CryptoError::InvalidKey)
}

fn x448_secret(raw: &[u8]) -> CryptoResult<cx448::x448::Secret> {
    cx448::x448::Secret::from_bytes(raw).ok_or(CryptoError::InvalidKey)
}

fn ed448_signing_key(raw: &[u8]) -> CryptoResult<Ed448SigningKey> {
    Ed448SigningKey::try_from(raw).map_err(|_| CryptoError::InvalidKey)
}

pub fn generate_keypair(kind: KeyKind) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    match kind {
        KeyKind::X25519 => {
            let raw = to_array::<32>(&random_bytes(32)?)?;
            let private = X25519StaticSecret::from(raw);
            let public = X25519PublicKey::from(&private);
            Ok((
                frame_key(kind, true, private.as_bytes()),
                frame_key(kind, false, public.as_bytes()),
            ))
        }
        KeyKind::Ed25519 => {
            let raw = to_array::<32>(&random_bytes(32)?)?;
            let private = Ed25519SigningKey::from_bytes(&raw);
            let public = private.verifying_key().to_bytes();
            Ok((
                frame_key(kind, true, private.as_bytes()),
                frame_key(kind, false, &public),
            ))
        }
        KeyKind::X448 => {
            let raw = random_bytes(56)?;
            let private = x448_secret(&raw)?;
            let public = cx448::x448::PublicKey::from(&private);
            Ok((
                frame_key(kind, true, private.as_bytes()),
                frame_key(kind, false, public.as_bytes()),
            ))
        }
        KeyKind::Ed448 => {
            let raw = random_bytes(57)?;
            let private = ed448_signing_key(&raw)?;
            let public = private.verifying_key().to_bytes();
            let private_bytes = private.to_bytes();
            Ok((
                frame_key(kind, true, &private_bytes),
                frame_key(kind, false, &public),
            ))
        }
    }
}

pub fn frame_key(kind: KeyKind, private: bool, raw: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(raw.len() + 1);
    output.push(kind.base_tag() + u8::from(private));
    output.extend_from_slice(raw);
    output
}

pub fn parse_framed_key(
    framed: &[u8],
    expected_kind: Option<KeyKind>,
    expected_private: Option<bool>,
) -> CryptoResult<(KeyKind, bool, &[u8])> {
    if framed.is_empty() {
        return Err(CryptoError::InvalidKey);
    }
    let (kind, private) = KeyKind::from_tag(framed[0])?;
    if expected_kind.is_some_and(|expected| expected != kind) {
        return Err(CryptoError::WrongAlgorithm);
    }
    if expected_private.is_some_and(|expected| expected != private) {
        return Err(CryptoError::WrongKeyKind);
    }
    if framed.len() != kind.public_len() + 1 {
        return Err(CryptoError::InvalidKey);
    }
    Ok((kind, private, &framed[1..]))
}

pub fn get_pub(framed_private: &[u8]) -> CryptoResult<Vec<u8>> {
    let (kind, _, raw) = parse_framed_key(framed_private, None, Some(true))?;
    let public = match kind {
        KeyKind::X25519 => {
            let private = X25519StaticSecret::from(to_array::<32>(raw)?);
            X25519PublicKey::from(&private).as_bytes().to_vec()
        }
        KeyKind::Ed25519 => {
            let private = Ed25519SigningKey::from_bytes(&to_array::<32>(raw)?);
            private.verifying_key().to_bytes().to_vec()
        }
        KeyKind::X448 => {
            let private = x448_secret(raw)?;
            cx448::x448::PublicKey::from(&private).as_bytes().to_vec()
        }
        KeyKind::Ed448 => ed448_signing_key(raw)?.verifying_key().to_bytes().to_vec(),
    };
    Ok(frame_key(kind, false, &public))
}

pub fn shared_secret(my_private: &[u8], peer_public: &[u8]) -> CryptoResult<Vec<u8>> {
    let (my_kind, _, my_raw) = parse_framed_key(my_private, None, Some(true))?;
    let (peer_kind, _, peer_raw) = parse_framed_key(peer_public, None, Some(false))?;
    if my_kind != peer_kind || !matches!(my_kind, KeyKind::X25519 | KeyKind::X448) {
        return Err(CryptoError::WrongAlgorithm);
    }

    match my_kind {
        KeyKind::X25519 => {
            let private = X25519StaticSecret::from(to_array::<32>(my_raw)?);
            let public = X25519PublicKey::from(to_array::<32>(peer_raw)?);
            Ok(private.diffie_hellman(&public).to_bytes().to_vec())
        }
        KeyKind::X448 => {
            let private = x448_secret(my_raw)?;
            let public = cx448::x448::PublicKey::from_bytes(peer_raw)
                .ok_or(CryptoError::InvalidKey)?;
            let shared = private
                .as_diffie_hellman(&public)
                .ok_or(CryptoError::AuthenticationFailed)?;
            Ok(shared.as_bytes().to_vec())
        }
        _ => Err(CryptoError::WrongAlgorithm),
    }
}

pub fn ed25519_sign(framed_private: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let (kind, _, raw) = parse_framed_key(framed_private, None, Some(true))?;
    let signature = match kind {
        KeyKind::Ed25519 => {
            let private = Ed25519SigningKey::from_bytes(&to_array::<32>(raw)?);
            use ed25519_dalek::Signer as _;
            private.sign(data).to_bytes().to_vec()
        }
        KeyKind::Ed448 => ed448_signing_key(raw)?.sign_raw(data).to_bytes().to_vec(),
        _ => return Err(CryptoError::WrongAlgorithm),
    };
    let mut output = Vec::with_capacity(signature.len() + data.len());
    output.extend_from_slice(&signature);
    output.extend_from_slice(data);
    Ok(output)
}

pub fn ed25519_verify(framed_public: &[u8], signed: &[u8]) -> CryptoResult<Vec<u8>> {
    let (kind, _, raw) = parse_framed_key(framed_public, None, Some(false))?;
    let signature_len = match kind {
        KeyKind::Ed448 => 114,
        KeyKind::Ed25519 => 64,
        _ => return Err(CryptoError::WrongAlgorithm),
    };
    if signed.len() < signature_len {
        return Err(CryptoError::AuthenticationFailed);
    }
    let (signature, data) = signed.split_at(signature_len);

    let verified = match kind {
        KeyKind::Ed25519 => {
            let public = Ed25519VerifyingKey::from_bytes(&to_array::<32>(raw)?)
                .map_err(|_| CryptoError::InvalidKey)?;
            let signature = Ed25519Signature::from_bytes(&to_array::<64>(signature)?);
            public.verify_strict(data, &signature).is_ok()
        }
        KeyKind::Ed448 => {
            let public = Ed448VerifyingKey::from_bytes(&to_array::<57>(raw)?)
                .map_err(|_| CryptoError::InvalidKey)?;
            let signature = Ed448Signature::from_bytes(&to_array::<114>(signature)?)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            public.verify_raw(&signature, data).is_ok()
        }
        _ => return Err(CryptoError::WrongAlgorithm),
    };

    if !verified {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(data.to_vec())
}

/// encryptGCM(data, key, aad): IV || random SALT || AES-256-GCM(data || tag).
pub fn encrypt_gcm(data: &[u8], key: &[u8], aad: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
    let iv = random_bytes(AES_GCM_IV_SIZE)?;
    let salt = random_bytes(AES_GCM_SALT_SIZE)?;
    let derived = basic_kdf(key, &salt, 32);
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    let nonce = Nonce::from_slice(&iv);
    let payload = Payload {
        msg: data,
        aad: aad.unwrap_or(&[]),
    };
    let encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let mut output = Vec::with_capacity(AES_GCM_OVERHEAD + data.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub fn decrypt_gcm(blob: &[u8], key: &[u8], aad: Option<&[u8]>) -> CryptoResult<Vec<u8>> {
    if blob.len() < 60 {
        return Err(CryptoError::InvalidCiphertext);
    }
    let iv = &blob[..AES_GCM_IV_SIZE];
    let salt = &blob[AES_GCM_IV_SIZE..AES_GCM_IV_SIZE + AES_GCM_SALT_SIZE];
    let encrypted = &blob[AES_GCM_IV_SIZE + AES_GCM_SALT_SIZE..];
    let derived = basic_kdf(key, salt, 32);
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    cipher
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: encrypted,
                aad: aad.unwrap_or(&[]),
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn normalize_base32(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn totp_secret_string(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

pub fn decode_totp_secret(secret: &str) -> CryptoResult<Vec<u8>> {
    BASE32_NOPAD
        .decode(normalize_base32(secret).as_bytes())
        .map_err(|_| CryptoError::InvalidTotp)
}

pub fn totp_at(secret: &[u8], unix_seconds: u64) -> CryptoResult<String> {
    let counter = unix_seconds / 30;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset] & 0x7f)) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

pub fn current_totp(secret: &[u8]) -> CryptoResult<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?
        .as_secs();
    totp_at(secret, now)
}

pub fn verify_totp(secret: &[u8], code: &str, window: i64) -> CryptoResult<bool> {
    let normalized: String = code.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if normalized.len() != 6 || !normalized.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?
        .as_secs() as i64;
    for delta in -window..=window {
        let timestamp = (now + delta * 30).max(0) as u64;
        let expected = totp_at(secret, timestamp)?;
        if bool::from(expected.as_bytes().ct_eq(normalized.as_bytes())) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn random_hex_id(bytes: usize) -> CryptoResult<String> {
    Ok(hex::encode(random_bytes(bytes)?))
}
