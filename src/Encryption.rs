#![allow(non_snake_case)]
use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as GcmNonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params as ArgonParams, Version as ArgonVersion};
use blake3::Hasher as Blake3Hasher;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    derive::Deriver,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer, Verifier},
    symm::{Cipher as OpenSslCipher, Crypter, Mode},
    x509::{
        extension::{BasicConstraints, SubjectAlternativeName},
        X509Builder, X509Name, X509NameBuilder, X509,
    },
};
use rand::{distributions::Alphanumeric, distributions::DistString};
use sha2::Sha512;
use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    X25519,
    Ed25519,
    X448,
    Ed448,
}
impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::Ed25519 => "ed25519",
            Self::X448 => "x448",
            Self::Ed448 => "ed448",
        }
    }
    pub fn tag(self) -> u8 {
        match self {
            Self::X25519 => 0,
            Self::Ed25519 => 2,
            Self::X448 => 4,
            Self::Ed448 => 6,
        }
    }
    pub fn raw_len(self) -> usize {
        match self {
            Self::X25519 | Self::Ed25519 => 32,
            Self::X448 => 56,
            Self::Ed448 => 57,
        }
    }
    fn from_tag(tag: u8) -> Option<(Self, bool)> {
        Some(match tag {
            0 => (Self::X25519, false),
            1 => (Self::X25519, true),
            2 => (Self::Ed25519, false),
            3 => (Self::Ed25519, true),
            4 => (Self::X448, false),
            5 => (Self::X448, true),
            6 => (Self::Ed448, false),
            7 => (Self::Ed448, true),
            _ => return None,
        })
    }
    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "x25519" => Some(Self::X25519),
            "ed25519" => Some(Self::Ed25519),
            "x448" => Some(Self::X448),
            "ed448" => Some(Self::Ed448),
            _ => None,
        }
    }
}
pub fn detect_key_type(
    data: &[u8],
    algorithms: Option<&[&str]>,
    private: Option<bool>,
    ignore_errors: bool,
) -> Result<Option<(Vec<u8>, Algorithm, bool)>> {
    let parsed = (|| -> Result<(Vec<u8>, Algorithm, bool)> {
        let (&tag, key) = data
            .split_first()
            .ok_or_else(|| anyhow!("Missing key type tag"))?;
        let (algo, is_private) = Algorithm::from_tag(tag)
            .ok_or_else(|| anyhow!("Unknown key type tag"))?;
        if key.len() != algo.raw_len() {
            bail!(
                "Invalid {} key length: expected {}, got {}",
                algo.name(),
                algo.raw_len(),
                key.len()
            );
        }
        if let Some(allowed) = algorithms {
            if !allowed.iter().any(|name| *name == algo.name()) {
                bail!("Unexpected algorithm: {}, expected: {:?}", algo.name(), allowed);
            }
        }
        if let Some(expected_private) = private {
            if is_private != expected_private {
                bail!(
                    "Unexpected key type: {}, expected: {}",
                    if is_private { "private" } else { "public" },
                    if expected_private { "private" } else { "public" }
                );
            }
        }
        Ok((key.to_vec(), algo, is_private))
    })();
    match parsed {
        Ok(value) => Ok(Some(value)),
        Err(_) if ignore_errors => Ok(None),
        Err(error) => Err(error),
    }
}
pub fn frame_key(key: &[u8], algo: Algorithm, private: bool) -> Result<Vec<u8>> {
    if key.len() != algo.raw_len() {
        bail!(
            "Invalid {} key length: expected {}, got {}",
            algo.name(),
            algo.raw_len(),
            key.len()
        );
    }
    let mut framed = Vec::with_capacity(key.len() + 1);
    framed.push(algo.tag() + u8::from(private));
    framed.extend_from_slice(key);
    Ok(framed)
}
pub fn frame_key_named(key: &[u8], algo: &str, private: bool) -> Result<Vec<u8>> {
    let algo = Algorithm::from_name(algo)
        .ok_or_else(|| anyhow!("Unsupported algorithm: {algo:?}"))?;
    frame_key(key, algo, private)
}
pub fn frame_key_code(key: &[u8], algo: u8, private: bool) -> Result<Vec<u8>> {
    let algo = match algo {
        0 => Algorithm::X25519,
        2 => Algorithm::Ed25519,
        4 => Algorithm::X448,
        6 => Algorithm::Ed448,
        _ => bail!("Unsupported algorithm: {algo}"),
    };
    frame_key(key, algo, private)
}
pub fn gen_id(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), length)
}
pub fn gen_id_default() -> String {
    gen_id(64)
}
pub fn HASH(master_pw: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Blake3Hasher::new();
    hasher.update(master_pw);
    hasher.update(salt);
    let mut output = vec![0u8; length];
    hasher.finalize_xof().fill(&mut output);
    output
}
pub fn HASH_default(master_pw: &[u8], salt: &[u8]) -> Vec<u8> {
    HASH(master_pw, salt, 32)
}
pub fn HASH_hkdf(master_pw: &[u8], salt: &[u8], length: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), master_pw);
    let mut output = vec![0u8; length];
    hkdf.expand(b"kdf", &mut output)
        .map_err(|_| anyhow!("HKDF output length is too large"))?;
    Ok(output)
}
pub fn basic_kdf(master_pw: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    HASH(master_pw, salt, length)
}
pub fn basic_kdf_default(master_pw: &[u8], salt: &[u8]) -> Vec<u8> {
    basic_kdf(master_pw, salt, 32)
}
pub fn kdf_level(level: i64) -> Result<(u32, u32)> {
    if level < 0 {
        bail!("LEVEL must be a non-negative integer");
    }
    let l = level as f64;
    let time = (3.0 + 0.7 * l - 0.12 * l * l / 10.0).round();
    let memory = (131072.0 + 39321.6 * l).round();
    if time < 1.0 || time > u32::MAX as f64 || memory < 8.0 || memory > u32::MAX as f64 {
        bail!("Invalid Argon2 cost calculated for LEVEL={level}");
    }
    Ok((time as u32, memory as u32))
}
pub fn kdf(master_pw: &[u8], salt: &[u8], level: i64) -> Result<Vec<u8>> {
    let (time_cost, memory_cost) = kdf_level(level)?;
    let params = ArgonParams::new(memory_cost, time_cost, 1, Some(512))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e}"))?;
    let argon = Argon2::new(ArgonAlgorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut output = vec![0u8; 512];
    argon
        .hash_password_into(master_pw, salt, &mut output)
        .map_err(|e| anyhow!("Argon2id failed: {e}"))?;
    Ok(output)
}
pub fn kdf_default(master_pw: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    kdf(master_pw, salt, 5)
}
pub fn kdf_fast(master_pw: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    kdf(master_pw, salt, 0)
}
pub fn kdf_slow(master_pw: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    kdf(master_pw, salt, 10)
}
type Aes256Ctr = ctr::Ctr128BE<Aes256>;
fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    openssl::rand::rand_bytes(&mut bytes).context("generating random bytes")?;
    Ok(bytes)
}
pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let salt = random_bytes(32)?;
    let iv = random_bytes(16)?;
    let derived = basic_kdf(key, &salt, 32);
    let mut cipher = Aes256Ctr::new_from_slices(&derived, &iv)
        .map_err(|_| anyhow!("Invalid AES-CTR key or IV length"))?;
    let mut output = Vec::with_capacity(48 + data.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&salt);
    let mut encrypted = data.to_vec();
    for chunk in encrypted.chunks_mut(32768) {
        cipher.apply_keystream(chunk);
    }
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub fn decrypt(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 48 {
        bail!("Ciphertext too short");
    }
    let iv = &encrypted[..16];
    let salt = &encrypted[16..48];
    let derived = basic_kdf(key, salt, 32);
    let mut cipher = Aes256Ctr::new_from_slices(&derived, iv)
        .map_err(|_| anyhow!("Invalid AES-CTR key or IV length"))?;
    let mut output = encrypted[48..].to_vec();
    for chunk in output.chunks_mut(32768) {
        cipher.apply_keystream(chunk);
    }
    Ok(output)
}
pub fn encrypt_hkdf(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let salt = random_bytes(32)?;
    let iv = random_bytes(16)?;
    let derived = HASH_hkdf(key, &salt, 32)?;
    let mut cipher = Aes256Ctr::new_from_slices(&derived, &iv)
        .map_err(|_| anyhow!("Invalid AES-CTR key or IV length"))?;
    let mut output = Vec::with_capacity(48 + data.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&salt);
    let mut encrypted = data.to_vec();
    for chunk in encrypted.chunks_mut(32768) {
        cipher.apply_keystream(chunk);
    }
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub fn decrypt_hkdf(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < 48 {
        bail!("Ciphertext too short");
    }
    let iv = &encrypted[..16];
    let salt = &encrypted[16..48];
    let derived = HASH_hkdf(key, salt, 32)?;
    let mut cipher = Aes256Ctr::new_from_slices(&derived, iv)
        .map_err(|_| anyhow!("Invalid AES-CTR key or IV length"))?;
    let mut output = encrypted[48..].to_vec();
    for chunk in output.chunks_mut(32768) {
        cipher.apply_keystream(chunk);
    }
    Ok(output)
}
pub fn encryptGCM(data: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    let salt = random_bytes(32)?;
    let nonce = random_bytes(12)?;
    let derived = basic_kdf(key, &salt, 32);
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|_| anyhow!("Invalid AES-GCM key length"))?;
    let encrypted = cipher
        .encrypt(
            GcmNonce::from_slice(&nonce),
            Payload {
                msg: data,
                aad: aad.unwrap_or(&[]),
            },
        )
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    let mut output = Vec::with_capacity(44 + encrypted.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub fn decryptGCM(encrypted: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    if encrypted.len() < 60 {
        bail!("Ciphertext too short");
    }
    let nonce = &encrypted[..12];
    let salt = &encrypted[12..44];
    let derived = basic_kdf(key, salt, 32);
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|_| anyhow!("Invalid AES-GCM key length"))?;
    cipher
        .decrypt(
            GcmNonce::from_slice(nonce),
            Payload {
                msg: &encrypted[44..],
                aad: aad.unwrap_or(&[]),
            },
        )
        .map_err(|_| anyhow!("AES-GCM authentication failed"))
}
pub fn encryptGCM_hkdf(data: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    let salt = random_bytes(32)?;
    let nonce = random_bytes(12)?;
    let derived = HASH_hkdf(key, &salt, 32)?;
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|_| anyhow!("Invalid AES-GCM key length"))?;
    let encrypted = cipher
        .encrypt(
            GcmNonce::from_slice(&nonce),
            Payload { msg: data, aad: aad.unwrap_or(&[]) },
        )
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    let mut output = Vec::with_capacity(44 + encrypted.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub fn decryptGCM_hkdf(encrypted: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    if encrypted.len() < 60 {
        bail!("Ciphertext too short");
    }
    let nonce = &encrypted[..12];
    let salt = &encrypted[12..44];
    let derived = HASH_hkdf(key, salt, 32)?;
    let cipher = Aes256Gcm::new_from_slice(&derived)
        .map_err(|_| anyhow!("Invalid AES-GCM key length"))?;
    cipher
        .decrypt(
            GcmNonce::from_slice(nonce),
            Payload { msg: &encrypted[44..], aad: aad.unwrap_or(&[]) },
        )
        .map_err(|_| anyhow!("AES-GCM authentication failed"))
}
pub fn encryptGCM_default(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    encryptGCM(data, key, None)
}
pub fn decryptGCM_default(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    decryptGCM(encrypted, key, None)
}
pub fn gen_chacha20() -> Result<Vec<u8>> {
    random_bytes(32)
}
pub fn encrypt_chacha(data: &[u8], key: &[u8], auth: bool) -> Result<Vec<u8>> {
    let salt = random_bytes(32)?;
    let nonce = random_bytes(if auth { 12 } else { 16 })?;
    let derived = basic_kdf(key, &salt, 32);
    let encrypted = if auth {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&derived)
            .map_err(|_| anyhow!("Invalid ChaCha20-Poly1305 key length"))?;
        cipher
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&nonce),
                data,
            )
            .map_err(|_| anyhow!("ChaCha20-Poly1305 encryption failed"))?
    } else {
        let mut crypter = Crypter::new(
            OpenSslCipher::chacha20(),
            Mode::Encrypt,
            &derived,
            Some(&nonce),
        )
        .context("initializing ChaCha20")?;
        crypter.pad(false);
        let mut output = vec![0u8; data.len() + OpenSslCipher::chacha20().block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        output
    };
    let mut output = Vec::with_capacity(32 + nonce.len() + encrypted.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub fn encrypt_chacha_hkdf(data: &[u8], key: &[u8], auth: bool) -> Result<Vec<u8>> {
    let salt = random_bytes(32)?;
    let nonce = random_bytes(if auth { 12 } else { 16 })?;
    let derived = HASH_hkdf(key, &salt, 32)?;
    let encrypted = if auth {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&derived)
            .map_err(|_| anyhow!("Invalid ChaCha20-Poly1305 key length"))?;
        cipher
            .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), data)
            .map_err(|_| anyhow!("ChaCha20-Poly1305 encryption failed"))?
    } else {
        let mut crypter = Crypter::new(
            OpenSslCipher::chacha20(), Mode::Encrypt, &derived, Some(&nonce),
        ).context("initializing ChaCha20")?;
        crypter.pad(false);
        let mut output = vec![0u8; data.len() + OpenSslCipher::chacha20().block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        output
    };
    let mut output = Vec::with_capacity(32 + nonce.len() + encrypted.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub fn decrypt_chacha_hkdf(data: &[u8], key: &[u8], auth: bool) -> Result<Vec<u8>> {
    let nonce_len = if auth { 12 } else { 16 };
    if data.len() < 32 + nonce_len {
        bail!("Ciphertext too short");
    }
    let salt = &data[..32];
    let nonce = &data[32..32 + nonce_len];
    let ciphertext = &data[32 + nonce_len..];
    let derived = HASH_hkdf(key, salt, 32)?;
    if auth {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&derived)
            .map_err(|_| anyhow!("Invalid ChaCha20-Poly1305 key length"))?;
        cipher
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("ChaCha20-Poly1305 authentication failed"))
    } else {
        let mut crypter = Crypter::new(
            OpenSslCipher::chacha20(), Mode::Decrypt, &derived, Some(nonce),
        ).context("initializing ChaCha20")?;
        crypter.pad(false);
        let mut output = vec![0u8; ciphertext.len() + OpenSslCipher::chacha20().block_size()];
        let count = crypter.update(ciphertext, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}
pub fn encrypt_chacha_default(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    encrypt_chacha(data, key, true)
}
pub fn decrypt_chacha(data: &[u8], key: &[u8], auth: bool) -> Result<Vec<u8>> {
    let nonce_len = if auth { 12 } else { 16 };
    if data.len() < 32 + nonce_len {
        bail!("Ciphertext too short");
    }
    let salt = &data[..32];
    let nonce = &data[32..32 + nonce_len];
    let ciphertext = &data[32 + nonce_len..];
    let derived = basic_kdf(key, salt, 32);
    if auth {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&derived)
            .map_err(|_| anyhow!("Invalid ChaCha20-Poly1305 key length"))?;
        cipher
            .decrypt(chacha20poly1305::Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("ChaCha20-Poly1305 authentication failed"))
    } else {
        let mut crypter = Crypter::new(
            OpenSslCipher::chacha20(),
            Mode::Decrypt,
            &derived,
            Some(nonce),
        )
        .context("initializing ChaCha20")?;
        crypter.pad(false);
        let mut output = vec![0u8; ciphertext.len() + OpenSslCipher::chacha20().block_size()];
        let count = crypter.update(ciphertext, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}
pub fn decrypt_chacha_default(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    decrypt_chacha(data, key, true)
}
pub enum KeyInput {
    Bytes(Vec<u8>),
    Path(PathBuf),
}
impl From<Vec<u8>> for KeyInput {
    fn from(value: Vec<u8>) -> Self { Self::Bytes(value) }
}
impl From<&[u8]> for KeyInput {
    fn from(value: &[u8]) -> Self { Self::Bytes(value.to_vec()) }
}
impl From<&Vec<u8>> for KeyInput {
    fn from(value: &Vec<u8>) -> Self { Self::Bytes(value.clone()) }
}
impl<const N: usize> From<&[u8; N]> for KeyInput {
    fn from(value: &[u8; N]) -> Self { Self::Bytes(value.to_vec()) }
}
impl From<&str> for KeyInput {
    fn from(value: &str) -> Self { Self::Path(PathBuf::from(value)) }
}
impl From<String> for KeyInput {
    fn from(value: String) -> Self { Self::Path(PathBuf::from(value)) }
}
impl From<&String> for KeyInput {
    fn from(value: &String) -> Self { Self::Path(PathBuf::from(value)) }
}
impl From<PathBuf> for KeyInput {
    fn from(value: PathBuf) -> Self { Self::Path(value) }
}
impl From<&Path> for KeyInput {
    fn from(value: &Path) -> Self { Self::Path(value.to_path_buf()) }
}
impl From<&PathBuf> for KeyInput {
    fn from(value: &PathBuf) -> Self { Self::Path(value.clone()) }
}
pub enum LoadedKey {
    Private(PKey<Private>),
    Public(PKey<Public>),
    Certificate(X509),
}
impl LoadedKey {
    pub fn as_private(&self) -> Result<&PKey<Private>> {
        match self {
            Self::Private(key) => Ok(key),
            _ => bail!("Loaded object is not a private key"),
        }
    }
    pub fn as_public(&self) -> Result<PKey<Public>> {
        match self {
            Self::Private(key) => Ok(PKey::public_key_from_der(&key.public_key_to_der()?)?),
            Self::Public(key) => Ok(key.clone()),
            Self::Certificate(cert) => Ok(cert.public_key()?),
        }
    }
    pub fn as_certificate(&self) -> Result<&X509> {
        match self {
            Self::Certificate(cert) => Ok(cert),
            _ => bail!("Loaded object is not a certificate"),
        }
    }
}
fn read_key_input(input: KeyInput) -> Result<Vec<u8>> {
    match input {
        KeyInput::Bytes(bytes) => Ok(bytes),
        KeyInput::Path(path) => fs::read(&path)
            .with_context(|| format!("reading key file {}", path.display())),
    }
}
pub fn load_keys(
    key: impl Into<KeyInput>,
    password: Option<&[u8]>,
    key_type: i32,
    algorithms: Option<&[&str]>,
) -> Result<LoadedKey> {
    let bytes = read_key_input(key.into())?;
    let trimmed = bytes.iter().position(|b| !b.is_ascii_whitespace()).map(|i| &bytes[i..]).unwrap_or(&bytes);
    if trimmed.starts_with(b"-----BEGIN") {
        if (key_type == 0 || key_type == 1) && trimmed.windows(7).any(|w| w == b"PRIVATE") {
            let parsed = match password {
                Some(pass) => PKey::private_key_from_pem_passphrase(&bytes, pass),
                None => PKey::private_key_from_pem(&bytes),
            };
            return Ok(LoadedKey::Private(parsed.context("loading PEM private key")?));
        }
        if (key_type == 0 || key_type == 2) && trimmed.windows(6).any(|w| w == b"PUBLIC") {
            return Ok(LoadedKey::Public(PKey::public_key_from_pem(&bytes).context("loading PEM public key")?));
        }
        if (key_type == 0 || key_type == 2) && trimmed.windows(11).any(|w| w == b"CERTIFICATE") {
            let cert = X509::from_pem(&bytes).context("loading PEM certificate")?;
            return Ok(LoadedKey::Public(cert.public_key()?));
        }
        if (key_type == 0 || key_type == 3) && trimmed.windows(11).any(|w| w == b"CERTIFICATE") {
            return Ok(LoadedKey::Certificate(X509::from_pem(&bytes).context("loading PEM certificate")?));
        }
    }
    if key_type == 0 || key_type == 1 {
        let private = if let Some(pass) = password {
            PKey::private_key_from_pkcs8_passphrase(&bytes, pass)
                .or_else(|_| PKey::private_key_from_pem_passphrase(&bytes, pass))
                .or_else(|_| PKey::private_key_from_der(&bytes))
        } else {
            PKey::private_key_from_der(&bytes)
        };
        if let Ok(key) = private {
            return Ok(LoadedKey::Private(key));
        }
    }
    if key_type == 0 || key_type == 2 {
        if let Ok(key) = PKey::public_key_from_der(&bytes) {
            return Ok(LoadedKey::Public(key));
        }
    }
    if key_type == 0 || key_type == 3 {
        if let Ok(cert) = X509::from_der(&bytes) {
            return Ok(LoadedKey::Certificate(cert));
        }
    }
    let expected_private = match key_type {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    };
    if let Some((raw, algo, is_private)) = detect_key_type(&bytes, algorithms, expected_private, false)? {
        let id = match algo {
            Algorithm::X25519 => Id::X25519,
            Algorithm::Ed25519 => Id::ED25519,
            Algorithm::X448 => Id::X448,
            Algorithm::Ed448 => Id::ED448,
        };
        if is_private {
            return Ok(LoadedKey::Private(PKey::private_key_from_raw_bytes(&raw, id)
                .context("constructing raw private key")?));
        }
        return Ok(LoadedKey::Public(PKey::public_key_from_raw_bytes(&raw, id)
            .context("constructing raw public key")?));
    }
    bail!("Unsupported key format")
}
pub fn load_keys_default(key: impl Into<KeyInput>) -> Result<LoadedKey> {
    load_keys(key, None, 0, None)
}
pub fn load_certificate(cert: impl Into<KeyInput>) -> Result<X509> {
    let bytes = read_key_input(cert.into())?;
    if bytes.starts_with(b"-----BEGIN") {
        X509::from_pem(&bytes).context("loading PEM certificate")
    } else {
        X509::from_der(&bytes).context("loading DER certificate")
    }
}
pub fn get_pub(data: impl Into<KeyInput>, pem: bool) -> Result<Vec<u8>> {
    let loaded = load_keys(data, None, 0, None)?;
    let public = loaded.as_public()?;
    if !pem {
        match public.id() {
            Id::ED25519 => frame_key(&public.raw_public_key()?, Algorithm::Ed25519, false),
            Id::ED448 => frame_key(&public.raw_public_key()?, Algorithm::Ed448, false),
            Id::X25519 => frame_key(&public.raw_public_key()?, Algorithm::X25519, false),
            Id::X448 => frame_key(&public.raw_public_key()?, Algorithm::X448, false),
            _ => Ok(public.public_key_to_der()?),
        }
    } else {
        Ok(public.public_key_to_pem()?)
    }
}
pub fn get_pub_default(data: impl Into<KeyInput>) -> Result<Vec<u8>> {
    get_pub(data, false)
}
pub fn gen_x25519(overkill: bool) -> Result<(Vec<u8>, Vec<u8>)> {
    let (key, algo) = if overkill {
        (PKey::generate_x448()?, Algorithm::X448)
    } else {
        (PKey::generate_x25519()?, Algorithm::X25519)
    };
    let private = frame_key(&key.raw_private_key()?, algo, true)?;
    let public = frame_key(&key.raw_public_key()?, algo, false)?;
    Ok((private, public))
}
pub fn gen_x25519_default() -> Result<(Vec<u8>, Vec<u8>)> {
    gen_x25519(false)
}
pub fn shared_secret(prv: &[u8], pub_key: &[u8]) -> Result<Vec<u8>> {
    if prv.len() != pub_key.len() {
        bail!("Key length mismatch: {} {}", prv.len(), pub_key.len());
    }
    let allowed = ["x25519", "x448"];
    let private = load_keys(prv, None, 1, Some(&allowed))?;
    let public = load_keys(pub_key, None, 2, Some(&allowed))?;
    let private = private.as_private()?;
    let public = public.as_public()?;
    let mut deriver = Deriver::new(private)?;
    deriver.set_peer(&public)?;
    Ok(deriver.derive_to_vec()?)
}
pub fn gen_ed25519(overkill: bool) -> Result<(Vec<u8>, Vec<u8>)> {
    let (key, algo) = if overkill {
        (PKey::generate_ed448()?, Algorithm::Ed448)
    } else {
        (PKey::generate_ed25519()?, Algorithm::Ed25519)
    };
    let private = frame_key(&key.raw_private_key()?, algo, true)?;
    let public = frame_key(&key.raw_public_key()?, algo, false)?;
    Ok((private, public))
}
pub fn gen_ed25519_default() -> Result<(Vec<u8>, Vec<u8>)> {
    gen_ed25519(false)
}
pub fn ed25519_sign(prv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let allowed = ["ed25519", "ed448"];
    let key = load_keys(prv, None, 1, Some(&allowed))?;
    let key = key.as_private()?;
    let mut signer = Signer::new_without_digest(key)?;
    let signature = signer.sign_oneshot_to_vec(data)?;
    let mut output = Vec::with_capacity(signature.len() + data.len());
    output.extend_from_slice(&signature);
    output.extend_from_slice(data);
    Ok(output)
}
pub fn ed25519_verify(pub_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let parsed = detect_key_type(pub_key, Some(&["ed25519", "ed448"]), Some(false), false)?
        .ok_or_else(|| anyhow!("Invalid framed public key"))?;
    let sig_len = if parsed.0.len() == 57 { 114 } else { 64 };
    if data.len() < sig_len {
        bail!("Invalid signature packet: too short");
    }
    let key = load_keys(pub_key, None, 2, None)?;
    let key = key.as_public()?;
    let signature = &data[..sig_len];
    let message = &data[sig_len..];
    let mut verifier = Verifier::new_without_digest(&key)?;
    if !verifier.verify_oneshot(signature, message)? {
        bail!("Signature verification failed");
    }
    Ok(message.to_vec())
}
fn ec_signature_digest(key: &PKey<Private>) -> Result<MessageDigest> {
    let ec = key.ec_key()?;
    Ok(match ec.group().curve_name() {
        Some(Nid::SECP384R1) => MessageDigest::sha384(),
        Some(Nid::SECP521R1) => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    })
}
fn ec_public_signature_digest(key: &PKey<Public>) -> Result<MessageDigest> {
    let ec = key.ec_key()?;
    Ok(match ec.group().curve_name() {
        Some(Nid::SECP384R1) => MessageDigest::sha384(),
        Some(Nid::SECP521R1) => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    })
}
pub fn sign(prv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if detect_key_type(prv, Some(&["ed25519", "ed448"]), Some(true), true)?.is_some() {
        if let Ok(packet) = ed25519_sign(prv, data) {
            return Ok(packet);
        }
    }
    let loaded = load_keys(prv, None, 1, None)?;
    let key = loaded.as_private()?;
    let signature = if key.id() == Id::EC {
        let md = ec_signature_digest(key)?;
        let mut signer = Signer::new(md, key)?;
        signer.update(data)?;
        signer.sign_to_vec()?
    } else if key.id() == Id::RSA || key.id() == Id::RSA_PSS {
        let mut signer = Signer::new(MessageDigest::sha256(), key)?;
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::MAXIMUM_LENGTH)?;
        signer.update(data)?;
        signer.sign_to_vec()?
    } else {
        bail!("Unsupported private key type for signing: {:?}", key.id());
    };
    let length = i64::try_from(signature.len()).context("signature is too large")?;
    let mut packet = Vec::with_capacity(8 + signature.len() + data.len());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&signature);
    packet.extend_from_slice(data);
    Ok(packet)
}
pub fn verify(pub_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 8 {
        bail!("Invalid signature packet: too short");
    }
    let signed_len = i64::from_be_bytes(data[..8].try_into().unwrap());
    if signed_len >= 0 && data.len() < 8usize.saturating_add(signed_len as usize) {
        bail!("Invalid signature packet length");
    }
    if detect_key_type(pub_key, Some(&["ed25519", "ed448"]), Some(false), true)?.is_some() {
        if let Ok(message) = ed25519_verify(pub_key, data) {
            return Ok(message);
        }
    }
    if signed_len < 0 {
        bail!("Invalid signature packet length");
    }
    let sig_start = 8;
    let sig_end = sig_start + signed_len as usize;
    let signature = &data[sig_start..sig_end];
    let message = &data[sig_end..];
    let loaded = load_keys(pub_key, None, 2, None)?;
    let key = loaded.as_public()?;
    let valid = if key.id() == Id::EC {
        let md = ec_public_signature_digest(&key)?;
        let mut verifier = Verifier::new(md, &key)?;
        verifier.update(message)?;
        verifier.verify(signature)?
    } else if key.id() == Id::RSA || key.id() == Id::RSA_PSS {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::MAXIMUM_LENGTH)?;
        verifier.update(message)?;
        verifier.verify(signature)?
    } else {
        bail!("Unsupported public key type for verification: {:?}", key.id());
    };
    if !valid {
        bail!("Signature verification failed");
    }
    Ok(message.to_vec())
}
fn make_subject(
    common_name: Option<&str>,
    country: Option<&str>,
    state: Option<&str>,
    locality: Option<&str>,
    organization: Option<&str>,
    organizational_unit: Option<&str>,
    email: Option<&str>,
) -> Result<X509Name> {
    let mut name = X509NameBuilder::new()?;
    for (field, value) in [
        ("CN", common_name),
        ("C", country),
        ("ST", state),
        ("L", locality),
        ("O", organization),
        ("OU", organizational_unit),
        ("emailAddress", email),
    ] {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            name.append_entry_by_text(field, value)?;
        }
    }
    Ok(name.build())
}
fn random_serial_number() -> Result<Asn1Integer> {
    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::ONE, false)?;
    Ok(serial.to_asn1_integer()?)
}
fn cert_times(valid_days: i64) -> Result<(Asn1Time, Asn1Time)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs() as i64;
    let before = Asn1Time::from_unix(now - 86400)?;
    let after = Asn1Time::from_unix(now.saturating_add(valid_days.saturating_mul(86400)))?;
    Ok((before, after))
}
fn write_key_private(
    path: &str,
    key: &PKey<Private>,
    password: Option<&[u8]>,
) -> Result<()> {
    let pem = path.to_ascii_lowercase().ends_with(".pem");
    let password = password.filter(|pass| !pass.is_empty());
    let bytes = match (pem, password) {
        (true, Some(pass)) => key.private_key_to_pem_pkcs8_passphrase(OpenSslCipher::aes_256_cbc(), pass)?,
        (false, Some(pass)) => key.private_key_to_pkcs8_passphrase(OpenSslCipher::aes_256_cbc(), pass)?,
        (true, None) => key.private_key_to_pem_pkcs8()?,
        (false, None) => key.private_key_to_pkcs8()?,
    };
    fs::write(path, bytes).with_context(|| format!("writing private key {path}"))?;
    Ok(())
}
fn write_key_public(path: &str, key: &PKey<Public>) -> Result<()> {
    let bytes = if path.to_ascii_lowercase().ends_with(".pem") {
        key.public_key_to_pem()?
    } else {
        key.public_key_to_der()?
    };
    fs::write(path, bytes).with_context(|| format!("writing public key {path}"))?;
    Ok(())
}
fn cert_to_path(cert: &X509, path: &str) -> Result<()> {
    let bytes = if path.to_ascii_lowercase().ends_with(".pem") {
        cert.to_pem()?
    } else {
        cert.to_der()?
    };
    fs::write(path, bytes).with_context(|| format!("writing certificate {path}"))?;
    Ok(())
}
pub fn generate_tls(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    common_name: Option<&str>,
    country: Option<&str>,
    state: Option<&str>,
    locality: Option<&str>,
    organization: Option<&str>,
    organizational_unit: Option<&str>,
    email: Option<&str>,
    valid_days: i64,
    san_ips: Option<&[String]>,
    san_dns: Option<&[String]>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    if cert_path.map(Path::new).map(Path::exists).unwrap_or(false)
        && key_path.map(Path::new).map(Path::exists).unwrap_or(false)
    {
        return Ok(None);
    }
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let ec_key = EcKey::generate(&group)?;
    let key = PKey::from_ec_key(ec_key)?;
    let subject = make_subject(
        common_name, country, state, locality, organization, organizational_unit, email,
    )?;
    let (not_before, not_after) = cert_times(valid_days)?;
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    builder.set_pubkey(&key)?;
    builder.set_serial_number(&random_serial_number()?)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    let basic = BasicConstraints::new().critical().build()?;
    builder.append_extension(basic)?;
    let ips = san_ips.unwrap_or(&[]);
    let dns = san_dns.unwrap_or(&[]);
    if !ips.is_empty() || !dns.is_empty() {
        let mut san = SubjectAlternativeName::new();
        for ip in ips {
            let parsed: IpAddr = ip.parse().with_context(|| format!("invalid SAN IP address: {ip}"))?;
            san.ip(&parsed.to_string());
        }
        for host in dns {
            san.dns(host);
        }
        let extension = {
            let context = builder.x509v3_context(None, None);
            san.build(&context)?
        };
        builder.append_extension(extension)?;
    }
    builder.sign(&key, MessageDigest::sha384())?;
    let cert = builder.build();
    let private_pem = key.private_key_to_pem_pkcs8()?;
    let cert_pem = cert.to_pem()?;
    if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        fs::write(key_path, &private_pem).with_context(|| format!("writing TLS key {key_path}"))?;
        fs::write(cert_path, &cert_pem).with_context(|| format!("writing TLS certificate {cert_path}"))?;
    }
    Ok(Some((private_pem, cert_pem)))
}
pub fn generate_tls_default(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    generate_tls(
        cert_path, key_path, Some("TLS Certificate"), None, None, None, None, None, None,
        3650, None, None,
    )
}
pub fn gen_CA(
    prv_path: &str,
    pub_path: &str,
    cert_path: &str,
    password: Option<&[u8]>,
    common_name: Option<&str>,
    country: Option<&str>,
    state: Option<&str>,
    locality: Option<&str>,
    organization: Option<&str>,
    organizational_unit: Option<&str>,
    email: Option<&str>,
    valid_days: i64,
    overkill: bool,
) -> Result<()> {
    let private = if overkill { PKey::generate_ed448()? } else { PKey::generate_ed25519()? };
    let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
    let subject = make_subject(
        common_name, country, state, locality, organization, organizational_unit, email,
    )?;
    let (not_before, not_after) = cert_times(valid_days)?;
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(&subject)?;
    builder.set_pubkey(&public)?;
    builder.set_serial_number(&random_serial_number()?)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.sign(&private, MessageDigest::null())?;
    let cert = builder.build();
    write_key_private(prv_path, &private, password)?;
    write_key_public(pub_path, &public)?;
    cert_to_path(&cert, cert_path)?;
    Ok(())
}
pub fn gen_CA_default(prv_path: &str, pub_path: &str, cert_path: &str) -> Result<()> {
    gen_CA(
        prv_path, pub_path, cert_path, None, None, None, None, None, None, None, None,
        3650, false,
    )
}
pub fn gen_keys(
    prv_path: &str,
    pub_path: &str,
    cert_path: &str,
    ca_prv: impl Into<KeyInput>,
    ca_cert: impl Into<KeyInput>,
    password: Option<&[u8]>,
    common_name: Option<&str>,
    country: Option<&str>,
    state: Option<&str>,
    locality: Option<&str>,
    organization: Option<&str>,
    organizational_unit: Option<&str>,
    email: Option<&str>,
    valid_days: i64,
    overkill: bool,
) -> Result<()> {
    let private = if overkill { PKey::generate_ed448()? } else { PKey::generate_ed25519()? };
    let public = PKey::public_key_from_der(&private.public_key_to_der()?)?;
    let ca_private_loaded = load_keys(ca_prv, password, 1, None)?;
    let ca_private = ca_private_loaded.as_private()?;
    let issuer_cert = load_certificate(ca_cert)?;
    let subject = make_subject(
        common_name, country, state, locality, organization, organizational_unit, email,
    )?;
    let (not_before, not_after) = cert_times(valid_days)?;
    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&subject)?;
    builder.set_issuer_name(issuer_cert.subject_name())?;
    builder.set_pubkey(&public)?;
    builder.set_serial_number(&random_serial_number()?)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.sign(ca_private, MessageDigest::null())?;
    let cert = builder.build();
    let password = password.filter(|pass| !pass.is_empty());
    let private_bytes = match password {
        Some(pass) => private.private_key_to_pkcs8_passphrase(OpenSslCipher::aes_256_cbc(), pass)?,
        None => private.private_key_to_pkcs8()?,
    };
    fs::write(prv_path, private_bytes).with_context(|| format!("writing private key {prv_path}"))?;
    fs::write(pub_path, public.public_key_to_der()?)
        .with_context(|| format!("writing public key {pub_path}"))?;
    fs::write(cert_path, cert.to_der()?)
        .with_context(|| format!("writing certificate {cert_path}"))?;
    Ok(())
}
pub fn gen_keys_default(
    prv_path: &str,
    pub_path: &str,
    cert_path: &str,
    ca_prv: impl Into<KeyInput>,
    ca_cert: impl Into<KeyInput>,
) -> Result<()> {
    gen_keys(
        prv_path, pub_path, cert_path, ca_prv, ca_cert, None, None, None, None, None, None,
        None, None, 3650, false,
    )
}
pub fn validate_keys(
    prv: impl Into<KeyInput>,
    pub_key: impl Into<KeyInput>,
    cert: Option<KeyInput>,
) -> Result<bool> {
    let private_loaded = load_keys(prv, None, 1, None)?;
    let public_loaded = load_keys(pub_key, None, 2, None)?;
    let private = private_loaded.as_private()?;
    let public = public_loaded.as_public()?;
    let public_bytes = public.raw_public_key()?;
    let derived_bytes = private.raw_public_key()?;
    if derived_bytes.len() != public_bytes.len() || !bool::from(derived_bytes.as_slice().ct_eq(public_bytes.as_slice())) {
        return Ok(false);
    }
    if let Some(cert_input) = cert {
        let certificate = load_certificate(cert_input)?;
        let cert_public = certificate.public_key()?.raw_public_key()?;
        if cert_public.len() != public_bytes.len() || !bool::from(cert_public.as_slice().ct_eq(public_bytes.as_slice())) {
            return Ok(false);
        }
    }
    Ok(true)
}
pub fn certificate_public_key(cert: impl Into<KeyInput>, pem: bool) -> Result<Vec<u8>> {
    let certificate = load_certificate(cert)?;
    let public = certificate.public_key()?;
    if pem {
        Ok(public.public_key_to_pem()?)
    } else {
        match public.id() {
            Id::ED25519 => frame_key(&public.raw_public_key()?, Algorithm::Ed25519, false),
            Id::ED448 => frame_key(&public.raw_public_key()?, Algorithm::Ed448, false),
            Id::X25519 => frame_key(&public.raw_public_key()?, Algorithm::X25519, false),
            Id::X448 => frame_key(&public.raw_public_key()?, Algorithm::X448, false),
            _ => Ok(public.public_key_to_der()?),
        }
    }
}
