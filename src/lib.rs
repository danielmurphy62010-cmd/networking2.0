#![allow(non_snake_case)]
pub mod backend;
#[allow(non_snake_case)]
pub mod Encryption;
#[cfg(test)]
mod tests {
    use super::{backend, Encryption};
    #[test]
    fn encryption_ctr_round_trip() {
        let key = b"test encryption key";
        let plaintext = b"CTR encryption round-trip test";
        let ciphertext = Encryption::encrypt(plaintext, key)
            .expect("AES-CTR encryption should succeed");
        let decrypted = Encryption::decrypt(&ciphertext, key)
            .expect("AES-CTR decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }
    #[test]
    fn encryption_gcm_round_trip() {
        let key = b"test encryption key";
        let plaintext = b"GCM encryption round-trip test";
        let aad = b"test associated data";
        let ciphertext = Encryption::encryptGCM(plaintext, key, Some(aad))
            .expect("AES-GCM encryption should succeed");
        let decrypted = Encryption::decryptGCM(&ciphertext, key, Some(aad))
            .expect("AES-GCM decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }
    #[test]
    fn encryption_chacha20_poly1305_round_trip() {
        let key = b"test encryption key";
        let plaintext = b"ChaCha20-Poly1305 round-trip test";
        let ciphertext = Encryption::encrypt_chacha_default(plaintext, key)
            .expect("ChaCha20-Poly1305 encryption should succeed");
        let decrypted = Encryption::decrypt_chacha_default(&ciphertext, key)
            .expect("ChaCha20-Poly1305 decryption should succeed");
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }
    #[test]
    fn encryption_x25519_shared_secrets_match() {
        let (private_a, public_a) = Encryption::gen_x25519_default()
            .expect("first X25519 keypair should be generated");
        let (private_b, public_b) = Encryption::gen_x25519_default()
            .expect("second X25519 keypair should be generated");
        let secret_ab = Encryption::shared_secret(&private_a, &public_b)
            .expect("first shared secret should be derived");
        let secret_ba = Encryption::shared_secret(&private_b, &public_a)
            .expect("second shared secret should be derived");
        assert_eq!(secret_ab, secret_ba);
    }
    #[test]
    fn encryption_ed25519_sign_and_verify() {
        let (private_key, public_key) = Encryption::gen_ed25519_default()
            .expect("Ed25519 keypair should be generated");
        let message = b"Ed25519 signing test";
        let packet = Encryption::ed25519_sign(&private_key, message)
            .expect("Ed25519 signing should succeed");
        let recovered = Encryption::ed25519_verify(&public_key, &packet)
            .expect("Ed25519 signature should verify");
        assert_eq!(recovered.as_slice(), message.as_slice());
    }
    #[tokio::test]
    async fn backend_server_can_start_and_stop() {
        let server = backend::Server::new(
            "127.0.0.1",
            0,
            backend::ServerCallbacks::default(),
            1,
            1,
        )
        .expect("backend server should be constructed");
        assert_ne!(server.magic1(), server.magic2());
        server.start().await.expect("backend server should start");
        server.stop().await;
    }
}