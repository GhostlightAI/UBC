//! UBC session cryptography: X25519 key exchange + ChaCha20-Poly1305.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

/// An ephemeral X25519 keypair for one session (forward secrecy: never reused).
pub struct SessionKeypair {
    secret: StaticSecret,
    pub public: X25519Public,
}

impl SessionKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(AeadOsRng);
        let public = X25519Public::from(&secret);
        SessionKeypair { secret, public }
    }

    /// ECDH → a shared 32-byte session key with the peer's public key.
    pub fn agree(self, peer_public: &X25519Public) -> SessionKey {
        let shared = self.secret.diffie_hellman(peer_public);
        SessionKey {
            cipher: ChaCha20Poly1305::new(Key::from_slice(shared.as_bytes())),
        }
    }
}

pub struct SessionKey {
    cipher: ChaCha20Poly1305,
}

impl SessionKey {
    /// Encrypt `plaintext`; returns nonce ‖ ciphertext (nonce is 12 bytes, random).
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Encrypt)?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a buffer produced by `seal` (nonce ‖ ciphertext).
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() < 12 {
            return Err(CryptoError::Malformed);
        }
        let (nonce_bytes, ct) = sealed.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ct)
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("malformed sealed message")]
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_roundtrip() {
        let alice = SessionKeypair::generate();
        let bob = SessionKeypair::generate();

        let alice_pub = alice.public;
        let bob_pub = bob.public;

        let alice_key = alice.agree(&bob_pub);
        let bob_key = bob.agree(&alice_pub);

        let msg = b"UBC secret message";
        let sealed = alice_key.seal(msg).unwrap();
        let opened = bob_key.open(&sealed).unwrap();

        assert_eq!(msg.as_slice(), opened.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let alice = SessionKeypair::generate();
        let bob = SessionKeypair::generate();
        let eve = SessionKeypair::generate();

        let bob_pub = bob.public;
        let eve_pub = eve.public;

        let alice_key = alice.agree(&bob_pub);
        let eve_key = eve.agree(&eve_pub); // not the shared key

        let sealed = alice_key.seal(b"secret").unwrap();
        assert!(eve_key.open(&sealed).is_err());
    }
}
