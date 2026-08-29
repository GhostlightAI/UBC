//! UBC identity and addressing

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crc::{Crc, CRC_8_SMBUS};

/// UBC address: 15 digits + 1 letter (base-36)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(String);

impl Address {
    /// Create from string, validating format
    pub fn from_string(s: &str) -> Result<Self, IdentityError> {
        if s.len() != 16 {
            return Err(IdentityError::InvalidAddressLength);
        }
        
        // Validate base-36 characters
        for (i, c) in s.chars().enumerate() {
            let valid = if i < 15 {
                c.is_ascii_digit() || (c.is_ascii_uppercase() && c.is_ascii_alphabetic())
            } else {
                c.is_ascii_uppercase() && c.is_ascii_alphabetic()
            };
            
            if !valid {
                return Err(IdentityError::InvalidAddressCharacter);
            }
        }
        
        // Verify checksum
        let (body, checksum) = s.split_at(15);
        let expected = Self::compute_checksum(body);
        if checksum != expected {
            return Err(IdentityError::InvalidChecksum);
        }
        
        Ok(Address(s.to_string()))
    }
    
    /// Derive address from public key
    pub fn from_public_key(public_key: &VerifyingKey) -> Self {
        let bytes = public_key.as_bytes();
        let body = Self::base36_encode(&bytes[0..12]);
        let checksum = Self::compute_checksum(&body);
        Address(format!("{}{}", body, checksum))
    }
    
    fn base36_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut num = u128::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            0, 0, 0, 0,
        ]);
        
        let mut result = String::with_capacity(15);
        for _ in 0..15 {
            let idx = (num % 36) as usize;
            result.push(ALPHABET[idx] as char);
            num /= 36;
        }
        result.chars().rev().collect()
    }
    
    fn compute_checksum(body: &str) -> String {
        const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let crc = Crc::<u8>::new(&CRC_8_SMBUS);
        let mut digest = crc.digest();
        digest.update(body.as_bytes());
        // Spec: the final character is always a LETTER. Map the CRC into the
        // 26 letter slots (indices 10..36) rather than the full base-36 range.
        let idx = 10 + (digest.finalize() % 26) as usize;
        (ALPHABET[idx] as char).to_string()
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// UBC identity: Ed25519 keypair + derived address
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    address: Address,
}

impl Identity {
    /// Generate new random identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let address = Address::from_public_key(&verifying_key);
        
        Identity {
            signing_key,
            verifying_key,
            address,
        }
    }
    
    /// Restore from private key bytes
    pub fn from_private_key(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let address = Address::from_public_key(&verifying_key);
        
        Ok(Identity {
            signing_key,
            verifying_key,
            address,
        })
    }
    
    /// Get UBC address
    pub fn address(&self) -> &Address {
        &self.address
    }
    
    /// Get public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, signature).is_ok()
    }
    
    /// Export private key (keep secret!)
    pub fn export_private_key(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Address must be 16 characters")]
    InvalidAddressLength,
    
    #[error("Invalid character in address")]
    InvalidAddressCharacter,
    
    #[error("Invalid checksum")]
    InvalidChecksum,
    
    #[error("Invalid private key")]
    InvalidPrivateKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_generation() {
        let identity = Identity::generate();
        let address = identity.address();
        
        assert_eq!(address.as_str().len(), 16);
        println!("Generated address: {}", address);
    }
    
    #[test]
    fn test_address_roundtrip() {
        let identity = Identity::generate();
        let address_str = identity.address().as_str();
        
        let parsed = Address::from_string(address_str).unwrap();
        assert_eq!(parsed.as_str(), address_str);
    }
    
    #[test]
    fn test_sign_verify() {
        let identity = Identity::generate();
        let message = b"Hello, UBC!";
        
        let signature = identity.sign(message);
        assert!(identity.verify(message, &signature));
    }
}
