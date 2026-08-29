//! UBC message envelope: signed, end-to-end encrypted frames.

use crate::crypto::SessionKey;
use crate::identity::Identity;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Text,
    File,
    Voice,
    Control,
}

/// The wire envelope (spec §Message Envelope). `payload` is base64 of the
/// sealed (encrypted) body; `signature` signs the canonical fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub from: String,
    pub to: String,
    pub tunnel_id: String,
    pub seq: u64,
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    pub payload: String, // base64(sealed bytes)
    pub timestamp: u64,
    pub signature: String, // base64(ed25519 signature)
}

impl Message {
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Bytes that get signed: everything but the signature itself.
    fn signing_bytes(from: &str, to: &str, tunnel_id: &str, seq: u64, payload: &str, ts: u64) -> Vec<u8> {
        format!("{from}|{to}|{tunnel_id}|{seq}|{payload}|{ts}").into_bytes()
    }

    /// Build + encrypt + sign a message.
    pub fn seal(
        identity: &Identity,
        to: &str,
        tunnel_id: &str,
        seq: u64,
        msg_type: MessageType,
        plaintext: &[u8],
        key: &SessionKey,
    ) -> Result<Self, MessageError> {
        let sealed = key
            .seal(plaintext)
            .map_err(|_| MessageError::Crypto)?;
        let payload = B64.encode(sealed);
        let ts = Self::now();
        let from = identity.address().as_str().to_string();
        let sig = identity.sign(&Self::signing_bytes(&from, to, tunnel_id, seq, &payload, ts));
        Ok(Message {
            from,
            to: to.to_string(),
            tunnel_id: tunnel_id.to_string(),
            seq,
            msg_type,
            payload,
            timestamp: ts,
            signature: B64.encode(sig.to_bytes()),
        })
    }

    /// Verify the sender's signature against their claimed address's key.
    pub fn verify(&self, sender_public: &VerifyingKey) -> Result<(), MessageError> {
        let sig_bytes = B64
            .decode(&self.signature)
            .map_err(|_| MessageError::BadEncoding)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| MessageError::BadSignature)?;
        let bytes = Self::signing_bytes(
            &self.from, &self.to, &self.tunnel_id, self.seq, &self.payload, self.timestamp,
        );
        sender_public
            .verify(&bytes, &sig)
            .map_err(|_| MessageError::BadSignature)
    }

    /// Decrypt the payload (call `verify` first).
    pub fn open(&self, key: &SessionKey) -> Result<Vec<u8>, MessageError> {
        let sealed = B64.decode(&self.payload).map_err(|_| MessageError::BadEncoding)?;
        key.open(&sealed).map_err(|_| MessageError::Crypto)
    }
}

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("bad base64 encoding")]
    BadEncoding,
    #[error("invalid signature")]
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeypair;

    #[test]
    fn test_message_roundtrip() {
        let alice_id = Identity::generate();
        let bob_id = Identity::generate();

        let alice_kp = SessionKeypair::generate();
        let bob_kp = SessionKeypair::generate();
        let alice_pub = alice_kp.public;
        let bob_pub = bob_kp.public;
        let alice_key = alice_kp.agree(&bob_pub);
        let bob_key = bob_kp.agree(&alice_pub);

        let msg = Message::seal(
            &alice_id,
            bob_id.address().as_str(),
            "550e8400-e29b-41d4-a716-446655440000",
            1,
            MessageType::Text,
            b"hello bob",
            &alice_key,
        )
        .unwrap();

        msg.verify(alice_id.public_key()).unwrap();
        let plain = msg.open(&bob_key).unwrap();
        assert_eq!(plain, b"hello bob");

        // tamper → signature must fail
        let mut forged = msg.clone();
        forged.payload = B64.encode(b"garbage-garbage");
        assert!(forged.verify(alice_id.public_key()).is_err());
    }

    #[test]
    fn test_envelope_serde_shape() {
        let json = r#"{"from":"A","to":"B","tunnel_id":"t","seq":1,"type":"text","payload":"eA","timestamp":1,"signature":"eA"}"#;
        let m: Message = serde_json::from_str(json).unwrap();
        assert_eq!(m.msg_type, MessageType::Text);
        assert_eq!(serde_json::to_string(&m).unwrap(), json);
    }
}
