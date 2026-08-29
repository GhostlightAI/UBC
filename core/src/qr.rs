//! UBC QR payload: build, sign, parse, and render pairing QR codes.
//!
//! Format (spec §QR Code Format):
//!   ubc:<address>?t=<type>&r=<relay>&exp=<expiry>&sig=<signature>

use crate::identity::{Address, Identity};
use crate::tunnel::TunnelType;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct QrPayload {
    pub address: String,
    pub tunnel_type: TunnelType,
    pub relay: Option<String>,
    pub expiry: Option<u64>,
    pub signature: String,
}

impl QrPayload {
    /// Signed pairing payload for `identity`. Signs addr|type|relay|exp.
    pub fn create(identity: &Identity, tunnel_type: TunnelType, relay: Option<&str>, expiry: Option<u64>) -> Self {
        let address = identity.address().as_str().to_string();
        let signing = Self::signing_string(&address, tunnel_type, relay, expiry);
        let sig = identity.sign(signing.as_bytes());
        QrPayload {
            address,
            tunnel_type,
            relay: relay.map(str::to_string),
            expiry,
            signature: B64URL.encode(sig.to_bytes()),
        }
    }

    fn signing_string(address: &str, t: TunnelType, relay: Option<&str>, exp: Option<u64>) -> String {
        format!(
            "{}|{}|{}|{}",
            address,
            t,
            relay.unwrap_or(""),
            exp.map(|e| e.to_string()).unwrap_or_default()
        )
    }

    /// The `ubc:...` string to encode in the QR image.
    pub fn to_uri(&self) -> String {
        let mut uri = format!("ubc:{}?t={}", self.address, self.tunnel_type);
        if let Some(r) = &self.relay {
            uri.push_str(&format!("&r={}", urlencoding(r)));
        }
        if let Some(e) = self.expiry {
            uri.push_str(&format!("&exp={}", e));
        }
        uri.push_str(&format!("&sig={}", self.signature));
        uri
    }

    /// Parse a `ubc:...` URI back into a payload (signature NOT yet verified).
    pub fn parse(uri: &str) -> Result<Self, QrError> {
        let rest = uri.strip_prefix("ubc:").ok_or(QrError::BadPrefix)?;
        let (address, query) = rest.split_once('?').ok_or(QrError::MissingQuery)?;
        Address::from_string(address).map_err(|_| QrError::BadAddress)?;

        let mut t = None;
        let mut r = None;
        let mut exp = None;
        let mut sig = None;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').ok_or(QrError::Malformed)?;
            match k {
                "t" => t = Some(v.parse::<TunnelType>().map_err(|_| QrError::BadType)?),
                "r" => r = Some(urldecode(v)),
                "exp" => exp = Some(v.parse::<u64>().map_err(|_| QrError::Malformed)?),
                "sig" => sig = Some(v.to_string()),
                _ => {} // forward-compatible: ignore unknown params
            }
        }
        Ok(QrPayload {
            address: address.to_string(),
            tunnel_type: t.ok_or(QrError::MissingField("t"))?,
            relay: r,
            expiry: exp,
            signature: sig.ok_or(QrError::MissingField("sig"))?,
        })
    }

    /// Verify the embedded signature against the claimed address's pubkey.
    /// Caller must obtain the pubkey for `address` out-of-band (first-contact
    /// trust, directory, or a prior tunnel).
    pub fn verify(&self, public_key: &VerifyingKey) -> Result<(), QrError> {
        let sig_bytes = B64URL.decode(&self.signature).map_err(|_| QrError::BadSignature)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| QrError::BadSignature)?;
        let signing = Self::signing_string(
            &self.address,
            self.tunnel_type,
            self.relay.as_deref(),
            self.expiry,
        );
        public_key
            .verify(signing.as_bytes(), &sig)
            .map_err(|_| QrError::BadSignature)
    }

    pub fn is_expired(&self) -> bool {
        match self.expiry {
            Some(exp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                now > exp
            }
            None => false,
        }
    }
}

/// Render a `ubc:` URI as a PNG QR code (for display/sharing).
pub fn generate_qr(payload: &QrPayload) -> Result<Vec<u8>, QrError> {
    let code = qrcode::QrCode::new(payload.to_uri().as_bytes())
        .map_err(|_| QrError::Encode)?;
    let image = code.render::<image::Luma<u8>>().min_dimensions(320, 320).build();
    let mut png = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png);
    use image::ImageEncoder;
    encoder
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::L8,
        )
        .map_err(|_| QrError::Encode)?;
    Ok(png)
}

pub fn parse_qr(uri: &str) -> Result<QrPayload, QrError> {
    QrPayload::parse(uri)
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug, Error)]
pub enum QrError {
    #[error("missing ubc: prefix")]
    BadPrefix,
    #[error("missing query string")]
    MissingQuery,
    #[error("invalid address")]
    BadAddress,
    #[error("invalid tunnel type")]
    BadType,
    #[error("malformed parameter")]
    Malformed,
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid signature")]
    BadSignature,
    #[error("QR encode failed")]
    Encode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_roundtrip() {
        let id = Identity::generate();
        let payload = QrPayload::create(&id, TunnelType::Session, Some("wss://relay.example.com"), Some(1999999999));
        let uri = payload.to_uri();
        let parsed = QrPayload::parse(&uri).unwrap();

        assert_eq!(parsed.address, id.address().as_str());
        assert_eq!(parsed.tunnel_type, TunnelType::Session);
        assert_eq!(parsed.relay.as_deref(), Some("wss://relay.example.com"));
        assert_eq!(parsed.expiry, Some(1999999999));
        parsed.verify(id.public_key()).unwrap();
        assert!(!parsed.is_expired());
    }

    #[test]
    fn test_tampered_qr_rejected() {
        let id = Identity::generate();
        let payload = QrPayload::create(&id, TunnelType::Ephemeral, None, None);
        let uri = payload.to_uri().replace("t=ephemeral", "t=persistent");
        let parsed = QrPayload::parse(&uri).unwrap();
        assert!(parsed.verify(id.public_key()).is_err());
    }

    #[test]
    fn test_generate_png() {
        let id = Identity::generate();
        let payload = QrPayload::create(&id, TunnelType::Session, None, None);
        let png = generate_qr(&payload).unwrap();
        assert_eq!(&png[1..4], b"PNG");
    }
}
