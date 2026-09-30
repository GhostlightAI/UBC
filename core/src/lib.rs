//! UBC Core — Universal Bot Communication protocol
//!
//! Identity, addressing, cryptography, and tunnel management.

pub mod crypto;
pub mod identity;
pub mod message;
pub mod qr;
pub mod tunnel;

pub use identity::{Address, Identity};
pub use message::{Message, MessageType};
pub use qr::{generate_qr, parse_qr, QrPayload};
pub use tunnel::{Permissions, Privacy, Tunnel, TunnelConfig, TunnelType};

/// UBC protocol version
pub const VERSION: &str = "0.1";

/// Address length: 15 digits + 1 letter
pub const ADDRESS_LENGTH: usize = 16;
