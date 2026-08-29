//! UBC Core — Universal Bot Communication protocol
//!
//! Identity, addressing, cryptography, and tunnel management.

pub mod identity;
pub mod tunnel;
pub mod crypto;
pub mod message;
pub mod qr;

pub use identity::{Identity, Address};
pub use tunnel::{Tunnel, TunnelConfig, TunnelType, Permissions, Privacy};
pub use message::{Message, MessageType};
pub use qr::{QrPayload, generate_qr, parse_qr};

/// UBC protocol version
pub const VERSION: &str = "0.1";

/// Address length: 15 digits + 1 letter
pub const ADDRESS_LENGTH: usize = 16;
