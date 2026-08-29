//! UBC tunnel types and per-tunnel communication preferences.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// How long a tunnel lives (spec §Tunnel Types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    /// Single exchange, auto-expires.
    Ephemeral,
    /// A conversation: hours to days, approved by both parties.
    Session,
    /// Ongoing relationship until explicitly revoked. Audited.
    Persistent,
}

impl std::fmt::Display for TunnelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TunnelType::Ephemeral => "ephemeral",
            TunnelType::Session => "session",
            TunnelType::Persistent => "persistent",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for TunnelType {
    type Err = TunnelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ephemeral" => Ok(TunnelType::Ephemeral),
            "session" => Ok(TunnelType::Session),
            "persistent" => Ok(TunnelType::Persistent),
            _ => Err(TunnelError::UnknownType(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permissions {
    pub human_to_bot: bool,
    pub bot_to_bot: bool,
    pub file_transfer: bool,
    pub voice: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Permissions {
            human_to_bot: true,
            bot_to_bot: false,
            file_transfer: false,
            voice: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Privacy {
    pub log_retention: String, // "none" | "session" | "persistent"
    pub forward_secrecy: bool,
    pub metadata_minimization: bool,
}

impl Default for Privacy {
    fn default() -> Self {
        Privacy {
            log_retention: "none".into(),
            forward_secrecy: true,
            metadata_minimization: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_duration_hours: u32,
    pub max_messages: u32,
    pub rate_limit_per_minute: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_duration_hours: 24,
            max_messages: 1000,
            rate_limit_per_minute: 60,
        }
    }
}

/// The negotiated configuration of one tunnel (spec §Communication Preferences).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub version: String,
    pub address: String,
    #[serde(rename = "type")]
    pub tunnel_type: TunnelType,
    pub permissions: Permissions,
    pub privacy: Privacy,
    pub limits: Limits,
}

/// A live tunnel between two UBC addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: Uuid,
    pub config: TunnelConfig,
    pub peer_address: String,
    pub state: TunnelState,
    pub created_at: u64,
    pub message_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    /// Signaling in progress, not yet usable.
    Pending,
    /// P2P channel established.
    Open,
    /// Closed by either side (or expired).
    Closed,
}

impl Tunnel {
    pub fn new(config: TunnelConfig, peer_address: String) -> Self {
        Tunnel {
            id: Uuid::new_v4(),
            config,
            peer_address,
            state: TunnelState::Pending,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            message_count: 0,
        }
    }

    /// Check limits before accepting another message.
    pub fn admit_message(&mut self) -> Result<(), TunnelError> {
        if self.state != TunnelState::Open {
            return Err(TunnelError::NotOpen);
        }
        if self.message_count >= self.config.limits.max_messages as u64 {
            return Err(TunnelError::LimitExceeded("max_messages"));
        }
        let age_hours = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(self.created_at))
            / 3600;
        if age_hours >= self.config.limits.max_duration_hours as u64 {
            return Err(TunnelError::LimitExceeded("max_duration_hours"));
        }
        self.message_count += 1;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("unknown tunnel type: {0}")]
    UnknownType(String),
    #[error("tunnel is not open")]
    NotOpen,
    #[error("tunnel limit exceeded: {0}")]
    LimitExceeded(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(t: TunnelType) -> TunnelConfig {
        TunnelConfig {
            version: "0.1".into(),
            address: "7K9M2N4P8Q3R5T1B".into(),
            tunnel_type: t,
            permissions: Permissions::default(),
            privacy: Privacy::default(),
            limits: Limits::default(),
        }
    }

    #[test]
    fn test_type_roundtrip() {
        for t in [TunnelType::Ephemeral, TunnelType::Session, TunnelType::Persistent] {
            assert_eq!(t.to_string().parse::<TunnelType>().unwrap(), t);
        }
    }

    #[test]
    fn test_admit_requires_open() {
        let mut tun = Tunnel::new(cfg(TunnelType::Session), "3X8K2M9P4Q7R1T5C".into());
        assert!(tun.admit_message().is_err()); // still Pending
        tun.state = TunnelState::Open;
        assert!(tun.admit_message().is_ok());
    }

    #[test]
    fn test_config_serde() {
        let c = cfg(TunnelType::Session);
        let json = serde_json::to_string(&c).unwrap();
        let back: TunnelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tunnel_type, TunnelType::Session);
    }
}
