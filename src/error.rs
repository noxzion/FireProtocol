use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum FireProtocolError {
    CryptoError(String),
    NetworkError(String),
    ProtocolError(String),
    SessionError(String),
    SerializationError(String),
    IoError(std::io::Error),
    Other(String),
}

impl fmt::Display for FireProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FireProtocolError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            FireProtocolError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            FireProtocolError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            FireProtocolError::SessionError(msg) => write!(f, "Session error: {}", msg),
            FireProtocolError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            FireProtocolError::IoError(err) => write!(f, "IO error: {}", err),
            FireProtocolError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl StdError for FireProtocolError {}


impl From<aes_gcm::Error> for FireProtocolError {
    fn from(err: aes_gcm::Error) -> Self {
        FireProtocolError::CryptoError(err.to_string())
    }
}


impl From<std::io::Error> for FireProtocolError {
    fn from(err: std::io::Error) -> Self {
        FireProtocolError::IoError(err)
    }
}

impl From<serde_json::Error> for FireProtocolError {
    fn from(err: serde_json::Error) -> Self {
        FireProtocolError::SerializationError(err.to_string())
    }
}

impl From<&str> for FireProtocolError {
    fn from(err: &str) -> Self {
        FireProtocolError::ProtocolError(err.to_string())
    }
}

impl From<String> for FireProtocolError {
    fn from(err: String) -> Self {
        FireProtocolError::ProtocolError(err)
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for FireProtocolError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        FireProtocolError::ProtocolError(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for FireProtocolError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        FireProtocolError::Other(e.to_string())
    }
}

impl From<sha2::digest::InvalidLength> for FireProtocolError {
    fn from(err: sha2::digest::InvalidLength) -> Self {
        FireProtocolError::CryptoError(err.to_string())
    }
}

impl From<std::time::SystemTimeError> for FireProtocolError {
    fn from(err: std::time::SystemTimeError) -> Self {
        FireProtocolError::ProtocolError(err.to_string())
    }
}