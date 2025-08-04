use serde::{Deserialize, Serialize};
use p256::{SecretKey, PublicKey};
use elliptic_curve::{ecdh::diffie_hellman, sec1::ToEncodedPoint};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use crate::error::FireProtocolError;

/// ECDH Key Exchange implementation for secure session key negotiation
#[derive(Debug)]
pub struct KeyExchange {
    private_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    peer_public_key: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
    session_key: Option<[u8; 32]>,
}

/// Handshake data structure for key exchange
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeData {
    pub protocol_version: String,
    pub services_count: u32,
    pub stages_per_service: u32,
    pub total_layers: u32,
    pub supported_algorithms: Vec<String>,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_exchange: Option<KeyExchangeData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_capabilities: Option<ClientCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_capabilities: Option<ServerCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchangeData {
    pub method: String,
    pub public_key: String, // hex encoded
    pub timestamp: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientCapabilities {
    pub key_exchange: Vec<String>,
    pub encryption: Vec<String>,
    pub hash: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerCapabilities {
    pub key_exchange: Vec<String>,
    pub encryption: Vec<String>,
    pub hash: Vec<String>,
}

impl KeyExchange {
    /// Create a new key exchange instance
    pub fn new() -> Self {
        Self {
            private_key: None,
            public_key: None,
            peer_public_key: None,
            shared_secret: None,
            session_key: None,
        }
    }

    /// Generate ECDH keypair
    pub fn generate_keypair(&mut self) -> Result<(), FireProtocolError> {
        let private_key = SecretKey::random(&mut OsRng);
        let public_key = private_key.public_key();
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        
        Ok(())
    }

    /// Get public key as hex string for transmission
    pub fn get_public_key_hex(&self) -> Result<String, FireProtocolError> {
        match &self.public_key {
            Some(pk) => {
                let encoded = pk.to_encoded_point(false);
                let hex_key = hex::encode(encoded.as_bytes());
                log::info!("ECDH Debug - Our public key: {}...", &hex_key[..32]);
                Ok(hex_key)
            }
            None => Err(FireProtocolError::CryptoError("No public key generated".to_string())),
        }
    }

    /// Set peer's public key from hex string
    pub fn set_peer_public_key_hex(&mut self, hex_key: &str) -> Result<(), FireProtocolError> {
        log::info!("ECDH Debug - Setting peer public key: {}...", &hex_key[..32]);
        
        let key_bytes = hex::decode(hex_key)
            .map_err(|e| FireProtocolError::CryptoError(format!("Invalid hex key: {}", e)))?;
        
        log::info!("ECDH Debug - Peer key bytes length: {}", key_bytes.len());
        
        let public_key = PublicKey::from_sec1_bytes(&key_bytes)
            .map_err(|e| FireProtocolError::CryptoError(format!("Invalid public key: {}", e)))?;
        
        self.peer_public_key = Some(public_key);
        log::info!("ECDH Debug - Peer public key set successfully");
        Ok(())
    }

    /// Compute shared secret using ECDH
    pub fn compute_shared_secret(&mut self) -> Result<(), FireProtocolError> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| FireProtocolError::CryptoError("No private key".to_string()))?;
        
        let peer_public_key = self.peer_public_key.as_ref()
            .ok_or_else(|| FireProtocolError::CryptoError("No peer public key".to_string()))?;

        let shared_secret = diffie_hellman(private_key.to_nonzero_scalar(), peer_public_key.as_affine());
        
        // Convert to fixed-size array
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(shared_secret.raw_secret_bytes());
        
        self.shared_secret = Some(secret_bytes);
        Ok(())
    }

    /// Derive session key from shared secret using HKDF
    pub fn derive_session_key(&mut self) -> Result<[u8; 32], FireProtocolError> {
        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| FireProtocolError::CryptoError("No shared secret".to_string()))?;

        let salt = b"FireProtocol_KeyExchange_2024";
        let info = b"FireProtocol_SessionKey";
        
        // Debug logging
        log::info!("ECDH Debug - Shared secret: {}", hex::encode(shared_secret));
        log::info!("ECDH Debug - Salt: {:?}", std::str::from_utf8(salt).unwrap_or("invalid"));
        log::info!("ECDH Debug - Info: {:?}", std::str::from_utf8(info).unwrap_or("invalid"));
        
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
        let mut session_key = [0u8; 32];
        hk.expand(info, &mut session_key)
            .map_err(|e| FireProtocolError::CryptoError(format!("HKDF expand failed: {}", e)))?;
        
        log::info!("ECDH Debug - Derived session key: {}", hex::encode(&session_key));
        
        self.session_key = Some(session_key);
        Ok(session_key)
    }

    /// Get the derived session key
    pub fn get_session_key(&self) -> Option<[u8; 32]> {
        self.session_key
    }
}

/// Handshake manager for server-side key exchange
pub struct HandshakeManager {
    key_exchange: KeyExchange,
    master_password: String,
}

impl HandshakeManager {
    /// Create new handshake manager
    pub fn new(master_password: String) -> Self {
        Self {
            key_exchange: KeyExchange::new(),
            master_password,
        }
    }

    /// Process client handshake and create server response
    pub fn process_client_handshake(&mut self, handshake_data: HandshakeData) -> Result<HandshakeData, FireProtocolError> {
        // Check if client supports key exchange
        let key_exchange_data = handshake_data.key_exchange
            .ok_or_else(|| FireProtocolError::ProtocolError("No key exchange data in client handshake".to_string()))?;

        if key_exchange_data.method != "ECDH-SECP256R1" {
            return Err(FireProtocolError::ProtocolError("Unsupported key exchange method".to_string()));
        }

        // Generate our keypair
        self.key_exchange.generate_keypair()?;

        // Set client's public key
        self.key_exchange.set_peer_public_key_hex(&key_exchange_data.public_key)?;

        // Compute shared secret and derive session key
        self.key_exchange.compute_shared_secret()?;
        let _session_key = self.key_exchange.derive_session_key()?;

        // Create server response
        let server_response = HandshakeData {
            protocol_version: "1.0".to_string(),
            services_count: handshake_data.services_count,
            stages_per_service: handshake_data.stages_per_service,
            total_layers: handshake_data.total_layers,
            supported_algorithms: vec![
                "AES256GCM".to_string(),
                "ChaCha20Poly1305".to_string(),
                "AES256CBC".to_string(),
                "AES128GCM".to_string(),
                "CustomXOR".to_string(),
            ],
            timestamp: handshake_data.timestamp,
            status: Some("accepted".to_string()),
            key_exchange: Some(KeyExchangeData {
                method: "ECDH-SECP256R1".to_string(),
                public_key: self.key_exchange.get_public_key_hex()?,
                timestamp: Some(handshake_data.timestamp),
            }),
            server_capabilities: Some(ServerCapabilities {
                key_exchange: vec!["ECDH-SECP256R1".to_string()],
                encryption: vec![
                    "AES256GCM".to_string(),
                    "ChaCha20Poly1305".to_string(),
                    "AES256CBC".to_string(),
                    "AES128GCM".to_string(),
                    "CustomXOR".to_string(),
                ],
                hash: vec!["SHA256".to_string()],
            }),
            client_capabilities: handshake_data.client_capabilities,
        };

        Ok(server_response)
    }

    /// Get the negotiated session key
    pub fn get_session_key(&self) -> Option<[u8; 32]> {
        self.key_exchange.get_session_key()
    }

    /// Check if handshake supports key exchange
    pub fn supports_key_exchange(handshake_data: &HandshakeData) -> bool {
        handshake_data.key_exchange.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let mut client_kx = KeyExchange::new();
        let mut server_kx = KeyExchange::new();

        // Generate keypairs
        client_kx.generate_keypair().unwrap();
        server_kx.generate_keypair().unwrap();

        // Exchange public keys
        let client_public = client_kx.get_public_key_hex().unwrap();
        let server_public = server_kx.get_public_key_hex().unwrap();

        client_kx.set_peer_public_key_hex(&server_public).unwrap();
        server_kx.set_peer_public_key_hex(&client_public).unwrap();

        // Compute shared secrets
        client_kx.compute_shared_secret().unwrap();
        server_kx.compute_shared_secret().unwrap();

        // Derive session keys
        let client_session_key = client_kx.derive_session_key().unwrap();
        let server_session_key = server_kx.derive_session_key().unwrap();

        // Keys should match
        assert_eq!(client_session_key, server_session_key);
    }

    #[test]
    fn test_handshake_manager() {
        let mut manager = HandshakeManager::new("test_password".to_string());
        
        // Create mock client handshake
        let client_handshake = HandshakeData {
            protocol_version: "1.0".to_string(),
            services_count: 2,
            stages_per_service: 12,
            total_layers: 24,
            supported_algorithms: vec!["AES256GCM".to_string()],
            timestamp: 1234567890,
            key_exchange: Some(KeyExchangeData {
                method: "ECDH-SECP256R1".to_string(),
                public_key: "04".to_string() + &"0".repeat(126), // Mock public key
                timestamp: Some(1234567890),
            }),
            client_capabilities: Some(ClientCapabilities {
                key_exchange: vec!["ECDH-SECP256R1".to_string()],
                encryption: vec!["AES256GCM".to_string()],
                hash: vec!["SHA256".to_string()],
            }),
            server_capabilities: None,
            status: None,
        };

        // This should work with a real public key, but for test we expect an error
        let result = manager.process_client_handshake(client_handshake);
        assert!(result.is_err()); // Expected due to invalid mock key
    }
}