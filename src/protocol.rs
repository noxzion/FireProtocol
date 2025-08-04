use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use crate::crypto::MultiLayerCrypto;
use crate::error::FireProtocolError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub sequence_number: u64,
    pub flags: MessageFlags,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Handshake,
    Data,
    Ack,
    Heartbeat,
    Error,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub fragmented: bool,
    pub urgent: bool,
    pub reliable: bool,
}

impl Default for MessageFlags {
    fn default() -> Self {
        Self {
            encrypted: true,
            compressed: false,
            fragmented: false,
            urgent: false,
            reliable: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub client_id: String,
    pub server_id: String,
    pub crypto: MultiLayerCrypto,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub sequence_number: u64,
    pub window_size: u32,
    pub timeout: u64,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Establishing,
    Established,
    Closing,
    Closed,
    Error,
}

#[derive(Debug, Clone)]
pub struct FireProtocol {
    sessions: HashMap<Uuid, Session>,
    default_timeout: u64,
    max_window_size: u32,
}

impl FireProtocol {
    pub fn new(_master_password: &str) -> Result<Self, FireProtocolError> {
        Ok(FireProtocol {
            sessions: HashMap::new(),
            default_timeout: 300,
            max_window_size: 1024,
        })
    }
    
    pub fn create_session(&mut self, client_id: &str, server_id: &str, master_password: &str) -> Result<Uuid, FireProtocolError> {
        let session_id = Uuid::new_v4();
        let crypto = MultiLayerCrypto::new_default(master_password)?;
        
        let session = Session {
            id: session_id,
            client_id: client_id.to_string(),
            server_id: server_id.to_string(),
            crypto,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            sequence_number: 0,
            window_size: self.max_window_size,
            timeout: self.default_timeout,
            status: SessionStatus::Establishing,
        };
        
        self.sessions.insert(session_id, session);
        Ok(session_id)
    }
    
    pub fn send_message(&mut self, session_id: Uuid, message_type: MessageType, payload: Vec<u8>) -> Result<Message, FireProtocolError> {
        let session = self.sessions.get_mut(&session_id)
            .ok_or_else(|| FireProtocolError::SessionError("Session not found".to_string()))?;
        
        session.sequence_number += 1;
        session.last_activity = Utc::now();
        
        let mut message = Message {
            id: Uuid::new_v4(),
            session_id,
            message_type,
            payload,
            timestamp: Utc::now(),
            sequence_number: session.sequence_number,
            flags: MessageFlags::default(),
            metadata: HashMap::new(),
        };
        
        if message.flags.encrypted {
            message.payload = session.crypto.encrypt(&message.payload)?;
        }
        
        Ok(message)
    }
    
    pub fn receive_message(&mut self, session_id: Uuid, encrypted_data: Vec<u8>) -> Result<Message, FireProtocolError> {
        let session = self.sessions.get_mut(&session_id)
            .ok_or_else(|| FireProtocolError::SessionError("Session not found".to_string()))?;
        
        let decrypted_data = session.crypto.decrypt(&encrypted_data)?;
        let message: Message = serde_json::from_slice(&decrypted_data)?;
        
        session.last_activity = Utc::now();
        
        Ok(message)
    }
    
    pub fn create_handshake_message(&mut self, session_id: Uuid) -> Result<Message, FireProtocolError> {
        let handshake_data = serde_json::json!({
            "protocol_version": "1.0",
            "services_count": crate::crypto::ENCRYPTION_SERVICE_COUNT,
            "stages_per_service": crate::crypto::STAGES_PER_SERVICE,
            "total_layers": crate::crypto::TOTAL_LAYERS,
            "supported_algorithms": ["AES256GCM", "ChaCha20Poly1305", "AES256CBC", "AES128GCM", "CustomXOR"],
            "timestamp": Utc::now().timestamp()
        });
        
        let payload = serde_json::to_vec(&handshake_data)?;
        self.send_message(session_id, MessageType::Handshake, payload)
    }
    
    pub fn create_heartbeat_message(&mut self, session_id: Uuid) -> Result<Message, FireProtocolError> {
        let heartbeat_data = serde_json::json!({
            "timestamp": Utc::now().timestamp(),
            "sequence": self.sessions.get(&session_id).map(|s| s.sequence_number).unwrap_or(0)
        });
        
        let payload = serde_json::to_vec(&heartbeat_data)?;
        self.send_message(session_id, MessageType::Heartbeat, payload)
    }
    
    pub fn close_session(&mut self, session_id: Uuid) -> Result<Message, FireProtocolError> {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.status = SessionStatus::Closing;
        }
        
        let close_data = serde_json::json!({
            "reason": "normal_closure",
            "timestamp": Utc::now().timestamp()
        });
        
        let payload = serde_json::to_vec(&close_data)?;
        let message = self.send_message(session_id, MessageType::Close, payload)?;
        
        self.sessions.remove(&session_id);
        
        Ok(message)
    }
    
    pub fn get_session_info(&self, session_id: Uuid) -> Option<&Session> {
        self.sessions.get(&session_id)
    }
    
    pub fn list_sessions(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }
    
    pub fn cleanup_expired_sessions(&mut self) {
        let now = Utc::now();
        let expired_sessions: Vec<Uuid> = self.sessions
            .iter()
            .filter(|(_, session)| {
                let duration = now.signed_duration_since(session.last_activity);
                duration.num_seconds() > session.timeout as i64
            })
            .map(|(id, _)| *id)
            .collect();
        
        for session_id in expired_sessions {
            self.sessions.remove(&session_id);
        }
    }
    
    pub fn get_crypto_info(&self, session_id: Uuid) -> Option<Vec<std::collections::HashMap<String, String>>> {
        self.sessions.get(&session_id)
            .map(|session| session.crypto.get_layer_info())
    }
    
    pub fn get_service_info(&self, session_id: Uuid) -> Option<Vec<std::collections::HashMap<String, String>>> {
        self.sessions.get(&session_id)
            .map(|session| session.crypto.get_service_info())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protocol_creation() {
        let protocol = FireProtocol::new("test_password");
        assert!(protocol.is_ok());
    }
    
    #[test]
    fn test_session_creation() {
        let mut protocol = FireProtocol::new("test_password").unwrap();
        let session_id = protocol.create_session("client1", "server1", "test_password");
        assert!(session_id.is_ok());
    }
    
    #[test]
    fn test_message_sending() {
        let mut protocol = FireProtocol::new("test_password").unwrap();
        let session_id = protocol.create_session("client1", "server1", "test_password").unwrap();
        
        let message = protocol.send_message(
            session_id,
            MessageType::Data,
            b"Hello, FireProtocol!".to_vec()
        );
        
        assert!(message.is_ok());
    }
} 