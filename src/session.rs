use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use crate::crypto::MultiLayerCrypto;
use crate::protocol::{Session, SessionStatus};
use crate::error::FireProtocolError;

#[derive(Debug, Clone)]
pub struct SessionManager {
    sessions: HashMap<Uuid, ManagedSession>,
    max_sessions: usize,
    session_timeout: Duration,
    heartbeat_interval: Duration,
    cleanup_interval: Duration,
    last_cleanup: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ManagedSession {
    pub session: Session,
    pub created_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
    pub heartbeat_count: u64,
    pub failed_heartbeats: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub security_level: SecurityLevel,
    pub connection_info: ConnectionInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Maximum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub remote_addr: String,
    pub local_addr: String,
    pub protocol_version: String,
    pub user_agent: String,
    pub connection_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: HashMap::new(),
            max_sessions: 1000,
            session_timeout: Duration::from_secs(300),
            heartbeat_interval: Duration::from_secs(30),
            cleanup_interval: Duration::from_secs(60),
            last_cleanup: Utc::now(),
        }
    }
    
    pub fn with_config(
        max_sessions: usize,
        session_timeout: Duration,
        heartbeat_interval: Duration,
    ) -> Self {
        SessionManager {
            sessions: HashMap::new(),
            max_sessions,
            session_timeout,
            heartbeat_interval,
            cleanup_interval: Duration::from_secs(60),
            last_cleanup: Utc::now(),
        }
    }
    
    pub fn create_session(
        &mut self,
        client_id: &str,
        server_id: &str,
        master_password: &str,
        remote_addr: &str,
        local_addr: &str,
        user_agent: &str,
    ) -> Result<Uuid, FireProtocolError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(FireProtocolError::SessionError("Maximum session limit reached".to_string()));
        }
        
        let crypto = MultiLayerCrypto::new(master_password)?;
        let security_level = Self::determine_security_level(master_password);
        
        let session = Session {
            id: Uuid::new_v4(),
            client_id: client_id.to_string(),
            server_id: server_id.to_string(),
            crypto,
            created_at: Utc::now(),
            last_activity: Utc::now(),
            sequence_number: 0,
            window_size: 1024,
            timeout: self.session_timeout.as_secs(),
            status: SessionStatus::Establishing,
        };
        
        let connection_info = ConnectionInfo {
            remote_addr: remote_addr.to_string(),
            local_addr: local_addr.to_string(),
            protocol_version: "1.0".to_string(),
            user_agent: user_agent.to_string(),
            connection_time: Utc::now(),
            last_activity: Utc::now(),
        };
        
        let managed_session = ManagedSession {
            session,
            created_at: Utc::now(),
            last_heartbeat: Utc::now(),
            heartbeat_count: 0,
            failed_heartbeats: 0,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            security_level,
            connection_info,
        };
        
        let session_id = managed_session.session.id;
        self.sessions.insert(session_id, managed_session);
        
        Ok(session_id)
    }
    
    pub fn get_session(&self, session_id: Uuid) -> Option<&ManagedSession> {
        self.sessions.get(&session_id)
    }
    
    pub fn get_session_mut(&mut self, session_id: Uuid) -> Option<&mut ManagedSession> {
        self.sessions.get_mut(&session_id)
    }
    
    pub fn update_activity(&mut self, session_id: Uuid) -> Result<(), FireProtocolError> {
        if let Some(managed_session) = self.sessions.get_mut(&session_id) {
            managed_session.session.last_activity = Utc::now();
            managed_session.connection_info.last_activity = Utc::now();
        } else {
            return Err(FireProtocolError::SessionError("Session not found".to_string()));
        }
        Ok(())
    }
    
    pub fn record_message_sent(&mut self, session_id: Uuid, bytes: usize) -> Result<(), FireProtocolError> {
        if let Some(managed_session) = self.sessions.get_mut(&session_id) {
            managed_session.bytes_sent += bytes as u64;
            managed_session.messages_sent += 1;
            self.update_activity(session_id)?;
        } else {
            return Err(FireProtocolError::SessionError("Session not found".to_string()));
        }
        Ok(())
    }
    
    pub fn record_message_received(&mut self, session_id: Uuid, bytes: usize) -> Result<(), FireProtocolError> {
        if let Some(managed_session) = self.sessions.get_mut(&session_id) {
            managed_session.bytes_received += bytes as u64;
            managed_session.messages_received += 1;
            self.update_activity(session_id)?;
        } else {
            return Err(FireProtocolError::SessionError("Session not found".to_string()));
        }
        Ok(())
    }
    
    pub fn record_heartbeat(&mut self, session_id: Uuid, success: bool) -> Result<(), FireProtocolError> {
        if let Some(managed_session) = self.sessions.get_mut(&session_id) {
            managed_session.last_heartbeat = Utc::now();
            managed_session.heartbeat_count += 1;
            
            if !success {
                managed_session.failed_heartbeats += 1;
            }
        } else {
            return Err(FireProtocolError::SessionError("Session not found".to_string()));
        }
        Ok(())
    }
    
    pub fn close_session(&mut self, session_id: Uuid) -> Result<(), FireProtocolError> {
        if let Some(managed_session) = self.sessions.get_mut(&session_id) {
            managed_session.session.status = SessionStatus::Closing;
        }
        
        self.sessions.remove(&session_id);
        Ok(())
    }
    
    pub fn cleanup_expired_sessions(&mut self) {
        let now = Utc::now();
        let last_cleanup_duration = now.signed_duration_since(self.last_cleanup);
        if last_cleanup_duration < chrono::Duration::from_std(self.cleanup_interval).unwrap() {
            return;
        }
        
        self.last_cleanup = now;
        let expired_sessions: Vec<Uuid> = self.sessions
            .iter()
            .filter(|(_, managed_session)| {
                let session_age = now.signed_duration_since(managed_session.created_at);
                let last_activity = managed_session.session.last_activity;
                let activity_age = now.signed_duration_since(last_activity);
                
                session_age.num_seconds() > self.session_timeout.as_secs() as i64 || 
                activity_age.num_seconds() > self.session_timeout.as_secs() as i64
            })
            .map(|(id, _)| *id)
            .collect();
        
        for session_id in expired_sessions {
            let _ = self.close_session(session_id);
        }
    }
    
    pub fn get_sessions_requiring_heartbeat(&self) -> Vec<Uuid> {
        let now = Utc::now();
        self.sessions
            .iter()
            .filter(|(_, managed_session)| {
                let time_since_heartbeat = now.signed_duration_since(managed_session.last_heartbeat);
                time_since_heartbeat >= chrono::Duration::from_std(self.heartbeat_interval).unwrap()
            })
            .map(|(id, _)| *id)
            .collect()
    }
    
    pub fn get_session_statistics(&self) -> SessionStatistics {
        let total_sessions = self.sessions.len();
        let active_sessions = self.sessions
            .values()
            .filter(|s| s.session.status == SessionStatus::Established)
            .count();
        
        let total_bytes_sent: u64 = self.sessions.values().map(|s| s.bytes_sent).sum();
        let total_bytes_received: u64 = self.sessions.values().map(|s| s.bytes_received).sum();
        let total_messages_sent: u64 = self.sessions.values().map(|s| s.messages_sent).sum();
        let total_messages_received: u64 = self.sessions.values().map(|s| s.messages_received).sum();
        
        let security_distribution = self.get_security_level_distribution();
        
        SessionStatistics {
            total_sessions,
            active_sessions,
            total_bytes_sent,
            total_bytes_received,
            total_messages_sent,
            total_messages_received,
            security_distribution,
        }
    }
    
    pub fn get_security_level_distribution(&self) -> HashMap<SecurityLevel, usize> {
        let mut distribution = HashMap::new();
        
        for managed_session in self.sessions.values() {
            *distribution.entry(managed_session.security_level.clone()).or_insert(0) += 1;
        }
        
        distribution
    }
    
    fn determine_security_level(password: &str) -> SecurityLevel {
        if password.len() >= 32 && password.chars().any(|c| c.is_uppercase()) 
           && password.chars().any(|c| c.is_lowercase()) 
           && password.chars().any(|c| c.is_numeric())
           && password.chars().any(|c| !c.is_alphanumeric()) {
            SecurityLevel::Maximum
        } else if password.len() >= 20 {
            SecurityLevel::High
        } else if password.len() >= 12 {
            SecurityLevel::Medium
        } else {
            SecurityLevel::Low
        }
    }
    
    pub fn list_all_sessions(&self) -> Vec<&ManagedSession> {
        self.sessions.values().collect()
    }
    
    pub fn get_session_count(&self) -> usize {
        self.sessions.len()
    }
    
    pub fn is_session_active(&self, session_id: Uuid) -> bool {
        self.sessions.get(&session_id)
            .map(|s| s.session.status == SessionStatus::Established)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatistics {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub security_distribution: HashMap<SecurityLevel, usize>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_manager_creation() {
        let manager = SessionManager::new();
        assert_eq!(manager.get_session_count(), 0);
    }
    
    #[test]
    fn test_session_creation() {
        let mut manager = SessionManager::new();
        let session_id = manager.create_session(
            "client1",
            "server1",
            "test_password",
            "127.0.0.1:1234",
            "127.0.0.1:8080",
            "FireProtocol/1.0"
        ).unwrap();
        
        assert!(session_id.is_ok());
        assert_eq!(manager.get_session_count(), 1);
    }
    
    #[test]
    fn test_session_activity_update() {
        let mut manager = SessionManager::new();
        let session_id = manager.create_session(
            "client1",
            "server1",
            "test_password",
            "127.0.0.1:1234",
            "127.0.0.1:8080",
            "FireProtocol/1.0"
        ).unwrap();
        
        assert!(manager.update_activity(session_id).is_ok());
    }
} 