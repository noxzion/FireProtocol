use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use crate::protocol::{FireProtocol, MessageType};
use crate::error::FireProtocolError;
use log::{info, warn, error};

#[derive(Debug, Clone)]
pub struct ServerSecurity {
    pub max_connections: usize,
    pub connection_timeout: Duration,
    pub rate_limit_per_second: u32,
    pub allowed_ips: Vec<String>,
    pub require_authentication: bool,
}

impl Default for ServerSecurity {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connection_timeout: Duration::from_secs(300),
            rate_limit_per_second: 10,
            allowed_ips: Vec::new(),
            require_authentication: true,
        }
    }
}

#[derive(Debug)]
pub struct ConnectionTracker {
    pub ip: String,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub message_count: u32,
    pub last_message_time: Instant,
}

pub struct FireServer {
    protocol: Arc<Mutex<FireProtocol>>,
    connections: Arc<Mutex<HashMap<String, ConnectionTracker>>>,
    security: ServerSecurity,
    port: u16,
    master_password: String,
}

impl FireServer {
    pub fn new(master_password: &str, port: u16) -> Result<Self, FireProtocolError> {
        Ok(FireServer {
            protocol: Arc::new(Mutex::new(FireProtocol::new(master_password)?)),
            connections: Arc::new(Mutex::new(HashMap::new())),
            security: ServerSecurity::default(),
            port,
            master_password: master_password.to_string(),
        })
    }
    
    pub fn with_security(mut self, security: ServerSecurity) -> Self {
        self.security = security;
        self
    }
    
    pub async fn start(&self) -> Result<(), FireProtocolError> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        info!("FireProtocol server started on port {}", self.port);
        
        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    let ip = addr.ip().to_string();
                    
                    if !self.is_connection_allowed(&ip).await {
                        warn!("Connection rejected from IP: {}", ip);
                        continue;
                    }
                    
                    if !self.track_connection(&ip).await {
                        warn!("Connection limit exceeded from IP: {}", ip);
                        continue;
                    }
                    
                    info!("New connection from {}", addr);
                    
                    let protocol = Arc::clone(&self.protocol);
                    let connections = Arc::clone(&self.connections);
                    let security = self.security.clone();
                    let master_password = self.master_password.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(socket, protocol, connections, security, ip, master_password).await {
                            error!("Connection handling error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Connection acceptance error: {}", e);
                }
            }
        }
    }
    
    async fn is_connection_allowed(&self, ip: &str) -> bool {
        if !self.security.allowed_ips.is_empty() && !self.security.allowed_ips.contains(&ip.to_string()) {
            return false;
        }
        
        if let Ok(connections) = self.connections.lock() {
            if connections.len() >= self.security.max_connections {
                return false;
            }
        }
        
        true
    }
    
    async fn track_connection(&self, ip: &str) -> bool {
        if let Ok(mut connections) = self.connections.lock() {
            if connections.len() >= self.security.max_connections {
                return false;
            }
            
            connections.insert(ip.to_string(), ConnectionTracker {
                ip: ip.to_string(),
                connected_at: Instant::now(),
                last_activity: Instant::now(),
                message_count: 0,
                last_message_time: Instant::now(),
            });
        }
        true
    }
    
    async fn handle_connection(
        mut socket: TcpStream,
        protocol: Arc<Mutex<FireProtocol>>,
        connections: Arc<Mutex<HashMap<String, ConnectionTracker>>>,
        security: ServerSecurity,
        client_ip: String,
        master_password: String,
    ) -> Result<(), FireProtocolError> {
        let mut buffer = vec![0u8; 4096];
        let mut session_id: Option<Uuid> = None;
        
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) => {
                    if let Some(id) = session_id {
                        if let Ok(mut protocol) = protocol.lock() {
                            let _ = protocol.close_session(id);
                        }
                    }
                    break;
                }
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    
                    if !Self::check_rate_limit(&connections, &client_ip, &security).await {
                        warn!("Rate limit exceeded for IP: {}", client_ip);
                        break;
                    }
                    
                    if session_id.is_none() {
                        let new_session_id = {
                            let mut protocol = protocol.lock()
                                .map_err(|_| FireProtocolError::ProtocolError("Failed to lock protocol".to_string()))?;
                            protocol.create_session("client", "server", &master_password)?
                        };
                        session_id = Some(new_session_id);
                        
                        let handshake_data = {
                            let mut protocol = protocol.lock()
                                .map_err(|_| FireProtocolError::ProtocolError("Failed to lock protocol".to_string()))?;
                            let handshake = protocol.create_handshake_message(new_session_id)?;
                            serde_json::to_vec(&handshake)?
                        };
                        
                        socket.write_all(&handshake_data).await?;
                    } else {
                        let id = session_id.unwrap();
                        let message = {
                            let mut protocol = protocol.lock()
                                .map_err(|_| FireProtocolError::ProtocolError("Failed to lock protocol".to_string()))?;
                            protocol.receive_message(id, data)?
                        };
                        
                        match message.message_type {
                            MessageType::Data => {
                                let response_data = {
                                    let mut protocol = protocol.lock()
                                        .map_err(|_| FireProtocolError::ProtocolError("Failed to lock protocol".to_string()))?;
                                    let response = protocol.send_message(
                                        id,
                                        MessageType::Data,
                                        message.payload
                                    )?;
                                    serde_json::to_vec(&response)?
                                };
                                socket.write_all(&response_data).await?;
                            }
                            MessageType::Heartbeat => {
                                let heartbeat_data = {
                                    let mut protocol = protocol.lock()
                                        .map_err(|_| FireProtocolError::ProtocolError("Failed to lock protocol".to_string()))?;
                                    let heartbeat = protocol.create_heartbeat_message(id)?;
                                    serde_json::to_vec(&heartbeat)?
                                };
                                socket.write_all(&heartbeat_data).await?;
                            }
                            MessageType::Close => {
                                let _ = {
                                    let mut protocol = protocol.lock()
                                        .map_err(|_| FireProtocolError::ProtocolError("Failed to lock protocol".to_string()))?;
                                    protocol.close_session(id)
                                };
                                break;
                            }
                            _ => {
                                info!("Received message type: {:?}", message.message_type);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Socket read error: {}", e);
                    break;
                }
            }
        }
        
        if let Ok(mut connections) = connections.lock() {
            connections.remove(&client_ip);
        }
        
        Ok(())
    }
    
    async fn check_rate_limit(
        connections: &Arc<Mutex<HashMap<String, ConnectionTracker>>>,
        ip: &str,
        security: &ServerSecurity,
    ) -> bool {
        if let Ok(mut connections) = connections.lock() {
            if let Some(tracker) = connections.get_mut(ip) {
                let now = Instant::now();
                
                if now.duration_since(tracker.last_message_time) < Duration::from_millis(1000 / security.rate_limit_per_second as u64) {
                    return false;
                }
                
                tracker.message_count += 1;
                tracker.last_message_time = now;
                tracker.last_activity = now;
            }
        }
        true
    }
}

pub struct FireClient {
    protocol: FireProtocol,
    session_id: Option<Uuid>,
    stream: Option<TcpStream>,
    master_password: String,
}

impl FireClient {
    pub fn new(master_password: &str) -> Result<Self, FireProtocolError> {
        Ok(FireClient {
            protocol: FireProtocol::new(master_password)?,
            session_id: None,
            stream: None,
            master_password: master_password.to_string(),
        })
    }
    
    pub async fn connect(&mut self, host: &str, port: u16) -> Result<(), FireProtocolError> {
        let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
        self.stream = Some(stream);
        
        self.session_id = Some(self.protocol.create_session("client", "server", &self.master_password)?);
        
        if let Some(session_id) = self.session_id {
            let handshake = self.protocol.create_handshake_message(session_id)?;
            let handshake_data = serde_json::to_vec(&handshake)?;
            
            if let Some(stream) = &mut self.stream {
                stream.write_all(&handshake_data).await?;
                
                let mut buffer = vec![0u8; 4096];
                let n = stream.read(&mut buffer).await?;
                if n > 0 {
                    let response_data = buffer[..n].to_vec();
                    let _ = self.protocol.receive_message(session_id, response_data);
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn send_data(&mut self, data: &[u8]) -> Result<Vec<u8>, FireProtocolError> {
        if let Some(session_id) = self.session_id {
            let message = self.protocol.send_message(session_id, MessageType::Data, data.to_vec())?;
            let message_data = serde_json::to_vec(&message)?;
            
            if let Some(stream) = &mut self.stream {
                stream.write_all(&message_data).await?;
                
                let mut buffer = vec![0u8; 4096];
                let n = stream.read(&mut buffer).await?;
                if n > 0 {
                    let response_data = buffer[..n].to_vec();
                    let response = self.protocol.receive_message(session_id, response_data)?;
                    return Ok(response.payload);
                }
            }
        }
        
        Err(FireProtocolError::ProtocolError("No active connection".to_string()))
    }
    
    pub async fn send_heartbeat(&mut self) -> Result<(), FireProtocolError> {
        if let Some(session_id) = self.session_id {
            let heartbeat = self.protocol.create_heartbeat_message(session_id)?;
            let heartbeat_data = serde_json::to_vec(&heartbeat)?;
            
            if let Some(stream) = &mut self.stream {
                stream.write_all(&heartbeat_data).await?;
                
                let mut buffer = vec![0u8; 4096];
                let n = stream.read(&mut buffer).await?;
                if n > 0 {
                    let response_data = buffer[..n].to_vec();
                    let _ = self.protocol.receive_message(session_id, response_data);
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn disconnect(&mut self) -> Result<(), FireProtocolError> {
        if let Some(session_id) = self.session_id {
            let close_message = self.protocol.close_session(session_id)?;
            let close_data = serde_json::to_vec(&close_message)?;
            
            if let Some(stream) = &mut self.stream {
                stream.write_all(&close_data).await?;
            }
        }
        
        self.stream = None;
        self.session_id = None;
        
        Ok(())
    }
    
    pub fn get_session_info(&self) -> Option<&crate::protocol::Session> {
        self.session_id.and_then(|id| self.protocol.get_session_info(id))
    }
    
    pub fn get_crypto_info(&self) -> Option<Vec<std::collections::HashMap<String, String>>> {
        self.session_id.and_then(|id| self.protocol.get_crypto_info(id))
    }
    
    pub fn get_service_info(&self) -> Option<Vec<std::collections::HashMap<String, String>>> {
        self.session_id.and_then(|id| self.protocol.get_service_info(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_client_creation() {
        let client = FireClient::new("test_password");
        assert!(client.is_ok());
    }
    
    #[tokio::test]
    async fn test_server_creation() {
        let server = FireServer::new("test_password", 8080);
        assert!(server.is_ok());
    }
} 