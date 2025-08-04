use fire_protocol::{
    crypto::MultiLayerCrypto,
    protocol::{FireProtocol, MessageType},
    session::SessionManager,
    utils::ProtocolUtils,
};
use std::time::Instant;
use tokio;
use log::error;

#[tokio::main]
async fn main() -> Result<(), fire_protocol::error::FireProtocolError> {
    env_logger::init();
    
    println!("FireProtocol - Data transfer protocol with 2 encryption services");
    println!("{}", "=".repeat(70));
    
    let protocol_info = ProtocolUtils::get_protocol_info();
    println!("Protocol Information:");
    println!("   Name: {}", protocol_info.name);
    println!("   Version: {}", protocol_info.version);
    println!("   Description: {}", protocol_info.description);
    println!("   Services count: {}", protocol_info.services_count);
    println!("   Stages per service: {}", protocol_info.stages_per_service);
    println!("   Total layers: {}", protocol_info.total_layers);
    println!("   Supported algorithms: {}", protocol_info.supported_algorithms.join(", "));
    println!();
    
    println!("Password Generation:");
    let weak_password = "123";
    let strong_password = ProtocolUtils::generate_password(32);
    
    let weak_strength = ProtocolUtils::check_password_strength(weak_password);
    let strong_strength = ProtocolUtils::check_password_strength(&strong_password);
    
    println!("   Weak password: '{}' - {}", weak_password, weak_strength.strength);
    println!("   Strong password: '{}' - {}", strong_password, strong_strength.strength);
    println!();
    
    println!("Encryption Demonstration:");
    let master_password = "MySuperSecurePassword123!@#";
    
            match MultiLayerCrypto::new_default(master_password) {
        Ok(crypto) => {
            let test_data = b"Hello, FireProtocol! This is a test message.";
            println!("   Original data: {}", String::from_utf8_lossy(test_data));
            println!("   Data size: {}", ProtocolUtils::format_data_size(test_data.len() as u64));
            
            // Простой тест без заголовка
            let mut encrypted_data = test_data.to_vec();
            if let Some(first_service) = crypto.services.first() {
                if let Some(first_stage) = first_service.stages.first() {
                    println!("   Testing first layer: {:?}", first_stage.algorithm);
                    encrypted_data = crypto.apply_encryption_layer(&encrypted_data, first_stage)?;
                    encrypted_data = crypto.apply_decryption_layer(&encrypted_data, first_stage)?;
                    
                    println!("   Simple test - Decrypted data: {}", String::from_utf8_lossy(&encrypted_data));
                    if test_data == encrypted_data.as_slice() {
                        println!("   Simple test - SUCCESS!");
                    } else {
                        println!("   Simple test - FAILED!");
                    }
                }
            }
            
            println!();
            println!("Encryption Services Information:");
            let service_info = crypto.get_service_info();
            for (i, service) in service_info.iter().enumerate() {
                println!("   Service {}: {} stages, algorithms: {}",
                    service.get("service_id").unwrap(),
                    service.get("stages_count").unwrap(),
                    service.get("algorithms").unwrap()
                );
            }
            
            println!();
            println!("Encryption Layers Information:");
            let layer_info = crypto.get_layer_info();
            for (i, layer) in layer_info.iter().enumerate() {
                if i < 5 {
                    println!("   Layer {} (Service {}, Stage {}): {} (key: {} bytes, IV: {} bytes, rounds: {})",
                        layer.get("layer_id").unwrap(),
                        layer.get("service_id").unwrap(),
                        layer.get("stage_id").unwrap(),
                        layer.get("algorithm").unwrap(),
                        layer.get("key_length").unwrap(),
                        layer.get("iv_length").unwrap(),
                        layer.get("rounds").unwrap()
                    );
                }
            }
            println!("   ... and {} more layers", layer_info.len() - 5);
        }
        Err(e) => {
            error!("Error creating cryptographic module: {}", e);
        }
    }
    
    println!();
    
    println!("Protocol Demonstration:");
    match FireProtocol::new(master_password) {
        Ok(mut protocol) => {
            let session_id = protocol.create_session("client1", "server1", master_password)?;
            println!("   Created session: {}", session_id);
            
            let test_message = b"Test message through FireProtocol";
            match protocol.send_message(session_id, MessageType::Data, test_message.to_vec()) {
                Ok(message) => {
                    println!("   Sent message: ID={}, type={:?}, size={} bytes",
                        message.id, message.message_type, message.payload.len());
                }
                Err(e) => {
                    error!("Error sending message: {}", e);
                }
            }
            
            match protocol.create_heartbeat_message(session_id) {
                Ok(heartbeat) => {
                    println!("   Created heartbeat: ID={}, sequence={}",
                        heartbeat.id, heartbeat.sequence_number);
                }
                Err(e) => {
                    error!("Error creating heartbeat: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Error creating protocol: {}", e);
        }
    }
    
    println!();
    
    println!("Session Manager Demonstration:");
    let mut session_manager = SessionManager::new();
    
    let session1 = session_manager.create_session(
        "client1",
        "server1",
        master_password,
        "192.168.1.100:1234",
        "192.168.1.1:8080",
        "FireProtocol/1.0"
    )?;
    
    let session2 = session_manager.create_session(
        "client2",
        "server1",
        master_password,
        "192.168.1.101:1235",
        "192.168.1.1:8080",
        "FireProtocol/1.0"
    )?;
    
    println!("   Created sessions: {}", session_manager.get_session_count());
    
    session_manager.record_message_sent(session1, 1024)?;
    session_manager.record_message_received(session1, 512)?;
    session_manager.record_message_sent(session2, 2048)?;
    
    let stats = session_manager.get_session_statistics();
    println!("   Active sessions: {}", stats.active_sessions);
    println!("   Bytes sent: {}", ProtocolUtils::format_data_size(stats.total_bytes_sent));
    println!("   Bytes received: {}", ProtocolUtils::format_data_size(stats.total_bytes_received));
    println!("   Messages sent: {}", stats.total_messages_sent);
    println!("   Messages received: {}", stats.total_messages_received);
    
    println!();
    
    println!("Utilities Demonstration:");
    let test_data = b"Data for encoding";
    let encoded = ProtocolUtils::encode_base64(test_data);
    let decoded = ProtocolUtils::decode_base64(&encoded)?;
    
    println!("   Base64 encoding: '{}' -> '{}'", 
        String::from_utf8_lossy(test_data), encoded);
    println!("   Base64 decoding: '{}' -> '{}'", 
        encoded, String::from_utf8_lossy(&decoded));
    
    let hash = ProtocolUtils::sha256_hash(test_data);
    println!("   SHA-256 hash: {}", hash);
    
    let unique_id = ProtocolUtils::generate_unique_id();
    println!("   Unique ID: {}", unique_id);
    
    println!();
    println!("Demonstration completed!");
    println!("FireProtocol is ready to use with 2 encryption services!");
    
    println!();
    println!("To start the server, use:");
    println!("   cargo run --bin server");
    println!();
    println!("To start the client, use:");
    println!("   cargo run --bin client");
    
    Ok(())
} 