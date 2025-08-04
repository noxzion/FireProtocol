use clap::Parser;
use fire_protocol::{
    network::FireClient,
    utils::ProtocolUtils,
};
use log::{info, warn, error};
use std::io::{self, Write};
use tokio::time::{sleep, Duration};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server host
    #[arg(short, long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Master password for encryption
    #[arg(short, long)]
    password: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Interactive mode
    #[arg(short, long)]
    interactive: bool,

    /// Send a test message and exit
    #[arg(short, long)]
    test: bool,

    /// Heartbeat interval in seconds
    #[arg(long, default_value_t = 30)]
    heartbeat_interval: u64,

    /// Number of test messages to send
    #[arg(long, default_value_t = 1)]
    test_count: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get password from args or environment
    let password = args.password
        .or_else(|| std::env::var("FIRE_PROTOCOL_PASSWORD").ok())
        .ok_or("Password must be provided via --password argument or FIRE_PROTOCOL_PASSWORD environment variable")?;

    // Setup logging
    std::env::set_var("RUST_LOG", &args.log_level);
    env_logger::init();

    info!("FireProtocol Client Starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Display protocol information
    let protocol_info = ProtocolUtils::get_protocol_info();
    info!("Protocol: {} v{}", protocol_info.name, protocol_info.version);
    info!("Description: {}", protocol_info.description);
    info!("Encryption Services: {}", protocol_info.services_count);
    info!("Stages per Service: {}", protocol_info.stages_per_service);
    info!("Total Encryption Layers: {}", protocol_info.total_layers);

    // Check password strength
    let password_strength = ProtocolUtils::check_password_strength(&password);
    match password_strength.strength {
        fire_protocol::utils::PasswordStrength::Weak => {
            warn!("WARNING: Weak password detected! Consider using a stronger password.");
            warn!("Password feedback: {:?}", password_strength.feedback);
        }
        fire_protocol::utils::PasswordStrength::Medium => {
            warn!("Password strength is medium. Consider using a stronger password.");
        }
        _ => {
            info!("Password strength: {}", password_strength.strength);
        }
    }

    // Create client
    let mut client = FireClient::new(&password)?;
    
    info!("Connecting to {}:{}...", args.host, args.port);
    
    // Connect to server
    match client.connect(&args.host, args.port).await {
        Ok(()) => {
            info!("Successfully connected to server!");
            
            if let Some(session_info) = client.get_session_info() {
                info!("Session ID: {}", session_info.id);
                info!("Client ID: {}", session_info.client_id);
                info!("Server ID: {}", session_info.server_id);
                info!("Session Status: {:?}", session_info.status);
            }
        }
        Err(e) => {
            error!("Failed to connect to server: {}", e);
            return Err(e.into());
        }
    }

    // Display crypto information
    if let Some(crypto_info) = client.get_crypto_info() {
        info!("Crypto Information:");
        for (_, layer) in crypto_info.iter().take(5).enumerate() {
            info!("  Layer {}: {} (Service {}, Stage {})", 
                layer.get("layer_id").unwrap_or(&"Unknown".to_string()),
                layer.get("algorithm").unwrap_or(&"Unknown".to_string()),
                layer.get("service_id").unwrap_or(&"Unknown".to_string()),
                layer.get("stage_id").unwrap_or(&"Unknown".to_string())
            );
        }
        if crypto_info.len() > 5 {
            info!("  ... and {} more layers", crypto_info.len() - 5);
        }
    }

    if args.test {
        // Send test messages
        info!("Sending {} test message(s)...", args.test_count);
        
        for i in 1..=args.test_count {
            let test_message = format!("Test message #{} from FireProtocol client", i);
            info!("Sending: {}", test_message);
            
            match client.send_data(test_message.as_bytes()).await {
                Ok(response) => {
                    let response_str = String::from_utf8_lossy(&response);
                    info!("Received response: {}", response_str);
                }
                Err(e) => {
                    error!("Failed to send test message: {}", e);
                }
            }
            
            if i < args.test_count {
                sleep(Duration::from_millis(100)).await;
            }
        }
        
        info!("Test completed");
    } else if args.interactive {
        // Interactive mode
        info!("Entering interactive mode. Type 'help' for commands, 'quit' to exit.");
        
        let mut heartbeat_handle = None;
        
        // Start heartbeat in background
        if args.heartbeat_interval > 0 {
            let mut client_clone = FireClient::new(&password)?;
            client_clone.connect(&args.host, args.port).await?;
            
            heartbeat_handle = Some(tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(args.heartbeat_interval)).await;
                    if let Err(e) = client_clone.send_heartbeat().await {
                        error!("Heartbeat failed: {}", e);
                        break;
                    }
                    info!("Heartbeat sent");
                }
            }));
        }
        
        // Interactive command loop
        loop {
            print!("fireprotocol> ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            
            match input {
                "help" | "h" => {
                    println!("Available commands:");
                    println!("  send <message>  - Send a message to server");
                    println!("  heartbeat       - Send heartbeat manually");
                    println!("  info            - Show session information");
                    println!("  crypto          - Show crypto information");
                    println!("  help            - Show this help");
                    println!("  quit            - Exit client");
                }
                "quit" | "q" | "exit" => {
                    info!("Disconnecting from server...");
                    break;
                }
                "heartbeat" => {
                    match client.send_heartbeat().await {
                        Ok(()) => info!("Heartbeat sent successfully"),
                        Err(e) => error!("Failed to send heartbeat: {}", e),
                    }
                }
                "info" => {
                    if let Some(session_info) = client.get_session_info() {
                        println!("Session Information:");
                        println!("  ID: {}", session_info.id);
                        println!("  Client ID: {}", session_info.client_id);
                        println!("  Server ID: {}", session_info.server_id);
                        println!("  Status: {:?}", session_info.status);
                        println!("  Created: {}", session_info.created_at);
                        println!("  Last Activity: {}", session_info.last_activity);
                        println!("  Sequence Number: {}", session_info.sequence_number);
                    } else {
                        println!("No session information available");
                    }
                }
                "crypto" => {
                    if let Some(crypto_info) = client.get_crypto_info() {
                        println!("Crypto Information:");
                        for (_, layer) in crypto_info.iter().take(10).enumerate() {
                            println!("  Layer {}: {} (Service {}, Stage {})", 
                                layer.get("layer_id").unwrap_or(&"Unknown".to_string()),
                                layer.get("algorithm").unwrap_or(&"Unknown".to_string()),
                                layer.get("service_id").unwrap_or(&"Unknown".to_string()),
                                layer.get("stage_id").unwrap_or(&"Unknown".to_string())
                            );
                        }
                        if crypto_info.len() > 10 {
                            println!("  ... and {} more layers", crypto_info.len() - 10);
                        }
                    } else {
                        println!("No crypto information available");
                    }
                }
                input if input.starts_with("send ") => {
                    let message = &input[5..];
                    if message.is_empty() {
                        println!("Usage: send <message>");
                        continue;
                    }
                    
                    info!("Sending: {}", message);
                    match client.send_data(message.as_bytes()).await {
                        Ok(response) => {
                            let response_str = String::from_utf8_lossy(&response);
                            info!("Received response: {}", response_str);
                        }
                        Err(e) => {
                            error!("Failed to send message: {}", e);
                        }
                    }
                }
                "" => continue,
                _ => {
                    println!("Unknown command: {}. Type 'help' for available commands.", input);
                }
            }
        }
        
        // Cancel heartbeat task
        if let Some(handle) = heartbeat_handle {
            handle.abort();
        }
    } else {
        // Simple connection test
        info!("Connection test successful!");
        info!("Use --interactive for interactive mode or --test to send test messages");
    }

    // Disconnect
    match client.disconnect().await {
        Ok(()) => info!("Disconnected from server"),
        Err(e) => warn!("Error during disconnect: {}", e),
    }

    info!("Client stopped successfully");
    Ok(())
} 