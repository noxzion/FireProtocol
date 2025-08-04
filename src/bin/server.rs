use clap::Parser;
use fire_protocol::{
    network::{FireServer, ServerSecurity},
    utils::ProtocolUtils,
};
use log::{info, warn, error};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Master password for encryption
    #[arg(short, long)]
    password: Option<String>,

    /// Maximum number of connections
    #[arg(long, default_value_t = 100)]
    max_connections: usize,

    /// Connection timeout in seconds
    #[arg(long, default_value_t = 300)]
    timeout: u64,

    /// Rate limit per second
    #[arg(long, default_value_t = 10)]
    rate_limit: u32,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Allow all IPs (disable IP filtering)
    #[arg(long)]
    allow_all_ips: bool,

    /// Specific allowed IPs (comma-separated)
    #[arg(long)]
    allowed_ips: Option<String>,
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

    info!("FireProtocol Server Starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Display protocol information
    let protocol_info = ProtocolUtils::get_protocol_info();
    info!("Protocol: {} v{}", protocol_info.name, protocol_info.version);
    info!("Description: {}", protocol_info.description);
    info!("Encryption Services: {}", protocol_info.services_count);
    info!("Stages per Service: {}", protocol_info.stages_per_service);
    info!("Total Encryption Layers: {}", protocol_info.total_layers);

    // Create server security configuration
    let mut security = ServerSecurity {
        max_connections: args.max_connections,
        connection_timeout: Duration::from_secs(args.timeout),
        rate_limit_per_second: args.rate_limit,
        allowed_ips: Vec::new(),
        require_authentication: true,
    };

    // Configure IP filtering
    if args.allow_all_ips {
        info!("IP filtering disabled - allowing all connections");
    } else if let Some(ips) = args.allowed_ips {
        security.allowed_ips = ips.split(',').map(|s| s.trim().to_string()).collect();
        info!("Allowed IPs: {:?}", security.allowed_ips);
    } else {
        info!("Using default IP filtering (localhost only)");
        security.allowed_ips = vec!["127.0.0.1".to_string(), "::1".to_string()];
    }

    // Display server configuration
    info!("Server Configuration:");
    info!("  Port: {}", args.port);
    info!("  Max Connections: {}", security.max_connections);
    info!("  Connection Timeout: {}s", security.connection_timeout.as_secs());
    info!("  Rate Limit: {} requests/second", security.rate_limit_per_second);
    info!("  Authentication Required: {}", security.require_authentication);

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

    // Create and start server
    let server = FireServer::new(&password, args.port)?
        .with_security(security);

    info!("Starting FireProtocol server on port {}...", args.port);
    info!("Press Ctrl+C to stop the server");

    // Handle graceful shutdown
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.start().await {
            error!("Server error: {}", e);
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping server...");

    // Cancel the server task
    server_handle.abort();
    
    info!("Server stopped successfully");
    Ok(())
} 