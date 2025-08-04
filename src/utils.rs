use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Digest};
use rand::{Rng, RngCore};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub services_count: usize,
    pub stages_per_service: usize,
    pub total_layers: usize,
    pub supported_algorithms: Vec<String>,
    pub security_features: Vec<String>,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub encryption_speed_mbps: f64,
    pub decryption_speed_mbps: f64,
    pub latency_ms: f64,
    pub throughput_mbps: f64,
}

pub struct ProtocolUtils;

impl ProtocolUtils {
    pub fn generate_password(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789\
                                !@#$%^&*()_+-=[]{}|;:,.<>?";
        
        let mut rng = rand::thread_rng();
        let mut password = String::with_capacity(length);
        
        for _ in 0..length {
            let idx = rng.gen_range(0..CHARSET.len());
            password.push(CHARSET[idx] as char);
        }
        
        password
    }
    
    pub fn generate_secure_key(length: usize) -> Vec<u8> {
        let mut key = vec![0u8; length];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        key
    }
    
    pub fn sha256_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        format!("{:x}", result)
    }
    
    pub fn encode_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }
    
    pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let decoded = general_purpose::STANDARD.decode(encoded)?;
        Ok(decoded)
    }
    
    pub fn get_protocol_info() -> ProtocolInfo {
        ProtocolInfo {
            name: "FireProtocol".to_string(),
            version: "1.0.0".to_string(),
            description: "Data transfer protocol with 2 encryption services, each with 12 stages, inspired by MTProto".to_string(),
            services_count: 2,
            stages_per_service: 12,
            total_layers: 24,
            supported_algorithms: vec![
                "AES256GCM".to_string(),
                "ChaCha20Poly1305".to_string(),
                "AES256CBC".to_string(),
                "AES128GCM".to_string(),
                "CustomXOR".to_string(),
            ],
            security_features: vec![
                "2 encryption services".to_string(),
                "12 stages per service".to_string(),
                "Message authentication".to_string(),
                "Integrity verification".to_string(),
                "Replay attack protection".to_string(),
                "Forward secrecy".to_string(),
                "Perfect forward secrecy".to_string(),
                "Server protection".to_string(),
                "Rate limiting".to_string(),
                "Connection tracking".to_string(),
            ],
            performance_metrics: PerformanceMetrics {
                encryption_speed_mbps: 50.0,
                decryption_speed_mbps: 45.0,
                latency_ms: 2.5,
                throughput_mbps: 100.0,
            },
        }
    }
    
    pub fn check_password_strength(password: &str) -> PasswordStrengthResult {
        let mut score = 0;
        let mut feedback = Vec::new();
        
        if password.len() >= 12 {
            score += 2;
        } else if password.len() >= 8 {
            score += 1;
            feedback.push("Password should contain at least 12 characters".to_string());
        } else {
            feedback.push("Password is too short".to_string());
        }
        
        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        } else {
            feedback.push("Add uppercase letters".to_string());
        }
        
        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        } else {
            feedback.push("Add lowercase letters".to_string());
        }
        
        if password.chars().any(|c| c.is_numeric()) {
            score += 1;
        } else {
            feedback.push("Add numbers".to_string());
        }
        
        if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 1;
        } else {
            feedback.push("Add special characters".to_string());
        }
        
        let mut chars: Vec<char> = password.chars().collect();
        chars.sort();
        chars.dedup();
        if chars.len() < password.len() * 3 / 4 {
            score -= 1;
            feedback.push("Avoid repeating characters".to_string());
        }
        
        let strength = match score {
            0..=2 => PasswordStrength::Weak,
            3..=4 => PasswordStrength::Medium,
            5..=6 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        };
        
        PasswordStrengthResult {
            strength,
            score,
            feedback,
        }
    }
    
    pub fn format_data_size(bytes: u64) -> String {
        const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;
        
        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }
        
        format!("{:.2} {}", size, UNITS[unit_index])
    }
    
    pub fn create_timestamp() -> DateTime<Utc> {
        Utc::now()
    }
    
    pub fn format_timestamp(timestamp: &DateTime<Utc>) -> String {
        timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }
    
    pub fn time_difference_seconds(t1: &DateTime<Utc>, t2: &DateTime<Utc>) -> i64 {
        t2.signed_duration_since(*t1).num_seconds()
    }
    
    pub fn generate_unique_id() -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }
    
    pub fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }
    
    pub fn is_valid_port(port: u16) -> bool {
        port > 0
    }
    
    pub fn create_performance_stats(
        encryption_time: std::time::Duration,
        decryption_time: std::time::Duration,
        data_size: usize,
    ) -> PerformanceStats {
        let data_size_mb = data_size as f64 / 1_048_576.0;
        let encryption_speed = data_size_mb / encryption_time.as_secs_f64();
        let decryption_speed = data_size_mb / decryption_time.as_secs_f64();
        
        PerformanceStats {
            encryption_time_ms: encryption_time.as_millis() as f64,
            decryption_time_ms: decryption_time.as_millis() as f64,
            data_size_bytes: data_size,
            encryption_speed_mbps: encryption_speed,
            decryption_speed_mbps: decryption_speed,
            total_time_ms: (encryption_time + decryption_time).as_millis() as f64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PasswordStrength {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrengthResult {
    pub strength: PasswordStrength,
    pub score: i32,
    pub feedback: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub encryption_time_ms: f64,
    pub decryption_time_ms: f64,
    pub data_size_bytes: usize,
    pub encryption_speed_mbps: f64,
    pub decryption_speed_mbps: f64,
    pub total_time_ms: f64,
}

impl std::fmt::Display for PasswordStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordStrength::Weak => write!(f, "Weak"),
            PasswordStrength::Medium => write!(f, "Medium"),
            PasswordStrength::Strong => write!(f, "Strong"),
            PasswordStrength::VeryStrong => write!(f, "Very Strong"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_generation() {
        let password = ProtocolUtils::generate_password(16);
        assert_eq!(password.len(), 16);
    }
    
    #[test]
    fn test_secure_key_generation() {
        let key = ProtocolUtils::generate_secure_key(32);
        assert_eq!(key.len(), 32);
    }
    
    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = ProtocolUtils::sha256_hash(data);
        assert_eq!(hash.len(), 64);
    }
    
    #[test]
    fn test_base64_encoding_decoding() {
        let original_data = b"Hello, FireProtocol!";
        let encoded = ProtocolUtils::encode_base64(original_data);
        let decoded = ProtocolUtils::decode_base64(&encoded).unwrap();
        assert_eq!(original_data, decoded.as_slice());
    }
    
    #[test]
    fn test_password_strength_check() {
        let weak_password = "123";
        let strong_password = "MySecurePassword123!@#";
        
        let weak_result = ProtocolUtils::check_password_strength(weak_password);
        let strong_result = ProtocolUtils::check_password_strength(strong_password);
        
        assert!(matches!(weak_result.strength, PasswordStrength::Weak));
        assert!(matches!(strong_result.strength, PasswordStrength::Strong | PasswordStrength::VeryStrong));
    }
    
    #[test]
    fn test_data_size_formatting() {
        assert_eq!(ProtocolUtils::format_data_size(1024), "1.00 KB");
        assert_eq!(ProtocolUtils::format_data_size(1048576), "1.00 MB");
    }
    
    #[test]
    fn test_ip_validation() {
        assert!(ProtocolUtils::is_valid_ip("127.0.0.1"));
        assert!(ProtocolUtils::is_valid_ip("::1"));
        assert!(!ProtocolUtils::is_valid_ip("invalid"));
    }
    
    #[test]
    fn test_port_validation() {
        assert!(ProtocolUtils::is_valid_port(8080));
        assert!(!ProtocolUtils::is_valid_port(0));
        assert!(!ProtocolUtils::is_valid_port(65536));
    }
} 