use aes_gcm::{Aes256Gcm, Aes128Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray,
};

use rand::RngCore;
use sha2::{Sha256, Digest};
use hmac::Hmac;
use pbkdf2::pbkdf2;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::error::FireProtocolError;

pub const ENCRYPTION_SERVICE_COUNT: usize = 2;
pub const STAGES_PER_SERVICE: usize = 12;
pub const TOTAL_LAYERS: usize = ENCRYPTION_SERVICE_COUNT * STAGES_PER_SERVICE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoLayer {
    pub layer_id: u32,
    pub service_id: u32,
    pub stage_id: u32,
    pub algorithm: EncryptionAlgorithm,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub salt: Vec<u8>,
    pub rounds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    AES256CBC,
    AES128GCM,
    CustomXOR,
}

#[derive(Debug, Clone)]
pub struct EncryptionService {
    pub service_id: u32,
    pub stages: Vec<CryptoLayer>,
}

#[derive(Debug, Clone)]
pub struct MultiLayerCrypto {
    pub services: Vec<EncryptionService>,
    session_key: Vec<u8>,
    #[allow(dead_code)]
    master_key: Vec<u8>,
}

impl MultiLayerCrypto {
    pub fn new(master_password: &str, custom_session_key: Option<Vec<u8>>) -> Result<Self, FireProtocolError> {
        let mut rng = rand::thread_rng();
        let master_key = Self::derive_master_key(master_password)?;
        let session_key = match custom_session_key {
            Some(key) => key,
            None => Self::generate_session_key(&master_key),
        };
        
        let mut services = Vec::with_capacity(ENCRYPTION_SERVICE_COUNT);
        
        for service_id in 0..ENCRYPTION_SERVICE_COUNT {
            let mut stages = Vec::with_capacity(STAGES_PER_SERVICE);
            
            for stage_id in 0..STAGES_PER_SERVICE {
                let layer_id = service_id * STAGES_PER_SERVICE + stage_id;
                let algorithm = match stage_id % 5 {
                    0 => EncryptionAlgorithm::AES256GCM,
                    1 => EncryptionAlgorithm::ChaCha20Poly1305,
                    2 => EncryptionAlgorithm::AES256CBC,
                    3 => EncryptionAlgorithm::AES128GCM,
                    4 => EncryptionAlgorithm::CustomXOR,
                    _ => EncryptionAlgorithm::AES256GCM,
                };
                
                let iv = Self::generate_iv(&algorithm, &master_key, layer_id);
                let layer = CryptoLayer {
                    layer_id: layer_id as u32,
                    service_id: service_id as u32,
                    stage_id: stage_id as u32,
                    algorithm,
                    key: Self::generate_layer_key(&master_key, layer_id, &mut rng),
                    iv,
                    salt: Self::generate_salt(&master_key, layer_id),
                    rounds: 10000 + (layer_id * 100) as u32,
                };
                
                stages.push(layer);
            }
            
            services.push(EncryptionService {
                service_id: service_id as u32,
                stages,
            });
        }
        
        Ok(MultiLayerCrypto {
            services,
            session_key,
            master_key,
        })
    }
    
    /// Create MultiLayerCrypto with default session key (backward compatibility)
    pub fn new_default(master_password: &str) -> Result<Self, FireProtocolError> {
        Self::new(master_password, None)
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, FireProtocolError> {
        let mut encrypted_data = data.to_vec();
        
        for service in &self.services {
            for stage in &service.stages {
                encrypted_data = self.apply_encryption_layer(&encrypted_data, stage)?;
            }
        }
        
        let header = self.create_header(&encrypted_data)?;
        let mut result = header;
        result.extend(encrypted_data);
        
        Ok(result)
    }
    
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, FireProtocolError> {
        let (header, data) = self.extract_header(encrypted_data)?;
        self.verify_header(&header, &data)?;
        
        let mut decrypted_data = data.to_vec();
        
        for service in self.services.iter().rev() {
            for stage in service.stages.iter().rev() {
                decrypted_data = self.apply_decryption_layer(&decrypted_data, stage)?;
            }
        }
        
        Ok(decrypted_data)
    }
    
    pub fn apply_encryption_layer(&self, data: &[u8], layer: &CryptoLayer) -> Result<Vec<u8>, FireProtocolError> {
        match layer.algorithm {
            EncryptionAlgorithm::AES256GCM => {
                let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&layer.key);
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(&layer.iv);
                let encrypted = cipher.encrypt(nonce, data)?;
                Ok(encrypted)
            },
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let key = chacha20poly1305::Key::from_slice(&layer.key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = ChaChaNonce::from_slice(&layer.iv);
                let encrypted = cipher.encrypt(nonce, data)?;
                Ok(encrypted)
            },
            EncryptionAlgorithm::AES256CBC => {
                let key = GenericArray::clone_from_slice(&layer.key[..32]);
                let cipher = Aes256::new(&key);
                
                // Pad data to block size
                let block_size = 16;
                let mut padded_data = data.to_vec();
                let padding_len = block_size - (padded_data.len() % block_size);
                padded_data.extend(std::iter::repeat(padding_len as u8).take(padding_len));
                
                let mut encrypted = Vec::new();
                let mut prev_block = GenericArray::clone_from_slice(&layer.iv[..16]);
                
                for chunk in padded_data.chunks(block_size) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    
                    // XOR with previous block (CBC mode)
                    for i in 0..16 {
                        block[i] ^= prev_block[i];
                    }
                    
                    cipher.encrypt_block(&mut block);
                    encrypted.extend_from_slice(&block);
                    prev_block = block;
                }
                
                Ok(encrypted)
            },
            EncryptionAlgorithm::AES128GCM => {
                let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&layer.key[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = Nonce::from_slice(&layer.iv);
                let encrypted = cipher.encrypt(nonce, data)?;
                Ok(encrypted)
            },
            EncryptionAlgorithm::CustomXOR => {
                let mut encrypted = Vec::new();
                for (i, &byte) in data.iter().enumerate() {
                    let key_byte = layer.key[i % layer.key.len()];
                    let salt_byte = layer.salt[i % layer.salt.len()];
                    encrypted.push(byte ^ key_byte ^ salt_byte);
                }
                Ok(encrypted)
            },
        }
    }
    
    pub fn apply_decryption_layer(&self, data: &[u8], layer: &CryptoLayer) -> Result<Vec<u8>, FireProtocolError> {
        match layer.algorithm {
            EncryptionAlgorithm::AES256GCM => {
                let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&layer.key);
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(&layer.iv);
                let decrypted = cipher.decrypt(nonce, data)?;
                Ok(decrypted)
            },
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let key = chacha20poly1305::Key::from_slice(&layer.key);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = ChaChaNonce::from_slice(&layer.iv);
                let decrypted = cipher.decrypt(nonce, data)?;
                Ok(decrypted)
            },
            EncryptionAlgorithm::AES256CBC => {
                let key = GenericArray::clone_from_slice(&layer.key[..32]);
                let cipher = Aes256::new(&key);
                
                if data.len() % 16 != 0 {
                    return Err(FireProtocolError::CryptoError("Invalid block size for CBC decryption".to_string()));
                }
                
                let mut decrypted = Vec::new();
                let mut prev_block = GenericArray::clone_from_slice(&layer.iv[..16]);
                
                for chunk in data.chunks(16) {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    let current_block = block.clone();
                    
                    cipher.decrypt_block(&mut block);
                    
                    // XOR with previous block (CBC mode)
                    for i in 0..16 {
                        block[i] ^= prev_block[i];
                    }
                    
                    decrypted.extend_from_slice(&block);
                    prev_block = current_block;
                }
                
                // Remove padding
                if let Some(&padding_len) = decrypted.last() {
                    if padding_len <= 16 && padding_len > 0 {
                        let padding_start = decrypted.len() - padding_len as usize;
                        if decrypted[padding_start..].iter().all(|&b| b == padding_len) {
                            decrypted.truncate(padding_start);
                        }
                    }
                }
                
                Ok(decrypted)
            },
            EncryptionAlgorithm::AES128GCM => {
                let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&layer.key[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = Nonce::from_slice(&layer.iv);
                let decrypted = cipher.decrypt(nonce, data)?;
                Ok(decrypted)
            },
            EncryptionAlgorithm::CustomXOR => {
                let mut decrypted = Vec::new();
                for (i, &byte) in data.iter().enumerate() {
                    let key_byte = layer.key[i % layer.key.len()];
                    let salt_byte = layer.salt[i % layer.salt.len()];
                    decrypted.push(byte ^ key_byte ^ salt_byte);
                }
                Ok(decrypted)
            },
        }
    }
    
    fn derive_master_key(password: &str) -> Result<Vec<u8>, FireProtocolError> {
        let salt = b"FireProtocol_Salt_2024";
        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100000, &mut key)?;
        Ok(key.to_vec())
    }
    
    fn generate_session_key(master_key: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(b"session_key");
        hasher.update(b"fire_protocol_v1"); // Добавляем версию для совместимости
        hasher.finalize().to_vec()
    }
    
    fn generate_layer_key(master_key: &[u8], layer_id: usize, _rng: &mut impl RngCore) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(layer_id.to_le_bytes());
        hasher.update(b"layer_key");
        hasher.finalize().to_vec()
    }
    
    fn generate_iv(algorithm: &EncryptionAlgorithm, master_key: &[u8], layer_id: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(layer_id.to_le_bytes());
        hasher.update(b"iv");
        let hash = hasher.finalize();
        
        match algorithm {
            EncryptionAlgorithm::AES256GCM | EncryptionAlgorithm::AES128GCM => {
                hash[..12].to_vec()
            },
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                hash[..12].to_vec()
            },
            EncryptionAlgorithm::AES256CBC => {
                hash[..16].to_vec()
            },
            EncryptionAlgorithm::CustomXOR => {
                hash[..16].to_vec()
            },
        }
    }
    
    fn generate_salt(master_key: &[u8], layer_id: usize) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(master_key);
        hasher.update(layer_id.to_le_bytes());
        hasher.update(b"salt");
        hasher.finalize().to_vec()
    }
    
    fn create_header(&self, data: &[u8]) -> Result<Vec<u8>, FireProtocolError> {
        let mut header = Vec::new();
        
        header.extend_from_slice(b"FIRE");
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&(TOTAL_LAYERS as u32).to_le_bytes());
        header.extend_from_slice(&(data.len() as u32).to_le_bytes());
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(&self.session_key);
        let hash = hasher.finalize();
        header.extend_from_slice(&hash);
        
        // Отладочная информация
        log::debug!("Creating header for data length: {}", data.len());
        log::debug!("Session key length: {}", self.session_key.len());
        log::debug!("Generated hash: {:?}", hash.as_slice());
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        header.extend_from_slice(&timestamp.to_le_bytes());
        
        Ok(header)
    }
    
    fn extract_header(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FireProtocolError> {
        if data.len() < 64 {
            return Err(FireProtocolError::CryptoError("Insufficient data for header".to_string()));
        }
        
        let header = data[..64].to_vec();
        let payload = data[64..].to_vec();
        
        Ok((header, payload))
    }
    
    fn verify_header(&self, header: &[u8], data: &[u8]) -> Result<(), FireProtocolError> {
        if header.len() < 64 {
            return Err(FireProtocolError::CryptoError("Invalid header size".to_string()));
        }
        
        if &header[0..4] != b"FIRE" {
            return Err(FireProtocolError::CryptoError("Invalid magic number".to_string()));
        }
        
        // Проверяем хеш зашифрованных данных (data), а не исходных
        let expected_hash = &header[16..48];
        let mut hasher = Sha256::new();
        hasher.update(data); // data - это уже зашифрованные данные
        hasher.update(&self.session_key);
        let actual_hash = hasher.finalize();
        
        // Отладочная информация
        log::debug!("Data length: {}", data.len());
        log::debug!("Session key length: {}", self.session_key.len());
        log::debug!("Expected hash: {:?}", expected_hash);
        log::debug!("Actual hash: {:?}", actual_hash.as_slice());
        
        if expected_hash != actual_hash.as_slice() {
            return Err(FireProtocolError::CryptoError("Data hash mismatch".to_string()));
        }
        
        Ok(())
    }
    
    pub fn get_service_info(&self) -> Vec<HashMap<String, String>> {
        self.services.iter().map(|service| {
            let mut info = HashMap::new();
            info.insert("service_id".to_string(), service.service_id.to_string());
            info.insert("stages_count".to_string(), service.stages.len().to_string());
            info.insert("algorithms".to_string(), service.stages.iter()
                .map(|s| format!("{:?}", s.algorithm))
                .collect::<Vec<_>>()
                .join(", "));
            info
        }).collect()
    }
    
    pub fn get_layer_info(&self) -> Vec<HashMap<String, String>> {
        self.services.iter().flat_map(|service| {
            service.stages.iter().map(|layer| {
                let mut info = HashMap::new();
                info.insert("layer_id".to_string(), layer.layer_id.to_string());
                info.insert("service_id".to_string(), layer.service_id.to_string());
                info.insert("stage_id".to_string(), layer.stage_id.to_string());
                info.insert("algorithm".to_string(), format!("{:?}", layer.algorithm));
                info.insert("key_length".to_string(), layer.key.len().to_string());
                info.insert("iv_length".to_string(), layer.iv.len().to_string());
                info.insert("rounds".to_string(), layer.rounds.to_string());
                info
            })
        }).collect()
    }
} 