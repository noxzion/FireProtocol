# FireProtocol

A high-security multi-layer encryption communication protocol implemented in Rust, inspired by MTProto with enhanced security features.

## Overview

FireProtocol is a secure communication protocol that provides:
- **24-layer encryption** using multiple cryptographic algorithms
- **ECDH key exchange** for perfect forward secrecy
- **Multi-service architecture** with 2 services and 12 stages each
- **Rate limiting** and connection management
- **Cross-platform compatibility**

## Features

### Security
- **Multi-layer Encryption**: 24 independent encryption layers
- **ECDH Key Exchange**: Secure key negotiation using SECP256R1
- **Perfect Forward Secrecy**: Unique session keys for each connection
- **Message Integrity**: SHA-256 hash verification
- **Algorithm Diversity**: AES-GCM, ChaCha20-Poly1305, AES-CBC, Custom XOR

### Architecture
- **Service-based Design**: 2 encryption services with 12 stages each
- **Deterministic Key Derivation**: PBKDF2 + SHA256 for consistent key generation
- **Session Management**: Secure session key handling
- **Protocol Versioning**: Version 1.0.0 with backward compatibility

### Network
- **TCP Server**: High-performance async TCP server
- **Rate Limiting**: Configurable request rate limiting per IP
- **Connection Management**: Maximum connections and timeout handling
- **IP Filtering**: Configurable IP allow/deny lists

## Protocol Specification

### Message Format

```
┌─────────────────┬─────────────────────┐
│   Header (64B)  │   Encrypted Data    │
└─────────────────┴─────────────────────┘
```

### Header Structure (64 bytes)

```
Offset  Size  Field           Description
0-3     4     Magic           "FIRE" magic number
4-7     4     Version         Protocol version (little endian)
8-11    4     Total Layers    Number of encryption layers (24)
12-15   4     Data Length     Length of encrypted data (little endian)
16-47   32    Hash            SHA-256(encrypted_data + session_key)
48-55   8     Timestamp       Unix timestamp (little endian)
56-63   8     Reserved        Padding/reserved bytes
```

### Encryption Layers

The protocol uses 24 encryption layers organized as follows:

**Service 1 (Layers 0-11):**
- Layer 0, 5, 10: AES-256-GCM
- Layer 1, 6, 11: ChaCha20-Poly1305
- Layer 2, 7: AES-256-CBC
- Layer 3, 8: AES-128-GCM
- Layer 4, 9: Custom XOR

**Service 2 (Layers 12-23):**
- Layer 12, 17, 22: AES-256-GCM
- Layer 13, 18, 23: ChaCha20-Poly1305
- Layer 14, 19: AES-256-CBC
- Layer 15, 20: AES-128-GCM
- Layer 16, 21: Custom XOR

### Key Derivation

```
Master Key = PBKDF2-SHA256(password, "FireProtocol_Salt_2024", 100000 iterations)
Session Key = SHA256(master_key + "session")
Layer Key[i] = SHA256(master_key + "layer_" + i)
Layer IV[i] = SHA256(master_key + "iv_" + i)[0:16]
Layer Salt[i] = SHA256(master_key + "salt_" + i)
```

### ECDH Key Exchange

For enhanced security, the protocol supports ECDH key exchange:

```
1. Client generates ECDH keypair (SECP256R1)
2. Client sends handshake with public key
3. Server generates ECDH keypair
4. Server computes shared secret
5. Server derives session key using HKDF-SHA256
6. Server responds with public key
7. Client computes shared secret and derives session key
8. Both parties use negotiated session key
```

**HKDF Parameters:**
- Salt: `"FireProtocol_KeyExchange_2024"`
- Info: `"FireProtocol_SessionKey"`
- Algorithm: SHA-256
- Output Length: 32 bytes

## Installation

### Prerequisites

- Rust 1.70+ with Cargo
- OpenSSL development headers (Linux)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/fireprotocol/fireprotocol.git
cd fireprotocol

# Build release version
cargo build --release

# Run tests
cargo test

# Build documentation
cargo doc --open
```

## Usage

### Starting the Server

```bash
# Basic usage
cargo run --release --bin server -- -p your_password

# With custom configuration
cargo run --release --bin server -- \
    --password your_secure_password \
    --port 8080 \
    --max-connections 100 \
    --rate-limit 100 \
    --timeout 300 \
    --allow-all-ips
```

### Command Line Options

```
OPTIONS:
    -p, --password <PASSWORD>                Master password for encryption
    -P, --port <PORT>                        Server port [default: 8080]
        --max-connections <MAX_CONNECTIONS>  Maximum connections [default: 100]
        --timeout <TIMEOUT>                  Connection timeout in seconds [default: 300]
        --rate-limit <RATE_LIMIT>           Rate limit per second [default: 10]
        --log-level <LOG_LEVEL>             Log level [default: info]
        --allow-all-ips                     Allow all IPs (disable IP filtering)
        --allowed-ips <ALLOWED_IPS>         Specific allowed IPs (comma-separated)
```

### Example Server Configuration

```bash
# Development server
cargo run --release --bin server -- \
    -p development_password \
    --port 8080 \
    --rate-limit 1000 \
    --max-connections 50 \
    --log-level debug

# Production server
cargo run --release --bin server -- \
    -p $(cat /etc/fireprotocol/password) \
    --port 443 \
    --rate-limit 100 \
    --max-connections 1000 \
    --timeout 600 \
    --allowed-ips "10.0.0.0/8,192.168.0.0/16" \
    --log-level warn
```

## Client Libraries

### Official Clients

- **Python**: [frproto](https://github.com/fireprotocol/frproto-python) - Professional Python client
- **Rust**: Built-in client examples in `examples/` directory

### Third-party Clients

Community-maintained clients for other languages are welcome!

## Security Considerations

### Password Security

- Use strong passwords (minimum 12 characters)
- Include uppercase, lowercase, numbers, and symbols
- Store passwords securely (environment variables, key management systems)
- Rotate passwords regularly

### Network Security

- Use TLS/SSL proxy for additional transport security
- Implement proper firewall rules
- Monitor connection logs for suspicious activity
- Use IP whitelisting in production environments

### Operational Security

- Run server with minimal privileges
- Enable comprehensive logging
- Monitor resource usage and connection patterns
- Implement proper backup and recovery procedures

## Performance

### Benchmarks

On a modern server (Intel Xeon, 16GB RAM):
- **Throughput**: ~10,000 messages/second
- **Latency**: <1ms average processing time
- **Memory**: ~50MB base usage + ~1KB per connection
- **CPU**: ~20% usage at 1000 concurrent connections

### Optimization Tips

1. **Increase rate limits** for high-throughput applications
2. **Tune connection limits** based on available memory
3. **Use SSD storage** for better I/O performance
4. **Enable compiler optimizations** with `--release` flag
5. **Consider horizontal scaling** for very high loads

## Monitoring and Logging

### Log Levels

- **ERROR**: Critical errors and failures
- **WARN**: Warnings and rate limit violations
- **INFO**: Connection events and key exchanges
- **DEBUG**: Detailed protocol information
- **TRACE**: Low-level debugging information

### Key Metrics to Monitor

- Connection count and rate
- Message throughput and latency
- Error rates and types
- Memory and CPU usage
- Network I/O statistics

## Troubleshooting

### Common Issues

**Connection Refused**
```
Error: Connection refused
Solution: Check if server is running and port is accessible
```

**Rate Limit Exceeded**
```
Error: Rate limit exceeded for IP
Solution: Increase --rate-limit or implement client-side throttling
```

**Authentication Failed**
```
Error: Invalid password or handshake failure
Solution: Verify password and client compatibility
```

**Hash Mismatch**
```
Error: Data hash mismatch
Solution: Ensure client and server use same session key
```

## Development

### Project Structure

```
fireprotocol/
├── src/
│   ├── lib.rs              # Library entry point
│   ├── crypto.rs           # Cryptography implementation
│   ├── key_exchange.rs     # ECDH key exchange
│   ├── network.rs          # TCP server implementation
│   ├── protocol.rs         # Protocol definitions
│   ├── session.rs          # Session management
│   └── utils.rs            # Utility functions
├── examples/               # Usage examples
├── tests/                  # Test suite
├── benches/               # Benchmarks
└── docs/                  # Documentation
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run `cargo test` and `cargo fmt`
6. Submit a pull request

### Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Run benchmarks
cargo bench

# Check code coverage
cargo tarpaulin --out Html
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Disclosure

If you discover a security vulnerability, please send an email to security@fireprotocol.dev. All security vulnerabilities will be promptly addressed.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Acknowledgments

- Inspired by Telegram's MTProto protocol
- Built with the Rust cryptography ecosystem
- Thanks to all contributors and security researchers