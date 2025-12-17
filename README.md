# VULPES Scanner

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**VULPES** (*Latin for "fox"*) is a blazing-fast, multi-threaded security reconnaissance tool written in Rust. Like a clever fox hunting for prey, VULPES efficiently discovers attack surfaces by enumerating subdomains and scanning for open ports across multiple targets simultaneously.

## Features

- **Lightning Fast**: Multi-threaded scanning with configurable thread pools (default: 512 threads)
- **Multiple Data Sources**: Aggregates subdomains from 6+ passive reconnaissance sources
  - Certificate Transparency Logs (crt.sh)
  - HackerTarget API
  - ThreatCrowd
  - AlienVault OTX
  - URLScan.io
  - VirusTotal
- **Comprehensive Port Scanning**: Scans 193 common ports or all 65,535 ports
- **Service Detection**: Automatically identifies services running on open ports
- **Beautiful Output**: Color-coded terminal output with progress bars
- **Export Results**: Save scan results in JSON format
- **Customizable**: Support for custom wordlists for brute-force enumeration
- **Memory Efficient**: Optimized for speed without sacrificing system resources

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo (comes with Rust)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/sunnyallana/vulpes-scanner-rs.git
cd vulpes-scanner-rs

# Build in release mode (optimized)
cargo build --release

# The binary will be available at: ./target/release/vulpes-scanner
```

### Quick Install

```bash
# Build and run directly
cargo run --release -- scan example.com
```

## 🚀 Usage

### Basic Scan

Scan a domain for subdomains and open ports:

```bash
vulpes-scanner scan example.com
```

### Advanced Usage

```bash
# Scan with all enumeration sources (default)
vulpes-scanner scan example.com

# Scan only common ports with increased threads
vulpes-scanner scan example.com -j 1024

# Scan ALL 65,535 ports (slower but comprehensive)
vulpes-scanner scan example.com -a

# Enumerate subdomains only (skip port scanning)
vulpes-scanner scan example.com --enum-only

# Use custom wordlist for subdomain brute-forcing
vulpes-scanner scan example.com -w wordlist.txt

# Save results to JSON file
vulpes-scanner scan example.com -o results.json

# Quiet mode (no progress bars)
vulpes-scanner scan example.com -q

# Custom timeout per port (in milliseconds)
vulpes-scanner scan example.com -t 1000

# Show closed ports in output
vulpes-scanner scan example.com --show-closed
```

### Other Commands

```bash
# Check if a specific subdomain resolves
vulpes-scanner check api.example.com

# List all common ports that are scanned
vulpes-scanner ports
```

## Command Line Options

### Scan Command

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--threads` | `-j` | Number of threads for parallel scanning | 512 |
| `--output` | `-o` | Output file for JSON results | None |
| `--quiet` | `-q` | Quiet mode (no progress bars) | false |
| `--timeout` | `-t` | Scan timeout in milliseconds per port | 500 |
| `--all-ports` | `-a` | Scan all 65535 ports instead of common ports | false |
| `--wordlist` | `-w` | Custom wordlist for subdomain brute-forcing | None |
| `--all-sources` | | Use all enumeration sources | true |
| `--show-closed` | | Include closed ports in output | false |
| `--enum-only` | | Skip port scanning, only enumerate subdomains | false |

## Example Output

```
VULPES Scanner v2.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⠋ Enumerating subdomains for example.com
✓ Found 47 subdomains from passive sources
⠋ Resolving DNS records
✓ 42 subdomains resolved
[========================================] 42/42 Scanning ports
✓ Scan completed in 12.34s

Target: example.com
Subdomains found: 42
Scan time: 12.34s

┌──────────────────────────────────────────────────────────────────┐
│                          SCAN RESULTS                            │
├──────────────────────────────────────────────────────────────────┤
│ www.example.com                                                  │
│   IPs: 93.184.216.34                                             │
│   Ports: 80 (HTTP), 443 (HTTPS)                                 │
├──────────────────────────────────────────────────────────────────┤
│ api.example.com                                                  │
│   IPs: 93.184.216.35                                             │
│   Ports: 443 (HTTPS), 8080 (HTTP Proxy)                         │
├──────────────────────────────────────────────────────────────────┤
└──────────────────────────────────────────────────────────────────┘

15 open ports across 8 subdomains
```

## Architecture

VULPES is built with performance and efficiency in mind:

- **Parallel Processing**: Uses Rayon for CPU-bound parallelism across enumeration and scanning
- **Async I/O**: HTTP requests use Reqwest with connection pooling
- **Memory Efficient**: Streams results instead of loading everything into memory
- **Thread Pool**: Configurable thread pool for port scanning operations
- **Error Handling**: Robust error handling with the `anyhow` and `thiserror` crates

### Technology Stack

- **Core**: Rust 2021 Edition
- **Parallelism**: Rayon
- **HTTP Client**: Reqwest (blocking)
- **CLI**: Clap v4
- **Terminal UI**: Colored + Indicatif
- **Serialization**: Serde + Serde JSON

## Security Considerations

**Important**: VULPES is designed for **authorized security testing only**. 

- Only scan domains you own or have explicit permission to test
- Aggressive scanning may trigger IDS/IPS systems
- Respect rate limits of public APIs
- Some sources may require API keys for full functionality
- Port scanning may be illegal in some jurisdictions without authorization

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development

```bash
# Run tests
cargo test

# Run with debug output
cargo run -- scan example.com

# Format code
cargo fmt

# Lint code
cargo clippy
```

## Roadmap

- [ ] Add support for HTTP/HTTPS probing
- [ ] Implement screenshot capture for web services
- [ ] Add DNS zone transfer detection
- [ ] Support for input file with multiple targets
- [ ] Integration with Shodan/Censys APIs
- [ ] Add Nuclei template execution
- [ ] Generate HTML reports
- [ ] Add rate limiting controls
- [ ] Implement resume functionality for interrupted scans

## Known Issues

- DNSDumpster integration is placeholder (requires CSRF token handling)
- Some APIs may rate limit aggressive queries
- Very large port ranges (-a flag) can take significant time

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have permission before scanning any network or system.

## Acknowledgments

- Thanks to all the public APIs and services that make subdomain enumeration possible
- Inspired by tools like Subfinder, Amass, and Nmap

## Contact

- **Author**: Sunny Allana
- **GitHub**: [@sunnyallana](https://github.com/sunnyallana)
- **Repository**: [vulpes-scanner-rs](https://github.com/sunnyallana/vulpes-scanner-rs)

---

**Star ⭐ this repository if you find it useful!**
