//! VULPES Scanner - Fast multi-threaded security reconnaissance tool
//! Like a clever fox, it hunts for exposed assets and vulnerabilities

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

/// VULPES Scanner - Fast multi-threaded security reconnaissance
#[derive(Parser)]
#[clap(name = "vulpes", version = "2.0.0", author = "Security Team")]
#[clap(about = "Fast security scanner for discovering attack surfaces", long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target for subdomains and open ports
    #[clap(arg_required_else_help = true)]
    Scan {
        /// Target domain (e.g., example.com)
        target: String,

        /// Number of threads for parallel scanning
        #[clap(short = 'j', long, default_value = "512")]
        threads: usize,

        /// Output file for JSON results
        #[clap(short, long)]
        output: Option<String>,

        /// Quiet mode (no progress bars)
        #[clap(short, long)]
        quiet: bool,

        /// Scan timeout in milliseconds per port
        #[clap(short = 't', long, default_value = "500")]
        timeout: u64,

        /// Scan all 65535 ports instead of common ports
        #[clap(short = 'a', long)]
        all_ports: bool,

        /// Custom wordlist for subdomain brute-forcing
        #[clap(short = 'w', long)]
        wordlist: Option<String>,

        /// Use all enumeration sources (crt.sh, hackertarget, threatcrowd, virustotal, etc.)
        #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
        all_sources: bool,

        /// Include closed ports in output
        #[clap(long)]
        show_closed: bool,

        /// Skip port scanning, only enumerate subdomains
        #[clap(long)]
        enum_only: bool,
    },

    /// Check if a specific subdomain resolves
    Check {
        /// Subdomain to check
        subdomain: String,
    },

    /// List common ports that are scanned
    Ports,
}

/// Custom error types for the scanner
#[derive(Error, Debug)]
enum ScannerError {
    #[error("Invalid target domain: {0}")]
    InvalidTarget(String),

    #[error("Port scanning error: {0}")]
    PortScanError(String),

    #[error("Invalid thread count: {0}")]
    InvalidThreadCount(usize),
}

/// Certificate entry from crt.sh API
#[derive(Debug, Deserialize, Clone)]
struct CertificateEntry {
    #[serde(rename = "name_value")]
    name_value: String,
}

/// Subdomain with discovered open ports
#[derive(Debug, Serialize, Clone)]
struct Subdomain {
    domain: String,
    ips: Vec<String>,
    open_ports: Vec<Port>,
    source: Vec<String>,
}

/// Port information
#[derive(Debug, Serialize, Clone)]
struct Port {
    port: u16,
    is_open: bool,
    service: Option<String>,
}

impl Port {
    fn new(port: u16, is_open: bool) -> Self {
        let service = Self::guess_service(port);
        Self {
            port,
            is_open,
            service,
        }
    }

    fn guess_service(port: u16) -> Option<String> {
        match port {
            20 => Some("FTP Data".to_string()),
            21 => Some("FTP".to_string()),
            22 => Some("SSH".to_string()),
            23 => Some("Telnet".to_string()),
            25 => Some("SMTP".to_string()),
            53 => Some("DNS".to_string()),
            80 => Some("HTTP".to_string()),
            110 => Some("POP3".to_string()),
            143 => Some("IMAP".to_string()),
            443 => Some("HTTPS".to_string()),
            465 => Some("SMTPS".to_string()),
            587 => Some("SMTP Submission".to_string()),
            993 => Some("IMAPS".to_string()),
            995 => Some("POP3S".to_string()),
            1433 => Some("MSSQL".to_string()),
            1521 => Some("Oracle DB".to_string()),
            3306 => Some("MySQL".to_string()),
            3389 => Some("RDP".to_string()),
            5432 => Some("PostgreSQL".to_string()),
            5900 => Some("VNC".to_string()),
            6379 => Some("Redis".to_string()),
            8080 => Some("HTTP Proxy".to_string()),
            8443 => Some("HTTPS Alt".to_string()),
            27017 => Some("MongoDB".to_string()),
            _ => None,
        }
    }
}

/// Extended list of 200 most commonly used TCP ports
const MOST_COMMON_PORTS: [u16; 193] = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 1001, 1002,
    1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018,
    1019, 1020, 1021, 1022, 1023, 1024, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 3001,
    3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 4000, 4001, 4002, 4003, 4004, 4005, 4006,
    5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010, 6002, 6003, 6004, 6005, 6006, 6007,
    7000, 7001, 7002, 7003, 7004, 7005, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 9000, 9001, 9002, 9003,
];

/// Fast DNS resolution
fn dns_resolves_fast(domain: &str) -> Option<Vec<IpAddr>> {
    let addr_str = format!("{}:0", domain);

    if let Ok(addrs) = addr_str.to_socket_addrs() {
        let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
        if !ips.is_empty() {
            return Some(ips);
        }
    }
    None
}

/// Load wordlist from file
fn load_wordlist(path: &str) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Failed to open wordlist: {}", path))?;
    let reader = BufReader::new(file);
    let words: Vec<String> = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_lowercase())
        .collect();
    Ok(words)
}

/// Extract subdomains from text content
fn extract_subdomains(text: &str, target: &str) -> Vec<String> {
    let mut subdomains = HashSet::new();
    let target_lower = target.to_lowercase();

    for line in text.lines() {
        let line_lower = line.to_lowercase();

        // Simple substring matching for domains
        if line_lower.contains(&target_lower) {
            for word in line_lower.split_whitespace() {
                let word =
                    word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
                if word.ends_with(&target_lower) && word.contains('.') {
                    let cleaned = word
                        .trim_start_matches("www.")
                        .trim_start_matches('*')
                        .trim_start_matches('.');
                    if !cleaned.is_empty() && !cleaned.contains('*') {
                        subdomains.insert(cleaned.to_string());
                    }
                }
            }
        }
    }

    subdomains.into_iter().collect()
}

/// Query crt.sh for certificate transparency logs
fn query_crtsh(client: &Client, target: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", target);
    let mut subdomains = HashSet::new();

    if let Ok(response) = client.get(&url).timeout(Duration::from_secs(15)).send() {
        if let Ok(entries) = response.json::<Vec<CertificateEntry>>() {
            for entry in entries {
                for name in entry.name_value.split('\n') {
                    let name = name.trim().to_lowercase();
                    if !name.is_empty()
                        && !name.contains('*')
                        && (name.ends_with(&format!(".{}", target)) || name == target)
                    {
                        subdomains.insert(name);
                    }
                }
            }
        }
    }

    subdomains.into_iter().collect()
}

/// Query HackerTarget API
fn query_hackertarget(client: &Client, target: &str) -> Vec<String> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", target);

    if let Ok(response) = client.get(&url).timeout(Duration::from_secs(10)).send() {
        if let Ok(text) = response.text() {
            return extract_subdomains(&text, target);
        }
    }

    Vec::new()
}

/// Query ThreatCrowd API
fn query_threatcrowd(client: &Client, target: &str) -> Vec<String> {
    let url = format!(
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
        target
    );
    let mut subdomains = HashSet::new();

    if let Ok(response) = client.get(&url).timeout(Duration::from_secs(10)).send() {
        if let Ok(json) = response.json::<Value>() {
            if let Some(subs) = json["subdomains"].as_array() {
                for sub in subs {
                    if let Some(subdomain) = sub.as_str() {
                        let subdomain = subdomain.trim().to_lowercase();
                        if !subdomain.is_empty() && !subdomain.contains('*') {
                            subdomains.insert(subdomain);
                        }
                    }
                }
            }
        }
    }

    subdomains.into_iter().collect()
}

/// Query AlienVault OTX API
fn query_alienvault(client: &Client, target: &str) -> Vec<String> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        target
    );
    let mut subdomains = HashSet::new();

    if let Ok(response) = client.get(&url).timeout(Duration::from_secs(10)).send() {
        if let Ok(json) = response.json::<Value>() {
            if let Some(results) = json["passive_dns"].as_array() {
                for result in results {
                    if let Some(hostname) = result["hostname"].as_str() {
                        let hostname = hostname.trim().to_lowercase();
                        if hostname.ends_with(&format!(".{}", target)) || hostname == target {
                            subdomains.insert(hostname);
                        }
                    }
                }
            }
        }
    }

    subdomains.into_iter().collect()
}

/// Query URLScan.io API
fn query_urlscan(client: &Client, target: &str) -> Vec<String> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", target);
    let mut subdomains = HashSet::new();

    if let Ok(response) = client.get(&url).timeout(Duration::from_secs(10)).send() {
        if let Ok(json) = response.json::<Value>() {
            if let Some(results) = json["results"].as_array() {
                for result in results {
                    if let Some(page) = result["page"].as_object() {
                        if let Some(domain) = page["domain"].as_str() {
                            let domain = domain.trim().to_lowercase();
                            if domain.ends_with(&format!(".{}", target)) || domain == target {
                                subdomains.insert(domain);
                            }
                        }
                    }
                }
            }
        }
    }

    subdomains.into_iter().collect()
}

/// Query VirusTotal API (no key needed for basic search)
fn query_virustotal(client: &Client, target: &str) -> Vec<String> {
    let url = format!(
        "https://www.virustotal.com/ui/domains/{}/subdomains?limit=40",
        target
    );
    let mut subdomains = HashSet::new();

    if let Ok(response) = client.get(&url).timeout(Duration::from_secs(10)).send() {
        if let Ok(json) = response.json::<Value>() {
            if let Some(data) = json["data"].as_array() {
                for item in data {
                    if let Some(id) = item["id"].as_str() {
                        let id = id.trim().to_lowercase();
                        if !id.is_empty() && !id.contains('*') {
                            subdomains.insert(id);
                        }
                    }
                }
            }
        }
    }

    subdomains.into_iter().collect()
}

/// Brute-force subdomains using wordlist
fn brute_force_subdomains(
    target: &str,
    wordlist: &[String],
    progress: Option<&ProgressBar>,
) -> Vec<String> {
    let discovered: Vec<String> = wordlist
        .par_iter()
        .filter_map(|word| {
            let subdomain = format!("{}.{}", word, target);
            if let Some(_) = dns_resolves_fast(&subdomain) {
                if let Some(pb) = progress {
                    pb.inc(1);
                }
                Some(subdomain)
            } else {
                if let Some(pb) = progress {
                    pb.inc(1);
                }
                None
            }
        })
        .collect();

    discovered
}

/// Enumerate subdomains using all available sources
fn enumerate_subdomains_all_sources(
    http_client: &Client,
    target: &str,
    all_sources: bool,
    progress: Option<&ProgressBar>,
) -> Result<HashSet<String>, ScannerError> {
    // Validate target
    if !target.contains('.') || target.starts_with('.') || target.ends_with('.') {
        return Err(ScannerError::InvalidTarget(target.to_string()));
    }

    let all_subdomains = Arc::new(Mutex::new(HashSet::new()));
    let target_arc = Arc::new(target.to_string());
    let client_arc = Arc::new(http_client.clone());

    if all_sources {
        // Run all queries in parallel
        let sources = vec![
            "crt.sh",
            "hackertarget",
            "threatcrowd",
            "alienvault",
            "urlscan",
            "virustotal",
        ];

        sources.par_iter().for_each(|&source| {
            if let Some(pb) = progress {
                pb.set_message(format!("Querying {}", source));
            }

            let subdomains = match source {
                "crt.sh" => query_crtsh(&client_arc, &target_arc),
                "hackertarget" => query_hackertarget(&client_arc, &target_arc),
                "threatcrowd" => query_threatcrowd(&client_arc, &target_arc),
                "alienvault" => query_alienvault(&client_arc, &target_arc),
                "urlscan" => query_urlscan(&client_arc, &target_arc),
                "virustotal" => query_virustotal(&client_arc, &target_arc),
                _ => Vec::new(),
            };

            if let Ok(mut all) = all_subdomains.lock() {
                for sub in subdomains {
                    all.insert(sub);
                }
            }
        });
    } else {
        // Just use crt.sh
        let subdomains = query_crtsh(&client_arc, &target_arc);
        if let Ok(mut all) = all_subdomains.lock() {
            for sub in subdomains {
                all.insert(sub);
            }
        }
    }

    // Add the main domain
    if let Ok(mut all) = all_subdomains.lock() {
        all.insert(target.to_string());
    }

    let result = all_subdomains.lock().unwrap().clone();
    Ok(result)
}

/// Resolve all subdomains to IPs in parallel
fn resolve_subdomains(subdomains: HashSet<String>, sources: Vec<String>) -> Vec<Subdomain> {
    subdomains
        .into_par_iter()
        .filter_map(|domain| {
            if let Some(ips) = dns_resolves_fast(&domain) {
                let ip_strings: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                Some(Subdomain {
                    domain,
                    ips: ip_strings,
                    open_ports: Vec::new(),
                    source: sources.clone(),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Scan ports on all subdomains in parallel
fn scan_all_ports(
    subdomains: Vec<Subdomain>,
    threads: usize,
    timeout_ms: u64,
    all_ports: bool,
    show_closed: bool,
    progress: Option<Arc<ProgressBar>>,
) -> Result<Vec<Subdomain>, ScannerError> {
    if threads == 0 {
        return Err(ScannerError::InvalidThreadCount(threads));
    }

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| ScannerError::PortScanError(e.to_string()))?;

    let results: Vec<Subdomain> = pool.install(|| {
        subdomains
            .into_par_iter()
            .map(|subdomain| {
                let result = scan_subdomain_ports(subdomain, timeout_ms, all_ports, show_closed);
                if let Some(ref pb) = progress {
                    pb.inc(1);
                }
                result
            })
            .collect()
    });

    Ok(results)
}

/// Scan ports on a single subdomain
fn scan_subdomain_ports(
    mut subdomain: Subdomain,
    timeout_ms: u64,
    all_ports: bool,
    show_closed: bool,
) -> Subdomain {
    if let Some(ip_str) = subdomain.ips.first() {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            let socket_addr = SocketAddr::new(ip, 0);

            let ports_to_scan: Vec<u16> = if all_ports {
                (1..=65535).collect()
            } else {
                MOST_COMMON_PORTS.to_vec()
            };

            subdomain.open_ports = ports_to_scan
                .into_par_iter()
                .map(|port| scan_single_port(socket_addr, port, timeout_ms))
                .filter(|port| show_closed || port.is_open)
                .collect();
        }
    }

    subdomain
}

/// Scan a single port with optimized timeout
fn scan_single_port(mut socket_addr: SocketAddr, port: u16, timeout_ms: u64) -> Port {
    socket_addr.set_port(port);
    let timeout = Duration::from_millis(timeout_ms);

    let is_open = TcpStream::connect_timeout(&socket_addr, timeout).is_ok();

    Port::new(port, is_open)
}

/// Display the banner
fn print_banner() {
    println!();
    println!("{}", "VULPES Scanner v2.0.0".bold().cyan());
    println!("{}", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed());
    println!();
}

/// Display scan results in a formatted table
fn display_results(results: &[Subdomain], target: &str, duration: Duration, enum_only: bool) {
    println!("{} {}", "Target:".bold(), target.cyan().bold());
    println!(
        "{} {}",
        "Subdomains found:".bold(),
        results.len().to_string().green()
    );
    println!("{} {:.2}s", "Scan time:".bold(), duration.as_secs_f32());

    println!();
    println!(
        "{}",
        "┌──────────────────────────────────────────────────────────────────┐".dimmed()
    );
    println!(
        "{}",
        "│                          SCAN RESULTS                            │".bold()
    );
    println!(
        "{}",
        "├──────────────────────────────────────────────────────────────────┤".dimmed()
    );

    for subdomain in results {
        if enum_only || !subdomain.open_ports.is_empty() {
            println!("│ {:<35} │", subdomain.domain.cyan());

            let ip_str = subdomain.ips.join(", ");
            println!(
                "│   IPs: {:<56} │",
                if ip_str.len() > 56 {
                    &ip_str[..56]
                } else {
                    &ip_str
                }
            );

            if !enum_only && !subdomain.open_ports.is_empty() {
                let ports_str = subdomain
                    .open_ports
                    .iter()
                    .map(|p| {
                        if let Some(service) = &p.service {
                            format!("{} ({})", p.port, service)
                        } else {
                            p.port.to_string()
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(", ");

                println!(
                    "│   Ports: {:<54} │",
                    if ports_str.len() > 54 {
                        &ports_str[..54]
                    } else {
                        &ports_str
                    }
                );
            }

            println!(
                "{}",
                "├──────────────────────────────────────────────────────────────────┤".dimmed()
            );
        }
    }

    println!(
        "{}",
        "└──────────────────────────────────────────────────────────────────┘".dimmed()
    );
    println!();

    // Summary statistics
    if !enum_only {
        let total_open_ports: usize = results.iter().map(|s| s.open_ports.len()).sum();
        let subdomains_with_ports: usize =
            results.iter().filter(|s| !s.open_ports.is_empty()).count();

        println!(
            "{} open ports across {} subdomains",
            total_open_ports.to_string().bold(),
            subdomains_with_ports
        );

        let no_ports_count = results.len() - subdomains_with_ports;
        if no_ports_count > 0 {
            println!("[!] {} subdomains had no open ports", no_ports_count);
        }
    }
}

/// Save results to a JSON file
fn save_results_to_json(results: &[Subdomain], path: &str) -> Result<()> {
    let json =
        serde_json::to_string_pretty(results).context("Failed to serialize results to JSON")?;

    let mut file = File::create(path).context(format!("Failed to create file: {}", path))?;

    file.write_all(json.as_bytes())
        .context("Failed to write results to file")?;

    Ok(())
}

/// Run a full scan
fn run_scan(
    target: &str,
    threads: usize,
    output: Option<String>,
    quiet: bool,
    timeout: u64,
    all_ports: bool,
    wordlist: Option<String>,
    all_sources: bool,
    show_closed: bool,
    enum_only: bool,
) -> Result<()> {
    let start_time = Instant::now();

    let multi = if !quiet {
        Some(MultiProgress::new())
    } else {
        None
    };

    // Create HTTP client
    let http_client = Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .context("Failed to create HTTP client")?;

    // Step 1: Enumerate subdomains from all sources
    let pb_enum = if let Some(ref m) = multi {
        let pb = m.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .unwrap(),
        );
        pb.set_message(format!("Enumerating subdomains for {}", target.cyan()));
        Some(pb)
    } else {
        None
    };

    let mut all_subdomains =
        enumerate_subdomains_all_sources(&http_client, target, all_sources, pb_enum.as_ref())
            .context("Failed to enumerate subdomains")?;

    if let Some(ref pb) = pb_enum {
        pb.finish_with_message(format!(
            "Found {} subdomains from passive sources",
            all_subdomains.len().to_string().green()
        ));
    }

    // Step 2: Brute-force with wordlist if provided
    if let Some(wordlist_path) = wordlist {
        let words = load_wordlist(&wordlist_path)?;

        let pb_brute = if let Some(ref m) = multi {
            let pb = m.add(ProgressBar::new(words.len() as u64));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                    .unwrap(),
            );
            pb.set_message("Brute-forcing subdomains");
            Some(pb)
        } else {
            None
        };

        let brute_forced = brute_force_subdomains(target, &words, pb_brute.as_ref());

        if let Some(ref pb) = pb_brute {
            pb.finish_with_message(format!(
                "Found {} additional subdomains via brute-force",
                brute_forced.len().to_string().green()
            ));
        }

        for sub in brute_forced {
            all_subdomains.insert(sub);
        }
    }

    // Step 3: Resolve all subdomains
    let pb_resolve = if let Some(ref m) = multi {
        let pb = m.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .unwrap(),
        );
        pb.set_message("Resolving DNS records");
        Some(pb)
    } else {
        None
    };

    let sources = vec!["multiple".to_string()];
    let subdomains = resolve_subdomains(all_subdomains, sources);

    if let Some(ref pb) = pb_resolve {
        pb.finish_with_message(format!(
            "{} subdomains resolved",
            subdomains.len().to_string().green()
        ));
    }

    if subdomains.is_empty() {
        println!("[!] No subdomains found or resolved!");
        return Ok(());
    }

    let duration = start_time.elapsed();
    let results = if enum_only {
        // Skip port scanning
        println!();
        display_results(&subdomains, target, duration, true);
        subdomains
    } else {
        // Step 4: Scan ports
        let pb_scan = if let Some(ref m) = multi {
            let pb = m.add(ProgressBar::new(subdomains.len() as u64));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
                    .unwrap(),
            );
            pb.set_message("Scanning ports");
            Some(Arc::new(pb))
        } else {
            None
        };

        let results = scan_all_ports(
            subdomains,
            threads,
            timeout,
            all_ports,
            show_closed,
            pb_scan.clone(),
        )
        .context("Failed to scan ports")?;

        let duration = start_time.elapsed();

        if let Some(ref pb) = pb_scan {
            pb.finish_with_message(format!("Scan completed in {:.2}s", duration.as_secs_f32()));
        }

        println!();
        display_results(&results, target, duration, false);
        results
    };

    if let Some(output_path) = output {
        save_results_to_json(&results, &output_path).context("Failed to save results to file")?;
        println!("[+] Results saved to: {}", output_path.cyan());
    }

    Ok(())
}

/// Check a single subdomain
fn check_subdomain(subdomain: &str) -> Result<()> {
    println!("Checking: {}", subdomain.cyan());

    if let Some(ips) = dns_resolves_fast(subdomain) {
        println!("{}", "[+] Resolves successfully".green());
        println!("IP Addresses:");
        for ip in ips {
            println!("  - {}", ip.to_string().cyan());
        }
    } else {
        println!("{}", "[-] Does not resolve".red());
    }

    Ok(())
}

/// List common ports
fn list_common_ports() {
    println!("Common ports scanned by VULPES:");
    println!();

    println!(
        "{}",
        "┌─────────┬──────────────────────┬─────────────────────────────┐".dimmed()
    );
    println!(
        "{}",
        "│  Port   │       Service        │         Description          │".bold()
    );
    println!(
        "{}",
        "├─────────┼──────────────────────┼─────────────────────────────┤".dimmed()
    );

    for &port in MOST_COMMON_PORTS.iter().take(30) {
        let port_info = Port::new(port, false);
        let service = port_info.service.unwrap_or_else(|| "Unknown".to_string());

        let description = match port {
            80 => "HTTP Web Server",
            443 => "HTTPS Secure Web",
            22 => "Secure Shell",
            25 => "Email Transfer",
            53 => "Domain Name System",
            3306 => "MySQL Database",
            5432 => "PostgreSQL Database",
            3389 => "Remote Desktop",
            8080 => "HTTP Alternative",
            21 => "File Transfer",
            23 => "Remote Terminal",
            110 => "Email Retrieval",
            143 => "Email Access",
            445 => "Windows File Sharing",
            6379 => "Redis Cache",
            27017 => "MongoDB Database",
            _ => "Common Service Port",
        };

        println!(
            "│ {:<7} │ {:<20} │ {:<27} │",
            port.to_string().cyan(),
            service.green(),
            description
        );
    }

    println!(
        "{}",
        "└─────────┴──────────────────────┴─────────────────────────────┘".dimmed()
    );
    println!();
    println!(
        "Total {} common ports scanned (use -a to scan all 65535)",
        MOST_COMMON_PORTS.len()
    );
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !matches!(cli.command, Commands::Check { .. } | Commands::Ports) {
        print_banner();
    }

    match cli.command {
        Commands::Scan {
            target,
            threads,
            output,
            quiet,
            timeout,
            all_ports,
            wordlist,
            all_sources,
            show_closed,
            enum_only,
        } => {
            run_scan(
                &target,
                threads,
                output,
                quiet,
                timeout,
                all_ports,
                wordlist,
                all_sources,
                show_closed,
                enum_only,
            )?;
        }
        Commands::Check { subdomain } => {
            check_subdomain(&subdomain)?;
        }
        Commands::Ports => {
            list_common_ports();
        }
    }

    Ok(())
}
