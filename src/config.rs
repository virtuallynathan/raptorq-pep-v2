use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    Local,
    Remote,
}

// ---------------------------------------------------------------------------
// FecProfile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FecProfile {
    pub k_max: u16,
    pub r_base: u16,
    pub timeout_ms: u64,
}

impl FecProfile {
    /// Number of source symbols for a given payload.
    /// Ceiling division, clamped to `1..=k_max`.
    pub fn k_eff(&self, payload_len: u32, symbol_size: u16) -> u16 {
        let ss = symbol_size as u32;
        if self.k_max == 0 || ss == 0 || payload_len == 0 {
            return 1;
        }
        let raw = payload_len.div_ceil(ss);
        raw.clamp(1, self.k_max as u32) as u16
    }

    /// Repair symbols for a given `k_eff`.
    /// Scales proportionally: `ceil(k_eff * r_base / k_max)`.
    pub fn r_eff(&self, k_eff: u16) -> u16 {
        if self.k_max == 0 || self.r_base == 0 {
            return 0;
        }
        let num = k_eff as u32 * self.r_base as u32 + self.k_max as u32 - 1;
        let val = num / self.k_max as u32;
        val as u16
    }
}

// ---------------------------------------------------------------------------
// RepairConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RepairConfig {
    pub delay_ms: u64,
    pub retry_ms: u64,
    pub deadline_ms: u64,
    pub max_reqs: u8,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub tcp_listen: Option<SocketAddr>,
    pub udp_listen: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub forward: Option<String>,
    pub allowed_targets: Vec<String>,
    pub psk: Vec<u8>,
    pub mtu: u16,
    pub symbol_size: u16,
    pub ipv6: bool,
    pub up: FecProfile,
    pub down: FecProfile,
    pub repair: RepairConfig,
    pub reorder_window: u32,
    pub control_dups: u8,
    pub max_send_mbps: u32,
}

// ---------------------------------------------------------------------------
// ConfigError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "I/O error: {e}"),
            ConfigError::Validation(msg) => write!(f, "config validation: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io(e) => Some(e),
            ConfigError::Validation(_) => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// CliArgs
// ---------------------------------------------------------------------------

/// RaptorQ Performance-Enhancing Proxy
#[derive(Debug, clap::Parser)]
#[command(name = "raptorq-pep", version, about)]
pub struct CliArgs {
    /// Operating mode
    #[arg(long)]
    pub mode: Mode,

    /// TCP listen address (required for local mode)
    #[arg(long)]
    pub tcp_listen: Option<SocketAddr>,

    /// UDP listen address (required for remote mode)
    #[arg(long)]
    pub udp_listen: Option<SocketAddr>,

    /// Remote peer UDP address (required for local mode)
    #[arg(long)]
    pub peer: Option<SocketAddr>,

    /// Forward destination host:port or RTMP URL (required for local mode)
    #[arg(long)]
    pub forward: Option<String>,

    /// Remote-side allowlist entry for negotiated targets. Repeat as needed.
    /// If omitted, any PSK-authenticated target is accepted.
    #[arg(long = "allow-target", value_name = "HOST:PORT")]
    pub allowed_targets: Vec<String>,

    /// Path to pre-shared key file
    #[arg(long)]
    pub psk_file: PathBuf,

    /// Network MTU
    #[arg(long, default_value_t = 1500)]
    pub mtu: u16,

    /// Force IPv6 overhead calculation
    #[arg(long, default_value_t = false)]
    pub ipv6: bool,

    /// Upstream K_max (max source symbols per block)
    #[arg(long, default_value_t = 10)]
    pub up_k_max: u16,

    /// Upstream R_base (base repair symbols)
    #[arg(long, default_value_t = 5)]
    pub up_r_base: u16,

    /// Upstream timeout in milliseconds
    #[arg(long, default_value_t = 20)]
    pub up_timeout_ms: u64,

    /// Downstream K_max
    #[arg(long, default_value_t = 5)]
    pub down_k_max: u16,

    /// Downstream R_base
    #[arg(long, default_value_t = 3)]
    pub down_r_base: u16,

    /// Downstream timeout in milliseconds
    #[arg(long, default_value_t = 50)]
    pub down_timeout_ms: u64,

    /// Repair delay in milliseconds
    #[arg(long, default_value_t = 50)]
    pub repair_delay_ms: u64,

    /// Repair retry interval in milliseconds
    #[arg(long, default_value_t = 100)]
    pub repair_retry_ms: u64,

    /// Repair deadline in milliseconds
    #[arg(long, default_value_t = 3000)]
    pub repair_deadline_ms: u64,

    /// Maximum repair requests per block
    #[arg(long, default_value_t = 4)]
    pub repair_max_reqs: u8,

    /// Maximum number of out-of-order FEC blocks tracked per flow.
    #[arg(long, default_value_t = 64)]
    pub reorder_window: u32,

    /// Copies to send for idempotent control messages
    #[arg(long, default_value_t = 2)]
    pub control_dups: u8,

    /// Max send rate in Mbps
    #[arg(long, default_value_t = 50)]
    pub max_send_mbps: u32,
}

// ---------------------------------------------------------------------------
// Config construction
// ---------------------------------------------------------------------------

// IP + UDP + wire-v2 common header + Data prefix + AEAD tag.
const IPV4_OVERHEAD: u16 = 20 + 8 + 40 + 16 + 16;
const IPV6_OVERHEAD: u16 = 40 + 8 + 40 + 16 + 16;
const RAPTORQ_SYMBOL_ALIGNMENT: u16 = 8;

const MIN_PSK_BYTES: usize = 16;
const RTMP_DEFAULT_PORT: u16 = 1935;
pub(crate) const RAPTORQ_MAX_SOURCE_SYMBOLS: u16 = 56_403;
pub(crate) const WIRE_ESI_SPACE: u32 = u16::MAX as u32 + 1;
const MAX_CONFIGURED_K: u16 = 512;
const MAX_CONFIGURED_REPAIR_SYMBOLS: u16 = 512;
const MAX_MTU: u16 = 9000;
const MAX_REORDER_WINDOW: u32 = 4096;
const MAX_CONTROL_COPIES: u8 = 8;
const MAX_BLOCK_PAYLOAD_BYTES: u64 = 1024 * 1024;
const MAX_PROACTIVE_REPAIR_BYTES: u64 = 1024 * 1024;

fn validate_fec_profile(
    name: &str,
    k_max: u16,
    r_base: u16,
    timeout_ms: u64,
) -> Result<(), ConfigError> {
    if k_max == 0 {
        return Err(ConfigError::Validation(format!(
            "--{name}-k-max must be >= 1"
        )));
    }
    if k_max > RAPTORQ_MAX_SOURCE_SYMBOLS {
        return Err(ConfigError::Validation(format!(
            "--{name}-k-max must be <= {RAPTORQ_MAX_SOURCE_SYMBOLS} (RaptorQ source-symbol limit)"
        )));
    }
    if k_max > MAX_CONFIGURED_K {
        return Err(ConfigError::Validation(format!(
            "--{name}-k-max must be <= {MAX_CONFIGURED_K} to bound per-flow FEC work"
        )));
    }
    if r_base > MAX_CONFIGURED_REPAIR_SYMBOLS {
        return Err(ConfigError::Validation(format!(
            "--{name}-r-base must be <= {MAX_CONFIGURED_REPAIR_SYMBOLS}"
        )));
    }
    if u32::from(k_max) + u32::from(r_base) > WIRE_ESI_SPACE {
        return Err(ConfigError::Validation(format!(
            "--{name}-k-max + --{name}-r-base must be <= {WIRE_ESI_SPACE} (u16 ESI space)"
        )));
    }
    if timeout_ms == 0 {
        return Err(ConfigError::Validation(format!(
            "--{name}-timeout-ms must be >= 1"
        )));
    }
    Ok(())
}

fn validate_fec_memory(
    name: &str,
    k_max: u16,
    r_base: u16,
    symbol_size: u16,
) -> Result<(), ConfigError> {
    let source_bytes = u64::from(k_max) * u64::from(symbol_size);
    if source_bytes > MAX_BLOCK_PAYLOAD_BYTES {
        return Err(ConfigError::Validation(format!(
            "--{name}-k-max and MTU permit a {source_bytes}-byte block; maximum is {MAX_BLOCK_PAYLOAD_BYTES}"
        )));
    }
    let repair_bytes = u64::from(r_base) * u64::from(symbol_size);
    if repair_bytes > MAX_PROACTIVE_REPAIR_BYTES {
        return Err(ConfigError::Validation(format!(
            "--{name}-r-base and MTU permit {repair_bytes} proactive repair bytes per block; maximum is {MAX_PROACTIVE_REPAIR_BYTES}"
        )));
    }
    Ok(())
}

fn parse_port(port: &str) -> Result<u16, ConfigError> {
    let parsed = port
        .parse::<u16>()
        .map_err(|_| ConfigError::Validation(format!("invalid forward target port: {port}")))?;
    if parsed == 0 {
        return Err(ConfigError::Validation(
            "forward target port must be in 1..=65535".into(),
        ));
    }
    Ok(parsed)
}

fn validate_host_port(target: &str) -> Result<(), ConfigError> {
    if target.is_empty() {
        return Err(ConfigError::Validation(
            "forward target must not be empty".into(),
        ));
    }

    if target.starts_with('[') {
        let Some(end_bracket) = target.find("]:") else {
            return Err(ConfigError::Validation(format!(
                "forward target must use [ipv6]:port form, got {target}",
            )));
        };
        let host = &target[1..end_bracket];
        if host.is_empty() {
            return Err(ConfigError::Validation(
                "forward target host must not be empty".into(),
            ));
        }
        let port = &target[end_bracket + 2..];
        parse_port(port)?;
        return Ok(());
    }

    let Some((host, port)) = target.rsplit_once(':') else {
        return Err(ConfigError::Validation(format!(
            "forward target must be host:port or rtmp://host[:port]/..., got {target}",
        )));
    };
    if host.is_empty() {
        return Err(ConfigError::Validation(
            "forward target host must not be empty".into(),
        ));
    }
    if host.contains(':') {
        return Err(ConfigError::Validation(
            "IPv6 forward targets must use [ipv6]:port form".into(),
        ));
    }
    parse_port(port)?;
    Ok(())
}

pub(crate) fn normalize_forward_target(raw: &str) -> Result<String, ConfigError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ConfigError::Validation(
            "--forward must not be empty".into(),
        ));
    }

    if let Some(rest) = value.strip_prefix("rtmp://") {
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(ConfigError::Validation(
                "rtmp:// URL must include host[:port]".into(),
            ));
        }

        let normalized = if authority.starts_with('[') && !authority.contains("]:") {
            format!("{authority}:{RTMP_DEFAULT_PORT}")
        } else if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:{RTMP_DEFAULT_PORT}")
        };
        validate_host_port(&normalized)?;
        return Ok(normalized);
    }

    validate_host_port(value)?;
    Ok(value.to_string())
}
impl Config {
    pub fn from_cli(args: CliArgs) -> Result<Config, ConfigError> {
        // Read PSK as raw bytes (no lossy UTF-8 conversion or trimming).
        let psk = std::fs::read(&args.psk_file)?;
        if psk.len() < MIN_PSK_BYTES {
            return Err(ConfigError::Validation(format!(
                "PSK must be at least {MIN_PSK_BYTES} bytes",
            )));
        }

        validate_fec_profile("up", args.up_k_max, args.up_r_base, args.up_timeout_ms)?;
        validate_fec_profile(
            "down",
            args.down_k_max,
            args.down_r_base,
            args.down_timeout_ms,
        )?;
        if args.repair_deadline_ms == 0 {
            return Err(ConfigError::Validation(
                "--repair-deadline-ms must be >= 1".into(),
            ));
        }
        if args.repair_delay_ms >= args.repair_deadline_ms {
            return Err(ConfigError::Validation(
                "--repair-delay-ms must be less than --repair-deadline-ms".into(),
            ));
        }
        if args.repair_max_reqs > 1 && args.repair_retry_ms == 0 {
            return Err(ConfigError::Validation(
                "--repair-retry-ms must be >= 1 when --repair-max-reqs is greater than 1".into(),
            ));
        }
        if args.max_send_mbps == 0 {
            return Err(ConfigError::Validation(
                "--max-send-mbps must be >= 1".into(),
            ));
        }
        if args.control_dups == 0 {
            return Err(ConfigError::Validation(
                "--control-dups must be >= 1".into(),
            ));
        }
        if args.control_dups > MAX_CONTROL_COPIES {
            return Err(ConfigError::Validation(format!(
                "--control-dups must be <= {MAX_CONTROL_COPIES}"
            )));
        }
        if args.reorder_window == 0 {
            return Err(ConfigError::Validation(
                "--reorder-window must be >= 1".into(),
            ));
        }
        if args.reorder_window > MAX_REORDER_WINDOW {
            return Err(ConfigError::Validation(format!(
                "--reorder-window must be <= {MAX_REORDER_WINDOW}"
            )));
        }
        if args.mtu > MAX_MTU {
            return Err(ConfigError::Validation(format!(
                "--mtu must be <= {MAX_MTU}"
            )));
        }

        let allowed_targets = args
            .allowed_targets
            .iter()
            .map(|target| normalize_forward_target(target))
            .collect::<Result<Vec<_>, _>>()?;

        // Validate mode-specific fields and forward-target ownership.
        let forward = match args.mode {
            Mode::Local => {
                if args.udp_listen.is_some() {
                    return Err(ConfigError::Validation(
                        "--udp-listen is only valid in remote mode".into(),
                    ));
                }
                if !allowed_targets.is_empty() {
                    return Err(ConfigError::Validation(
                        "--allow-target is only valid in remote mode".into(),
                    ));
                }
                if args.tcp_listen.is_none() {
                    return Err(ConfigError::Validation(
                        "--tcp-listen is required in local mode".into(),
                    ));
                }
                if args.peer.is_none() {
                    return Err(ConfigError::Validation(
                        "--peer is required in local mode".into(),
                    ));
                }
                let raw_forward = args.forward.as_deref().ok_or_else(|| {
                    ConfigError::Validation("--forward is required in local mode".into())
                })?;
                Some(normalize_forward_target(raw_forward)?)
            }
            Mode::Remote => {
                if args.tcp_listen.is_some() || args.peer.is_some() {
                    return Err(ConfigError::Validation(
                        "--tcp-listen and --peer are only valid in local mode".into(),
                    ));
                }
                if args.udp_listen.is_none() {
                    return Err(ConfigError::Validation(
                        "--udp-listen is required in remote mode".into(),
                    ));
                }
                if args.forward.is_some() {
                    return Err(ConfigError::Validation(
                        "--forward is only valid in local mode".into(),
                    ));
                }
                None
            }
        };

        // Auto-detect IPv6 from address family
        let ipv6 = args.ipv6
            || args.peer.is_some_and(|a| a.is_ipv6())
            || args.udp_listen.is_some_and(|a| a.is_ipv6());

        let overhead = if ipv6 { IPV6_OVERHEAD } else { IPV4_OVERHEAD };
        let usable_payload = args.mtu.saturating_sub(overhead);
        if usable_payload < RAPTORQ_SYMBOL_ALIGNMENT {
            return Err(ConfigError::Validation(format!(
                "MTU ({}) leaves {usable_payload} bytes after overhead ({overhead}); at least {RAPTORQ_SYMBOL_ALIGNMENT} bytes are required",
                args.mtu,
            )));
        }
        let symbol_size = usable_payload - (usable_payload % RAPTORQ_SYMBOL_ALIGNMENT);
        validate_fec_memory("up", args.up_k_max, args.up_r_base, symbol_size)?;
        validate_fec_memory("down", args.down_k_max, args.down_r_base, symbol_size)?;

        Ok(Config {
            mode: args.mode,
            tcp_listen: args.tcp_listen,
            udp_listen: args.udp_listen,
            peer: args.peer,
            forward,
            allowed_targets,
            psk,
            mtu: args.mtu,
            symbol_size,
            ipv6,
            up: FecProfile {
                k_max: args.up_k_max,
                r_base: args.up_r_base,
                timeout_ms: args.up_timeout_ms,
            },
            down: FecProfile {
                k_max: args.down_k_max,
                r_base: args.down_r_base,
                timeout_ms: args.down_timeout_ms,
            },
            repair: RepairConfig {
                delay_ms: args.repair_delay_ms,
                retry_ms: args.repair_retry_ms,
                deadline_ms: args.repair_deadline_ms,
                max_reqs: args.repair_max_reqs,
            },
            reorder_window: args.reorder_window,
            control_dups: args.control_dups,
            max_send_mbps: args.max_send_mbps,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_PSK_FILE: AtomicU64 = AtomicU64::new(0);

    fn up_profile() -> FecProfile {
        FecProfile {
            k_max: 50,
            r_base: 5,
            timeout_ms: 100,
        }
    }

    fn down_profile() -> FecProfile {
        FecProfile {
            k_max: 5,
            r_base: 2,
            timeout_ms: 250,
        }
    }

    #[test]
    fn test_k_eff_full_block() {
        let p = up_profile();
        let t: u16 = 1424;
        // payload exactly fills k_max * T
        let payload = p.k_max as u32 * t as u32;
        assert_eq!(p.k_eff(payload, t), 50);
    }

    #[test]
    fn test_k_eff_partial() {
        let p = up_profile();
        // 1 byte -> ceil(1/1424) = 1
        assert_eq!(p.k_eff(1, 1424), 1);
    }

    #[test]
    fn test_k_eff_boundary() {
        let p = up_profile();
        let t: u16 = 1424;
        // T+1 bytes -> ceil((T+1)/T) = 2
        assert_eq!(p.k_eff(t as u32 + 1, t), 2);
    }

    #[test]
    fn test_k_eff_zero_payload() {
        let p = up_profile();
        assert_eq!(p.k_eff(0, 1424), 1);
    }

    #[test]
    fn test_k_eff_clamp() {
        let p = up_profile();
        // payload way bigger than k_max * T -> clamp to k_max
        let payload = 100_000u32;
        assert_eq!(p.k_eff(payload, 1424), 50);
    }

    #[test]
    fn test_r_eff_scaling() {
        let p = up_profile(); // k_max=50, r_base=5
        // k_eff = k_max -> r_eff = ceil(50*5/50) = 5
        assert_eq!(p.r_eff(50), 5);
        // k_eff = 1 -> r_eff = ceil(1*5/50) = ceil(5/50) = 1
        assert_eq!(p.r_eff(1), 1);
        // k_eff = 25 -> r_eff = ceil(25*5/50) = ceil(125/50) = 3
        assert_eq!(p.r_eff(25), 3);
        // k_eff = 10 -> r_eff = ceil(10*5/50) = ceil(50/50) = 1
        assert_eq!(p.r_eff(10), 1);

        // Downstream: k_max=5, r_base=2
        let d = down_profile();
        // k_eff = 5 -> r_eff = ceil(5*2/5) = 2
        assert_eq!(d.r_eff(5), 2);
        // k_eff = 1 -> r_eff = ceil(1*2/5) = ceil(2/5) = 1
        assert_eq!(d.r_eff(1), 1);
        // k_eff = 3 -> r_eff = ceil(3*2/5) = ceil(6/5) = 2
        assert_eq!(d.r_eff(3), 2);

        let mut disabled = p;
        disabled.r_base = 0;
        assert_eq!(disabled.r_eff(50), 0);
    }

    #[test]
    fn test_symbol_size_ipv4() {
        let usable = 1500u16 - IPV4_OVERHEAD;
        let t = usable - usable % RAPTORQ_SYMBOL_ALIGNMENT;
        assert_eq!(t, 1400);
        assert_eq!(t % RAPTORQ_SYMBOL_ALIGNMENT, 0);
    }

    #[test]
    fn test_symbol_size_ipv6() {
        let usable = 1500u16 - IPV6_OVERHEAD;
        let t = usable - usable % RAPTORQ_SYMBOL_ALIGNMENT;
        assert_eq!(t, 1376);
        assert_eq!(t % RAPTORQ_SYMBOL_ALIGNMENT, 0);
    }

    fn write_psk_file(bytes: &[u8]) -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "raptorq-pep-config-test-{}-{}",
            std::process::id(),
            NEXT_PSK_FILE.fetch_add(1, Ordering::Relaxed),
        );
        path.push(unique);
        std::fs::write(&path, bytes).expect("write test psk");
        path
    }

    fn local_args(psk_file: PathBuf, forward: Option<&str>) -> CliArgs {
        CliArgs {
            mode: Mode::Local,
            tcp_listen: Some("127.0.0.1:1935".parse().unwrap()),
            udp_listen: None,
            peer: Some("127.0.0.1:9000".parse().unwrap()),
            forward: forward.map(str::to_string),
            allowed_targets: Vec::new(),
            psk_file,
            mtu: 1500,
            ipv6: false,
            up_k_max: 50,
            up_r_base: 5,
            up_timeout_ms: 100,
            down_k_max: 5,
            down_r_base: 2,
            down_timeout_ms: 250,
            repair_delay_ms: 150,
            repair_retry_ms: 300,
            repair_deadline_ms: 500,
            repair_max_reqs: 2,
            reorder_window: 64,
            control_dups: 2,
            max_send_mbps: 10,
        }
    }

    fn remote_args(psk_file: PathBuf, forward: Option<&str>) -> CliArgs {
        CliArgs {
            mode: Mode::Remote,
            tcp_listen: None,
            udp_listen: Some("0.0.0.0:9000".parse().unwrap()),
            peer: None,
            forward: forward.map(str::to_string),
            allowed_targets: Vec::new(),
            psk_file,
            mtu: 1500,
            ipv6: false,
            up_k_max: 50,
            up_r_base: 5,
            up_timeout_ms: 100,
            down_k_max: 5,
            down_r_base: 2,
            down_timeout_ms: 250,
            repair_delay_ms: 150,
            repair_retry_ms: 300,
            repair_deadline_ms: 500,
            repair_max_reqs: 2,
            reorder_window: 64,
            control_dups: 2,
            max_send_mbps: 10,
        }
    }

    #[test]
    fn test_k_eff_zero_kmax_is_safe() {
        let p = FecProfile {
            k_max: 0,
            r_base: 5,
            timeout_ms: 100,
        };
        assert_eq!(p.k_eff(10_000, 1400), 1);
    }

    #[test]
    fn test_local_mode_requires_forward() {
        let psk = write_psk_file(b"0123456789abcdef");
        let args = local_args(psk.clone(), None);
        let err = Config::from_cli(args).unwrap_err();
        let _ = std::fs::remove_file(psk);
        assert!(
            matches!(err, ConfigError::Validation(msg) if msg.contains("--forward is required in local mode"))
        );
    }

    #[test]
    fn test_remote_mode_rejects_forward() {
        let psk = write_psk_file(b"0123456789abcdef");
        let args = remote_args(psk.clone(), Some("live.twitch.tv:1935"));
        let err = Config::from_cli(args).unwrap_err();
        let _ = std::fs::remove_file(psk);
        assert!(
            matches!(err, ConfigError::Validation(msg) if msg.contains("--forward is only valid in local mode"))
        );
    }

    #[test]
    fn test_remote_mode_normalizes_allowed_targets() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = remote_args(psk.clone(), None);
        args.allowed_targets = vec![
            "rtmp://live.twitch.tv/app/key".into(),
            "example.com:443".into(),
        ];
        let cfg = Config::from_cli(args).expect("remote allowlist config");
        let _ = std::fs::remove_file(psk);
        assert_eq!(
            cfg.allowed_targets,
            ["live.twitch.tv:1935", "example.com:443"]
        );
    }

    #[test]
    fn test_local_mode_rejects_allowed_targets() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.allowed_targets = vec!["live.twitch.tv:1935".into()];
        let err = Config::from_cli(args).unwrap_err();
        let _ = std::fs::remove_file(psk);
        assert!(
            matches!(err, ConfigError::Validation(msg) if msg.contains("--allow-target is only valid in remote mode"))
        );
    }

    #[test]
    fn test_forward_rtmp_url_is_normalized() {
        let psk = write_psk_file(b"0123456789abcdef");
        let args = local_args(psk.clone(), Some("rtmp://live.twitch.tv/app/stream-key"));
        let cfg = Config::from_cli(args).expect("config parse");
        let _ = std::fs::remove_file(psk);
        assert_eq!(cfg.forward.as_deref(), Some("live.twitch.tv:1935"));
    }

    #[test]
    fn test_psk_bytes_preserved_exactly() {
        let raw = b"line1\nline2\n1234";
        let psk = write_psk_file(raw);
        let args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        let cfg = Config::from_cli(args).expect("config parse");
        let _ = std::fs::remove_file(psk);
        assert_eq!(cfg.psk, raw);
    }

    #[test]
    fn test_reject_zero_up_k_max() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.up_k_max = 0;
        let err = Config::from_cli(args).unwrap_err();
        let _ = std::fs::remove_file(psk);
        assert!(
            matches!(err, ConfigError::Validation(msg) if msg.contains("--up-k-max must be >= 1"))
        );
    }

    #[test]
    fn test_symbol_size_rejects_less_than_one_alignment_unit() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.mtu = IPV4_OVERHEAD + RAPTORQ_SYMBOL_ALIGNMENT - 1;
        let err = Config::from_cli(args).unwrap_err();
        let _ = std::fs::remove_file(psk);
        assert!(matches!(err, ConfigError::Validation(msg) if msg.contains("at least 8 bytes")));
    }

    #[test]
    fn test_symbol_size_accepts_exactly_one_alignment_unit() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.mtu = IPV4_OVERHEAD + RAPTORQ_SYMBOL_ALIGNMENT;
        let cfg = Config::from_cli(args).expect("minimum aligned symbol size");
        let _ = std::fs::remove_file(psk);
        assert_eq!(cfg.symbol_size, RAPTORQ_SYMBOL_ALIGNMENT);
    }

    #[test]
    fn test_ipv6_peer_uses_aligned_ipv6_symbol_size() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.peer = Some("[::1]:9000".parse().unwrap());
        let cfg = Config::from_cli(args).expect("IPv6 peer config");
        let _ = std::fs::remove_file(psk);
        assert!(cfg.ipv6);
        assert_eq!(cfg.symbol_size, 1376);
    }

    #[test]
    fn test_ipv6_udp_listener_uses_aligned_ipv6_symbol_size() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = remote_args(psk.clone(), None);
        args.udp_listen = Some("[::]:9000".parse().unwrap());
        let cfg = Config::from_cli(args).expect("IPv6 listener config");
        let _ = std::fs::remove_file(psk);
        assert!(cfg.ipv6);
        assert_eq!(cfg.symbol_size, 1376);
    }

    #[test]
    fn test_fec_configuration_bounds() {
        let psk = write_psk_file(b"0123456789abcdef");
        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.up_k_max = MAX_CONFIGURED_K;
        Config::from_cli(args).expect("maximum practical k value");

        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.up_k_max = MAX_CONFIGURED_K + 1;
        let err = Config::from_cli(args).unwrap_err();
        assert!(
            matches!(err, ConfigError::Validation(msg) if msg.contains("bound per-flow FEC work"))
        );

        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.up_r_base = MAX_CONFIGURED_REPAIR_SYMBOLS + 1;
        let err = Config::from_cli(args).unwrap_err();
        let _ = std::fs::remove_file(psk);
        assert!(matches!(err, ConfigError::Validation(msg) if msg.contains("--up-r-base")));

        assert!(matches!(
            validate_fec_profile(
                "up",
                RAPTORQ_MAX_SOURCE_SYMBOLS + 1,
                0,
                1
            ),
            Err(ConfigError::Validation(msg)) if msg.contains("RaptorQ source-symbol limit")
        ));
    }

    #[test]
    fn test_rejects_zero_timeouts_and_required_repair_retry() {
        let psk = write_psk_file(b"0123456789abcdef");

        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.up_timeout_ms = 0;
        assert!(
            matches!(Config::from_cli(args), Err(ConfigError::Validation(msg)) if msg.contains("--up-timeout-ms"))
        );

        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.repair_deadline_ms = 0;
        assert!(
            matches!(Config::from_cli(args), Err(ConfigError::Validation(msg)) if msg.contains("--repair-deadline-ms"))
        );

        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.repair_retry_ms = 0;
        args.repair_max_reqs = 2;
        assert!(
            matches!(Config::from_cli(args), Err(ConfigError::Validation(msg)) if msg.contains("--repair-retry-ms"))
        );

        let mut args = local_args(psk.clone(), Some("live.twitch.tv:1935"));
        args.repair_retry_ms = 0;
        args.repair_max_reqs = 1;
        Config::from_cli(args).expect("retry is unused with one repair request");
        let _ = std::fs::remove_file(psk);
    }
}
