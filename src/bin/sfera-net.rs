use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sfera::remote::{
    self, CLIENT_TUN_IP, CongestionMode, DEFAULT_MAX_MBPS, DEFAULT_MTU, SERVER_TUN_IP,
    TunnelConfig, UNLIMITED_MBPS,
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Parser)]
#[command(about = "Experimental SFERA MEDIA IPv4 TUN transport over DTLS-SRTP")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a Linux TUN server with loopback signaling.
    Server {
        /// IPv4 address advertised in ICE, reachable by the client on UDP.
        #[arg(long)]
        public_ip: Ipv4Addr,
        #[arg(long, default_value_t = 443)]
        udp_port: u16,
        #[arg(long, default_value = "127.0.0.1:7443")]
        signal_listen: SocketAddr,
        /// File containing the signaling bearer token.
        #[arg(long, required_unless_present = "peer_credentials")]
        signal_token_file: Option<PathBuf>,
        /// File of per-client IPv4 addresses and signaling bearer tokens.
        #[arg(long, conflicts_with = "signal_token_file")]
        peer_credentials: Option<PathBuf>,
        /// Publish per-peer counters atomically in multi-peer mode.
        #[arg(long, requires = "peer_credentials")]
        status_file: Option<PathBuf>,
        /// Linux TUN name prefix for an isolated server instance.
        #[arg(long, requires = "peer_credentials")]
        tun_name: Option<String>,
        #[arg(long, default_value_t = SERVER_TUN_IP)]
        tun_ip: Ipv4Addr,
        #[arg(long, default_value_t = CLIENT_TUN_IP)]
        peer_ip: Ipv4Addr,
        #[arg(long, default_value_t = DEFAULT_MTU)]
        mtu: u16,
        /// Explicit pacing cap for lab experiments. Normal IpTunnel adapts without a fixed cap.
        #[arg(long)]
        max_mbps: Option<f64>,
        #[arg(long, value_enum, default_value = "ip-tunnel")]
        congestion: CongestionMode,
    },
    /// Connect through authenticated HTTPS signaling.
    Client {
        /// HTTPS session URL with an IPv4 host, e.g. https://192.0.2.1/api/session.
        #[arg(long)]
        signal_url: String,
        /// File containing the signaling bearer token.
        #[arg(long)]
        signal_token_file: PathBuf,
        #[arg(long, default_value_t = CLIENT_TUN_IP)]
        tun_ip: Ipv4Addr,
        #[arg(long, default_value_t = SERVER_TUN_IP)]
        peer_ip: Ipv4Addr,
        #[arg(long, default_value_t = DEFAULT_MTU)]
        mtu: u16,
        /// Explicit pacing cap for lab experiments. Normal IpTunnel adapts without a fixed cap.
        #[arg(long)]
        max_mbps: Option<f64>,
        #[arg(long, value_enum, default_value = "ip-tunnel")]
        congestion: CongestionMode,
        /// Write interface and transfer status here after media authenticates.
        #[arg(long, conflicts_with = "check")]
        status_file: Option<PathBuf>,
        /// Check ICE, DTLS and encrypted RTP without creating an interface.
        #[arg(long)]
        check: bool,
        /// Duration of the authenticated probe sample, in seconds (default: 5).
        #[arg(long, requires = "check")]
        check_seconds: Option<u16>,
    },
}

fn configured_rate(mode: CongestionMode, explicit: Option<f64>) -> f64 {
    explicit.unwrap_or(match mode {
        CongestionMode::IpTunnel => UNLIMITED_MBPS,
        _ => DEFAULT_MAX_MBPS,
    })
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Server {
            public_ip,
            udp_port,
            signal_listen,
            signal_token_file,
            peer_credentials,
            status_file,
            tun_name,
            tun_ip,
            peer_ip,
            mtu,
            max_mbps,
            congestion,
        } => {
            let config = TunnelConfig {
                local_ip: tun_ip,
                peer_ip,
                mtu,
                max_mbps: configured_rate(congestion, max_mbps),
                congestion,
            };
            if let Some(path) = peer_credentials {
                #[cfg(target_os = "linux")]
                return remote::serve_multi(
                    signal_listen,
                    &path,
                    public_ip,
                    udp_port,
                    config,
                    status_file.as_deref(),
                    tun_name.as_deref(),
                );
                #[cfg(not(target_os = "linux"))]
                anyhow::bail!("multi-peer server requires Linux: {}", path.display());
            }
            #[cfg(not(target_os = "linux"))]
            let _ = (status_file, tun_name);
            remote::serve(
                signal_listen,
                &signal_token_file.context("missing signaling token file")?,
                public_ip,
                udp_port,
                config,
            )
        }
        Command::Client {
            signal_url,
            signal_token_file,
            tun_ip,
            peer_ip,
            mtu,
            max_mbps,
            congestion,
            status_file,
            check,
            check_seconds,
        } => {
            let config = TunnelConfig {
                local_ip: tun_ip,
                peer_ip,
                mtu,
                max_mbps: configured_rate(congestion, max_mbps),
                congestion,
            };
            if check {
                remote::check(
                    &signal_url,
                    &signal_token_file,
                    config,
                    check_seconds.unwrap_or(5),
                )
            } else {
                remote::connect(
                    &signal_url,
                    &signal_token_file,
                    config,
                    status_file.as_deref(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_tunnel_defaults_to_no_fixed_cap_on_client_and_server() {
        let server = Cli::try_parse_from([
            "sfera-net",
            "server",
            "--public-ip",
            "192.0.2.1",
            "--peer-credentials",
            "peers",
        ])
        .unwrap();
        let client = Cli::try_parse_from([
            "sfera-net",
            "client",
            "--signal-url",
            "https://192.0.2.1/api/session",
            "--signal-token-file",
            "token",
        ])
        .unwrap();
        for (mode, rate) in [server, client].into_iter().map(|cli| match cli.command {
            Command::Server {
                congestion,
                max_mbps,
                ..
            }
            | Command::Client {
                congestion,
                max_mbps,
                ..
            } => (congestion, max_mbps),
        }) {
            assert_eq!(mode, CongestionMode::IpTunnel);
            assert!(rate.is_none());
            assert_eq!(configured_rate(mode, rate), UNLIMITED_MBPS);
        }
        assert_eq!(
            configured_rate(CongestionMode::IpTunnel, Some(700.0)),
            700.0
        );
        assert_eq!(
            configured_rate(CongestionMode::ArrivalFeedback, None),
            DEFAULT_MAX_MBPS
        );
    }
}
