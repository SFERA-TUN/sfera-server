//! Authenticated IPv4 TUN over the SFERA RTP/DTLS-SRTP carrier.
//!
//! An authenticated HTTPS exchange supplies SDP and DTLS fingerprints.
//! IP packets only travel as encrypted RTP on UDP, with encrypted liveness probes.

use crate::{
    congestion::{ArrivalReport, Controller},
    media,
    path_mtu::{PathMtu, enable_dont_fragment, is_message_too_large},
    signaling::{self, Endpoint, Token, valid_media_endpoint},
    wire::{Frame, HEADER, Kind, MAX_DATA, MAX_WIDE_DATAGRAM},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use socket2::SockRef;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use std::sync::mpsc;
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    hash::{BuildHasher, RandomState},
    io::{self, ErrorKind, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    path::Path,
    sync::mpsc::Receiver,
    thread,
    time::{Duration, Instant},
};
use str0m::bwe::{Bitrate, BweKind};
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::config::DtlsVersion;
use str0m::format::Codec;
use str0m::ice::{StunMessageBuilder, TransId};
use str0m::media::{Direction, MediaKind, Mid};
use str0m::net::{Protocol, Receive, Transmit};
use str0m::rtp::RtpWrite;
use str0m::{Candidate, Event, Input, Output, Rtc};
#[cfg(not(any(target_os = "ios", target_os = "android")))]
use tun_rs::{DeviceBuilder, SyncDevice};

mod delivery;
mod egress;
mod pacing;
mod repair;
#[cfg(target_os = "linux")]
mod server;

use egress::StagedPackets;

#[cfg(target_os = "linux")]
pub use server::serve_multi;

pub const DEFAULT_MTU: u16 = 1280;
/// Default for the experimental congestion-control modes.
pub const DEFAULT_MAX_MBPS: f64 = 100.0;
/// No software bitrate ceiling for ordinary IP tunneling.
pub const UNLIMITED_MBPS: f64 = f64::INFINITY;
pub const SERVER_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 1);
pub const CLIENT_TUN_IP: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 2);
const DATA_FLOW: u32 = 10;
const PING_FLOW: u32 = 11;
const ECHO_FLOW: u32 = 12;
const FRAGMENT_FLOW: u32 = 13;
const ARRIVAL_FLOW: u32 = 14;
const MTU_PROBE_FLOW: u32 = 15;
const MTU_ECHO_FLOW: u32 = 16;
const FRAME_END_FLOW: u32 = 17;
const CAMERA_COVER_FLOW: u32 = 18;
const REPAIR_REQUEST_FLOW: u32 = 19;
const REPAIRED_DATA_FLOW: u32 = 20;
const REPAIRED_FRAGMENT_FLOW: u32 = 21;
const DELIVERY_REPORT_FLOW: u32 = 22;
const DELIVERY_ACK_FLOW: u32 = 23;
const MTU_ECHO_INTERVAL: Duration = Duration::from_millis(250);
const RTP_FRAME_SPAN: Duration = Duration::from_micros(33_333);
const FRAME_END_MIN_PAYLOAD: usize = 16;
const FRAME_END_MAX_PAYLOAD: usize = 96;
const MAX_WIDE_PADDING: usize = 8;
const FIRST_FRAGMENT_BYTES: usize = MAX_DATA - 1;
const MAX_REASSEMBLIES: usize = 64;
const REASSEMBLY_AGE: Duration = Duration::from_millis(250);
const PROBE_BODY: [u8; 1] = [1];
const ICE_STARTUP_GRACE: Duration = Duration::from_secs(2);
const BINDING_INDICATION_DELAY: Duration = Duration::from_millis(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const INITIAL_MBPS: f64 = 4.0;
const ARRIVAL_PROBE_INTERVAL: Duration = Duration::from_millis(200);
const MAX_NATIVE_PENDING: usize = 16;
const MAX_PACKET_QUEUE: usize = 32;
const MAX_QUEUE_AGE: Duration = Duration::from_millis(25);
const UDP_BUFFER_REQUEST: usize = 1024 * 1024;
const MAX_PENDING_UDP_PACKETS: usize = 32;
const MAX_PENDING_UDP_BYTES: usize = 32 * 1024;
const MAX_PENDING_UDP_AGE: Duration = Duration::from_millis(5);
const UDP_RETRY_INTERVAL: Duration = Duration::from_micros(250);
const MAX_SEND_INTERRUPTS: usize = 4;
const MAX_IO_BATCH: usize = 64;
// Wintun can also receive IPv6 packets and rejects reads into short buffers.
// Keep enough space to read and discard packets outside the configured IPv4 MTU.
#[cfg(windows)]
const TUN_READ_BUFFER_SIZE: usize = u16::MAX as usize;
#[cfg(unix)]
const TUN_READ_BUFFER_SIZE: usize = 2048;
#[cfg(windows)]
static CLIENT_INTERRUPTED: AtomicBool = AtomicBool::new(false);
const VP8_PREFIX_LEN: usize = 17;
const RTP_ADMISSION_OVERHEAD: usize = VP8_PREFIX_LEN + HEADER + 81;
const IPV4_UDP_OVERHEAD: usize = 20 + 8;
const CAMERA_MAX_SLOT_SLIP: Duration = Duration::from_millis(1);
const CAMERA_IPV4_BYTES_PER_SLOT: u64 = 240_000 / 8 / 30;
const CAMERA_SIZE_PHASE_BYTES: i64 = 48;
#[cfg(target_os = "linux")]
const CAMERA_MAX_IPV4_BYTES_PER_SLOT: u64 =
    CAMERA_IPV4_BYTES_PER_SLOT + (2 * CAMERA_SIZE_PHASE_BYTES) as u64;
const CAMERA_COVER_IP_RESERVE: usize = 3
    * (DEFAULT_MTU as usize + 2 * RTP_ADMISSION_OVERHEAD + MAX_WIDE_PADDING)
    + RTP_ADMISSION_OVERHEAD
    + FRAME_END_MAX_PAYLOAD;
const WIRE_FILL_RESERVE: usize =
    DEFAULT_MTU as usize + 3 * RTP_ADMISSION_OVERHEAD + FRAME_END_MAX_PAYLOAD;
const VP8_PREFIX: [u8; VP8_PREFIX_LEN] = {
    let ivf = include_bytes!("../fixtures/cover-vp8.ivf");
    let mut prefix = [0; VP8_PREFIX_LEN];
    prefix[0] = 0x10;
    let mut i = 1;
    // IVF has a 32-byte file header and 12-byte first frame header.
    while i < VP8_PREFIX_LEN {
        prefix[i] = ivf[43 + i];
        i += 1;
    }
    prefix
};

#[derive(Clone, Copy)]
pub struct TunnelConfig {
    pub local_ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
    pub mtu: u16,
    pub max_mbps: f64,
    pub congestion: CongestionMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CongestionMode {
    NativeTwcc,
    ArrivalFeedback,
    /// Pace the encrypted carrier up to the configured ceiling. The inner
    /// transport responds to packet loss, with no outer padding or retries.
    IpTunnel,
}

impl CongestionMode {
    fn name(self) -> &'static str {
        match self {
            Self::NativeTwcc => "str0m-twcc",
            Self::ArrivalFeedback => "sfera-arrival-feedback",
            Self::IpTunnel => "ip-tunnel",
        }
    }
}

impl TunnelConfig {
    fn uses_adaptive_pacing(self) -> bool {
        self.congestion == CongestionMode::IpTunnel && self.max_mbps == UNLIMITED_MBPS
    }

    fn validate(self) -> Result<()> {
        let local = u32::from(self.local_ip);
        let peer = u32::from(self.peer_ip);
        ensure!(
            self.local_ip.is_private()
                && self.peer_ip.is_private()
                && local & !3 == peer & !3
                && local != peer
                && matches!(local & 3, 1 | 2)
                && matches!(peer & 3, 1 | 2),
            "TUN addresses must be distinct private hosts in the same /30"
        );
        ensure!(
            (576..=DEFAULT_MTU).contains(&self.mtu),
            "TUN MTU must be 576..={DEFAULT_MTU}"
        );
        ensure!(
            (0.05..=1_000.0).contains(&self.max_mbps)
                || (self.congestion == CongestionMode::IpTunnel && self.max_mbps == UNLIMITED_MBPS),
            "max-mbps must be 0.05..=1000"
        );
        Ok(())
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    fn make_device(self, server: bool) -> Result<SyncDevice> {
        self.make_named_device(server, None)
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    fn make_named_device(self, server: bool, name: Option<&str>) -> Result<SyncDevice> {
        // On Windows a destination would install a default route immediately.
        #[cfg(any(target_os = "linux", windows))]
        let destination = None;
        #[cfg(not(any(target_os = "linux", windows)))]
        let destination = Some(self.peer_ip);
        let builder = DeviceBuilder::new()
            .ipv4(self.local_ip, 30, destination)
            .mtu(self.mtu)
            .enable(true);
        #[cfg(unix)]
        let builder = builder.packet_information(false);
        #[cfg(windows)]
        let builder = {
            let dll = std::env::current_exe()?.with_file_name("wintun.dll");
            ensure!(dll.is_file(), "place wintun.dll next to sfera-net.exe");
            builder
                .name(format!("SFERA Test {}", std::process::id()))
                .wintun_file(dll.to_str().context("invalid Wintun DLL path")?.to_owned())
        };
        // On macOS the kernel already installs the point-to-point peer route;
        // the external client helper owns all wider route and DNS changes.
        #[cfg(target_os = "macos")]
        let builder = builder.associate_route(false);
        #[cfg(target_os = "linux")]
        let builder = {
            let builder = builder.tx_queue_len(256);
            if server {
                builder.name(name.unwrap_or("sfera0"))
            } else {
                builder
            }
        };
        #[cfg(not(target_os = "linux"))]
        let _ = (server, name);
        let device = builder
            .build_sync()
            .context("create and configure TUN interface")?;
        #[cfg(unix)]
        device.set_nonblocking(true)?;
        Ok(device)
    }
}

#[derive(Clone, Copy)]
enum Role {
    Client,
    Server,
}

impl Role {
    fn valid_packet(self, config: TunnelConfig, packet: &[u8], incoming: bool) -> bool {
        let Some((source, destination)) = ipv4_addresses(packet, config.mtu) else {
            return false;
        };
        match (self, incoming) {
            (Self::Client, false) => source == config.local_ip,
            (Self::Client, true) => destination == config.local_ip,
            (Self::Server, false) => destination == config.peer_ip,
            (Self::Server, true) => source == config.peer_ip,
        }
    }
}

fn ipv4_addresses(packet: &[u8], mtu: u16) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (total, source, destination) = ipv4_header(packet, mtu)?;
    (total == packet.len()).then_some((source, destination))
}

fn ipv4_header(packet: &[u8], mtu: u16) -> Option<(usize, Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header < 20
        || header > total
        || header > packet.len()
        || total > usize::from(mtu)
        || packet[8] == 0
        || packet[6] & 0x80 != 0
    {
        return None;
    }
    Some((
        total,
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    ))
}

struct PartialPacket {
    sequence: u32,
    created: Instant,
    first: Option<Vec<u8>>,
    second: Option<Vec<u8>>,
}

#[derive(Default)]
struct Reassembly(VecDeque<PartialPacket>);

impl Reassembly {
    fn expire(&mut self, now: Instant) -> u64 {
        let mut dropped = 0;
        while self
            .0
            .front()
            .is_some_and(|part| now.saturating_duration_since(part.created) >= REASSEMBLY_AGE)
        {
            self.0.pop_front();
            dropped += 1;
        }
        dropped
    }

    fn push(
        &mut self,
        sequence: u32,
        payload: &[u8],
        mtu: u16,
        now: Instant,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let (&index, data) = payload.split_first().context("empty tunnel fragment")?;
        let max_tail = usize::from(mtu).saturating_sub(FIRST_FRAGMENT_BYTES);
        ensure!(max_tail > 1, "fragment for a single-packet MTU");
        match index {
            0 => ensure!(
                data.len() == FIRST_FRAGMENT_BYTES
                    && ipv4_header(data, mtu).is_some_and(|(total, _, _)| total > MAX_DATA),
                "invalid first fragment"
            ),
            1 => ensure!(
                (2..=max_tail).contains(&data.len()),
                "invalid second fragment"
            ),
            _ => bail!("unknown fragment index"),
        }
        let mut dropped = self.expire(now);
        let index_in_queue =
            if let Some(i) = self.0.iter().position(|part| part.sequence == sequence) {
                i
            } else {
                if self.0.len() == MAX_REASSEMBLIES {
                    self.0.pop_front();
                    dropped += 1;
                }
                self.0.push_back(PartialPacket {
                    sequence,
                    created: now,
                    first: None,
                    second: None,
                });
                self.0.len() - 1
            };
        let part = &mut self.0[index_in_queue];
        let slot = if index == 0 {
            &mut part.first
        } else {
            &mut part.second
        };
        if slot.is_some() {
            return Ok((None, dropped));
        }
        *slot = Some(data.to_vec());
        if part.first.is_none() || part.second.is_none() {
            return Ok((None, dropped));
        }
        let complete = self
            .0
            .remove(index_in_queue)
            .expect("reassembly entry exists");
        let mut packet = complete.first.expect("first fragment exists");
        packet.extend(complete.second.expect("second fragment exists"));
        // Length and address validation of the complete packet occurs before TUN admission.
        Ok((Some(packet), dropped))
    }
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub fn serve(
    signal: SocketAddr,
    signal_token_file: &Path,
    public_ip: Ipv4Addr,
    udp_port: u16,
    config: TunnelConfig,
) -> Result<()> {
    config.validate()?;
    ensure!(
        signal.ip().is_loopback(),
        "signaling listener must be loopback"
    );
    let public = SocketAddrV4::new(public_ip, udp_port);
    ensure!(
        valid_media_endpoint(public),
        "invalid advertised media endpoint"
    );
    let token = Token::load(signal_token_file)?;
    let listener = signaling::bind_listener(signal).context("bind loopback signaling listener")?;
    let socket =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, udp_port)).context("bind media UDP listener")?;
    socket.set_nonblocking(true)?;
    configure_media_socket_buffers(&socket, UDP_BUFFER_REQUEST);
    let device = config.make_device(true)?;
    let name = device.name()?;
    let signal_address = listener.local_addr()?;
    let replacements = listen_for_peers(listener, token, socket, public, config)?;
    eprintln!("SFERA MEDIA: {name}, signaling {signal_address}, UDP {public}");

    let mut peer = replacements.recv().context("signaling listener stopped")?;
    loop {
        let result = (|| -> Result<Option<Peer>> {
            if let Some(replacement) = peer.wait_connected(Some(&replacements))? {
                return Ok(Some(replacement));
            }
            // A new peer gets only TUN packets queued after it authenticates.
            discard_stale_tun(&device)?;
            eprintln!("SFERA MEDIA: authenticated peer connected on {name}");
            run_device(&device, peer, None, Some(&replacements), None, None)
        })();
        peer = match result {
            Ok(Some(replacement)) => replacement,
            Ok(None) => replacements.recv().context("signaling listener stopped")?,
            Err(error) => {
                eprintln!("SFERA MEDIA: session ended: {error:#}");
                replacements.recv().context("signaling listener stopped")?
            }
        };
    }
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn listen_for_peers(
    listener: TcpListener,
    token: Token,
    socket: UdpSocket,
    public: SocketAddrV4,
    config: TunnelConfig,
) -> Result<Receiver<Peer>> {
    let (send, receive) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("sfera-signaling".into())
        .spawn(move || {
            for accepted in listener.incoming() {
                let stream = match accepted {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => {
                        eprintln!("SFERA MEDIA: accept signaling connection: {error}");
                        return;
                    }
                };
                let peer = signaling::handle(stream, &token, |offer| {
                    answer_offer(offer, &socket, public, config)
                });
                // The HTTP connection has closed. Only the media loop polls UDP.
                if let Some(peer) = peer
                    && send.send(peer).is_err()
                {
                    return;
                }
            }
        })
        .context("start signaling listener")?;
    Ok(receive)
}

fn replacement(replacements: Option<&Receiver<Peer>>) -> Option<Peer> {
    // The signaling thread reports listener failures. The current peer can
    // keep using media until it disconnects, even if no new peer can join.
    replacements.and_then(|receiver| receiver.try_recv().ok())
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub fn connect(
    signal_url: &str,
    signal_token_file: &Path,
    config: TunnelConfig,
    status: Option<&Path>,
) -> Result<()> {
    config.validate()?;
    #[cfg(windows)]
    ctrlc::set_handler(|| CLIENT_INTERRUPTED.store(true, Ordering::Relaxed))
        .context("register Windows Ctrl+C handler")?;
    let signal = Endpoint::parse(signal_url)?;
    // The macOS helper removes the root-owned token file after authentication.
    let token = Token::load(signal_token_file)?;
    let mut peer = dial_endpoint(&signal, &token, config, IpIngress::Handshake, None, None)?;
    #[cfg(windows)]
    if CLIENT_INTERRUPTED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let device = config.make_device(false)?;
    let name = device.name()?;
    eprintln!(
        "SFERA MEDIA: authenticated UDP peer {}, TUN {name}",
        peer.public
    );
    let status = status.map(|path| (path, name.as_str()));
    loop {
        let ticket = peer.session_ticket;
        match run_device(&device, peer, status, None, Some(signal.route_to), None) {
            Err(error) if error.is::<MediaDisconnected>() && ticket.is_some() => {
                eprintln!("SFERA MEDIA: {error:#}; reestablishing media on TUN {name}");
            }
            result => return result.map(|_| ()),
        }
        let Some(reconnected) = reconnect_client(&signal, &token, config, ticket)? else {
            return Ok(());
        };
        discard_stale_tun(&device)?;
        peer = reconnected;
    }
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn reconnect_client(
    signal: &Endpoint,
    token: &Token,
    config: TunnelConfig,
    ticket: Option<SessionTicket>,
) -> Result<Option<Peer>> {
    let mut retry = Duration::from_secs(1);
    loop {
        if client_interrupted() {
            return Ok(None);
        }
        match dial_endpoint(signal, token, config, IpIngress::Handshake, ticket, None) {
            Ok(peer) => return Ok((!client_interrupted()).then_some(peer)),
            Err(error) if error.is::<signaling::SessionReplaced>() => return Err(error),
            Err(error) => eprintln!("SFERA MEDIA: reconnect failed: {error:#}"),
        }
        let deadline = Instant::now() + retry;
        while Instant::now() < deadline && !client_interrupted() {
            thread::sleep(Duration::from_millis(100));
        }
        retry = (retry * 2).min(Duration::from_secs(8));
    }
}

fn client_interrupted() -> bool {
    #[cfg(windows)]
    return CLIENT_INTERRUPTED.load(Ordering::Relaxed);
    #[cfg(not(windows))]
    false
}

#[derive(Debug)]
struct MediaDisconnected(&'static str);

impl std::fmt::Display for MediaDisconnected {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(self.0)
    }
}

impl std::error::Error for MediaDisconnected {}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn discard_stale_tun(tun: &SyncDevice) -> Result<()> {
    let mut buf = [0u8; TUN_READ_BUFFER_SIZE];
    for _ in 0..1024 {
        match recv_tun(tun, &mut buf) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("discard old TUN packets"),
        }
    }
    Ok(())
}

type SessionTicket = [u8; 16];

#[derive(Deserialize, Serialize)]
struct SessionOffer {
    settings: SessionSettings,
    offer: SdpOffer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_feedback: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_ack: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_ack_timing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume_ticket: Option<SessionTicket>,
}

#[derive(Deserialize, Serialize)]
struct SessionAnswer {
    settings: SessionSettings,
    public: SocketAddrV4,
    answer: SdpAnswer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_feedback: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_ack: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delivery_ack_timing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_ticket: Option<SessionTicket>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SessionSettings {
    version: u8,
    congestion: CongestionMode,
    mtu: u16,
    server_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
}

impl SessionSettings {
    fn new(config: TunnelConfig, role: Role) -> Self {
        let (server_ip, client_ip) = match role {
            Role::Server => (config.local_ip, config.peer_ip),
            Role::Client => (config.peer_ip, config.local_ip),
        };
        Self {
            version: if config.congestion == CongestionMode::IpTunnel {
                2
            } else {
                1
            },
            congestion: config.congestion,
            mtu: config.mtu,
            server_ip,
            client_ip,
        }
    }
}

fn answer_offer(
    request: SessionOffer,
    socket: &UdpSocket,
    public: SocketAddrV4,
    config: TunnelConfig,
) -> Result<(SessionAnswer, Peer)> {
    let SessionOffer {
        settings,
        offer,
        delivery_feedback,
        delivery_ack,
        delivery_ack_timing,
        resume_ticket: _,
    } = request;
    let delivery_feedback = delivery::negotiate(
        config.congestion == CongestionMode::IpTunnel,
        delivery_feedback,
    );
    let delivery_ack = delivery_ack.filter(|&version| {
        config.congestion == CongestionMode::IpTunnel && version == delivery::matched::VERSION
    });
    let timed = delivery_ack.is_some()
        && delivery_ack_timing.is_some_and(|requested| requested || config.uses_adaptive_pacing());
    ensure!(
        settings == SessionSettings::new(config, Role::Server),
        "incompatible SFERA session settings"
    );
    let [line] = offer.media_lines.as_slice() else {
        bail!("expected one SDP media line");
    };
    ensure!(
        line.typ.is_media()
            && !line.disabled
            && line.direction() == Direction::SendRecv
            && line.simulcast().is_none()
            && line
                .rtp_params()
                .iter()
                .any(|params| params.spec().codec == Codec::Vp8)
            && offer
                .session
                .ice_candidates()
                .chain(line.ice_candidates())
                .any(|candidate| candidate.proto() == Protocol::Udp && candidate.addr().is_ipv4()),
        "SDP offer does not describe bidirectional VP8 over IPv4 UDP"
    );
    let mut peer = Peer::new(socket.try_clone()?, public, public, Role::Server, config)?;
    peer.delivery = delivery_feedback.map(|_| delivery::Observer::default());
    if delivery_ack.is_some() {
        peer.enable_matched_delivery(timed);
    }
    // Match str0m's session-first setup lookup. This is a fresh Peer; legacy
    // active/passive/missing setup retains the library's ordinary handling.
    let actpass = offer
        .session
        .setup()
        .or_else(|| offer.media_lines.iter().find_map(|line| line.setup()))
        .is_some_and(|setup| setup.setup_line() == "actpass");
    if actpass {
        let mut direct = peer.rtc.direct_api();
        direct.set_ice_lite(true);
        // accept_offer skips its ICE-role initialization after DTLS is started.
        // Public ICE-lite must remain controlled; the viewer opens the NAT tuple.
        direct.set_ice_controlling(false);
        direct
            .start_dtls(true)
            .context("initialize active DTLS answer")?;
    }
    let answer = peer
        .rtc
        .sdp_api()
        .accept_offer(offer)
        .context("accept SDP offer")?;
    ensure!(
        answer
            .media_lines
            .first()
            .and_then(|line| peer.rtc.media(line.mid()))
            .is_some_and(|media| media.kind() == MediaKind::Video),
        "unexpected SDP media"
    );
    peer.drain()?;
    Ok((
        SessionAnswer {
            settings,
            public,
            answer,
            delivery_feedback,
            delivery_ack,
            delivery_ack_timing: timed.then_some(true),
            session_ticket: None,
        },
        peer,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IceStartup {
    Direct,
    BindingIndication,
}

fn dial_peer(
    signal_url: &str,
    signal_token_file: &Path,
    config: TunnelConfig,
    ingress: IpIngress,
) -> Result<Peer> {
    let signal = Endpoint::parse(signal_url)?;
    let token = Token::load(signal_token_file)?;
    dial_endpoint(&signal, &token, config, ingress, None, None)
}

fn dial_endpoint(
    signal: &Endpoint,
    token: &Token,
    config: TunnelConfig,
    ingress: IpIngress,
    resume_ticket: Option<SessionTicket>,
    stop: Option<&AtomicBool>,
) -> Result<Peer> {
    let dial = |startup| {
        ensure!(
            !stop.is_some_and(|flag| flag.load(Ordering::Relaxed)),
            "media startup interrupted"
        );
        negotiate_client(signal.route_to, config, startup, |mut offer| {
            offer.resume_ticket = resume_ticket;
            signal.exchange(token, &offer)
        })
    };
    let mut peer = dial(IceStartup::Direct)?;
    peer.ip_ingress = ingress;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    if peer.adaptive_mtu() && !peer.wait_for_ice_nomination(stop)? {
        #[cfg(windows)]
        ensure!(
            !CLIENT_INTERRUPTED.load(Ordering::Relaxed),
            "media startup interrupted"
        );
        eprintln!("SFERA MEDIA: no nominated ICE pair, retrying on a fresh UDP socket");
        let mut retry = dial(IceStartup::BindingIndication).context("retry media signaling")?;
        // Keep the previous socket bound until the new port has been assigned.
        drop(peer);
        retry.ip_ingress = ingress;
        retry
            .wait_connected_until(None, Instant::now() + HANDSHAKE_TIMEOUT, stop)
            .context("retry media handshake")?;
        return Ok(retry);
    }
    peer.wait_connected_until(None, deadline, stop)?;
    Ok(peer)
}

fn negotiate_client(
    route_to: SocketAddrV4,
    config: TunnelConfig,
    startup: IceStartup,
    exchange: impl FnOnce(SessionOffer) -> Result<SessionAnswer>,
) -> Result<Peer> {
    // An unconnected media socket can advertise the underlay source address
    // before the HTTPS response supplies its UDP destination.
    let route_source = underlay_source(route_to).context("select IPv4 underlay route")?;
    ensure!(
        route_source != config.local_ip,
        "server route points into SFERA TUN"
    );
    let socket = UdpSocket::bind((route_source, 0))?;
    socket.set_nonblocking(true)?;
    configure_media_socket_buffers(&socket, UDP_BUFFER_REQUEST);
    let SocketAddr::V4(local) = socket.local_addr()? else {
        bail!("no IPv4 media socket");
    };
    let mut peer = Peer::new(socket, local, route_to, Role::Client, config)?;
    let mut change = peer.rtc.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().context("make SDP offer")?;
    peer.mid = Some(mid);
    peer.drain()?;
    let expected_settings = SessionSettings::new(config, Role::Client);
    let requested_delivery = delivery::negotiate(
        config.congestion == CongestionMode::IpTunnel,
        Some(delivery::VERSION),
    );
    let requested_ack =
        (config.congestion == CongestionMode::IpTunnel).then_some(delivery::matched::VERSION);
    let SessionAnswer {
        settings,
        public,
        answer,
        delivery_feedback,
        delivery_ack,
        delivery_ack_timing,
        session_ticket,
    } = exchange(SessionOffer {
        settings: expected_settings,
        offer,
        delivery_feedback: requested_delivery,
        delivery_ack: requested_ack,
        delivery_ack_timing: requested_ack.map(|_| config.uses_adaptive_pacing()),
        resume_ticket: None,
    })?;
    ensure!(
        settings == expected_settings,
        "incompatible SFERA session settings"
    );
    ensure!(valid_media_endpoint(public), "invalid media endpoint");
    ensure!(
        answer
            .session
            .ice_candidates()
            .chain(
                answer
                    .media_lines
                    .iter()
                    .flat_map(|line| line.ice_candidates())
            )
            .any(|candidate| candidate.proto() == Protocol::Udp
                && candidate.addr() == SocketAddr::V4(public)),
        "SDP answer does not advertise the returned UDP endpoint"
    );
    peer.socket
        .connect(public)
        .context("connect underlay media socket")?;
    peer.public = public;
    peer.session_ticket = session_ticket;
    if delivery_feedback == requested_delivery && delivery_feedback.is_some() {
        peer.delivery = Some(delivery::Observer::default());
    }
    if delivery_ack == requested_ack && delivery_ack.is_some() {
        peer.enable_matched_delivery(delivery_ack_timing == Some(true));
    }
    if startup == IceStartup::BindingIndication {
        peer.send_binding_indication()?;
    }
    peer.rtc
        .sdp_api()
        .accept_answer(pending, answer)
        .context("accept SDP answer")?;
    peer.drain()?;
    Ok(peer)
}

fn underlay_source(endpoint: SocketAddrV4) -> io::Result<Ipv4Addr> {
    // UDP connect selects a local address without transmitting a packet.
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(endpoint)?;
    match socket.local_addr()? {
        SocketAddr::V4(address) => Ok(*address.ip()),
        SocketAddr::V6(_) => Err(io::Error::new(ErrorKind::AddrNotAvailable, "no IPv4 route")),
    }
}

#[derive(Default, Serialize)]
struct Stats {
    tun_tx_packets: u64,
    tun_tx_bytes: u64,
    tun_rx_packets: u64,
    tun_rx_bytes: u64,
    tun_stage_peak_packets: usize,
    tun_stage_full_visits: u64,
    udp_tx_bytes: u64,
    udp_tx_ipv4_bytes: u64,
    udp_rx_bytes: u64,
    udp_recv_buffer_bytes: usize,
    udp_send_buffer_bytes: usize,
    udp_send_would_block: u64,
    udp_send_no_buffer: u64,
    udp_send_interruptions: u64,
    udp_pending_sent: u64,
    udp_pending_peak_packets: usize,
    udp_pending_peak_bytes: usize,
    rtp_tx_packets: u64,
    rtp_tx_ipv4_bytes: u64,
    rtp_rx_candidates: u64,
    rtp_rx_authenticated: u64,
    #[serde(skip_serializing_if = "is_zero")]
    delivery_reports_generated: u64,
    #[serde(skip_serializing_if = "is_zero")]
    delivery_report_samples: u64,
    #[serde(skip_serializing_if = "is_zero")]
    delivery_arrived_ipv4_kbps: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_report_age_ms: Option<u64>,
    #[serde(skip_serializing_if = "is_zero")]
    delivery_ack_reports_generated: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_matched_sample: Option<delivery::matched::Sample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery_matched_age_ms: Option<u64>,
    #[serde(skip)]
    delivery_matched_at: Option<Instant>,
    #[serde(skip)]
    delivery_sender: Option<Box<delivery::matched::Sender>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adaptive_pacing_mbps: Option<f64>,
    #[serde(skip_serializing_if = "is_zero")]
    adaptive_pacing_updates: u64,
    #[serde(skip)]
    delivery_tx_ssrc: Option<u32>,
    rtp_rx_invalid_frame: u64,
    rtp_tx_markers: u64,
    rtp_padding_tx_bytes: u64,
    mtu_probes_sent: u64,
    mtu_probes_acked: u64,
    camera_cover_packets: u64,
    camera_cover_udp_bytes: u64,
    camera_cover_skipped: u64,
    camera_cover_send_failures: u64,
    repair_requests_sent: u64,
    #[serde(skip_serializing_if = "is_zero")]
    repair_feedback_copies_sent: u64,
    repair_packets_sent: u64,
    repair_packets_received: u64,
    repair_duplicate_or_late: u64,
    drops: DropStats,
}

impl Stats {
    fn record_udp_send(&mut self, bytes: &[u8]) {
        self.udp_tx_bytes += bytes.len() as u64;
        self.udp_tx_ipv4_bytes += (bytes.len() + IPV4_UDP_OVERHEAD) as u64;
        if let Some((sequence, ssrc, padding)) = rtp_header(bytes) {
            self.rtp_tx_packets += 1;
            self.rtp_tx_ipv4_bytes += (bytes.len() + IPV4_UDP_OVERHEAD) as u64;
            if !padding
                && sequence % 16 == 0
                && self.delivery_tx_ssrc == Some(ssrc)
                && let Some(sender) = &mut self.delivery_sender
            {
                sender.record(sequence, bytes.len() + IPV4_UDP_OVERHEAD, Instant::now());
            }
            self.rtp_tx_markers += u64::from(bytes[1] & 0x80 != 0);
            if padding {
                self.rtp_padding_tx_bytes += bytes.len() as u64;
            }
        }
    }
}

#[derive(Default, Serialize)]
struct DropStats {
    udp_pending_expired: u64,
    udp_pending_full: u64,
    udp_pending_shutdown: u64,
    udp_message_too_large: u64,
    incoming_queue_full: u64,
    incoming_queue_expired: u64,
    #[serde(skip_serializing_if = "is_zero")]
    outgoing_queue_full: u64,
    outgoing_queue_expired: u64,
    invalid_incoming_ip: u64,
    invalid_outgoing_ip: u64,
    invalid_fragment: u64,
    incomplete_fragment: u64,
    invalid_feedback: u64,
}

impl DropStats {
    fn total(&self) -> u64 {
        self.udp_pending_expired
            + self.udp_pending_full
            + self.udp_pending_shutdown
            + self.udp_message_too_large
            + self.incoming_queue_full
            + self.incoming_queue_expired
            + self.outgoing_queue_full
            + self.outgoing_queue_expired
            + self.invalid_incoming_ip
            + self.invalid_outgoing_ip
            + self.invalid_fragment
            + self.incomplete_fragment
            + self.invalid_feedback
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Default)]
struct UdpEgress {
    // A blocked socket must not make later datagrams overtake the first one.
    pending: VecDeque<(Instant, Transmit)>,
    bytes: usize,
    next_retry: Option<Instant>,
}

#[derive(PartialEq, Eq)]
enum UdpSend {
    Sent,
    Blocked,
    TooLarge,
}

impl UdpEgress {
    fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    fn send_cover(
        &self,
        packet: &Transmit,
        stats: &mut Stats,
        send: impl FnOnce(&Transmit) -> io::Result<usize>,
    ) -> bool {
        if self.is_pending() {
            stats.camera_cover_skipped += 1;
            return false;
        }
        // Cover never enters the retry queue or changes the active path MTU.
        if send(packet).is_ok_and(|n| n == packet.contents.len()) {
            stats.record_udp_send(&packet.contents);
            stats.camera_cover_packets += 1;
            stats.camera_cover_udp_bytes += packet.contents.len() as u64;
            true
        } else {
            stats.camera_cover_send_failures += 1;
            false
        }
    }

    fn submit(
        &mut self,
        now: Instant,
        packet: Transmit,
        stats: &mut Stats,
        mut send: impl FnMut(&Transmit) -> io::Result<usize>,
    ) -> Result<()> {
        self.expire(now, stats);
        if !self.is_pending() {
            if Self::try_send(&packet, stats, &mut send)? != UdpSend::Blocked {
                return Ok(());
            }
            self.next_retry = Some(now + UDP_RETRY_INTERVAL);
        }
        if self.pending.len() >= MAX_PENDING_UDP_PACKETS
            || self.bytes.saturating_add(packet.contents.len()) > MAX_PENDING_UDP_BYTES
        {
            stats.drops.udp_pending_full += 1;
            return Ok(());
        }
        self.bytes += packet.contents.len();
        self.pending.push_back((now, packet));
        stats.udp_pending_peak_packets = stats.udp_pending_peak_packets.max(self.pending.len());
        stats.udp_pending_peak_bytes = stats.udp_pending_peak_bytes.max(self.bytes);
        Ok(())
    }

    fn flush(
        &mut self,
        now: Instant,
        stats: &mut Stats,
        mut send: impl FnMut(&Transmit) -> io::Result<usize>,
    ) -> Result<bool> {
        self.expire(now, stats);
        if self.next_retry.is_some_and(|retry| now < retry) {
            return Ok(false);
        }
        self.next_retry = None;
        let mut sent = false;
        while let Some((_, packet)) = self.pending.front() {
            match Self::try_send(packet, stats, &mut send)? {
                UdpSend::Blocked => {
                    self.next_retry = Some(now + UDP_RETRY_INTERVAL);
                    break;
                }
                UdpSend::Sent => stats.udp_pending_sent += 1,
                UdpSend::TooLarge => {}
            }
            self.remove_head();
            sent = true;
        }
        Ok(sent)
    }

    fn expire(&mut self, now: Instant, stats: &mut Stats) {
        while self.pending.front().is_some_and(|(queued, _)| {
            now.saturating_duration_since(*queued) >= MAX_PENDING_UDP_AGE
        }) {
            self.remove_head();
            stats.drops.udp_pending_expired += 1;
        }
    }

    fn remove_head(&mut self) {
        if let Some((_, packet)) = self.pending.pop_front() {
            self.bytes -= packet.contents.len();
        }
    }

    fn try_send(
        packet: &Transmit,
        stats: &mut Stats,
        send: &mut impl FnMut(&Transmit) -> io::Result<usize>,
    ) -> Result<UdpSend> {
        for _ in 0..MAX_SEND_INTERRUPTS {
            match send(packet) {
                Ok(n) if n == packet.contents.len() => {
                    stats.record_udp_send(&packet.contents);
                    return Ok(UdpSend::Sent);
                }
                Ok(_) => bail!("partial media UDP send"),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    stats.udp_send_would_block += 1;
                    return Ok(UdpSend::Blocked);
                }
                #[cfg(unix)]
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    stats.udp_send_no_buffer += 1;
                    return Ok(UdpSend::Blocked);
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {
                    stats.udp_send_interruptions += 1;
                }
                Err(error) if is_message_too_large(&error) => {
                    stats.drops.udp_message_too_large += 1;
                    return Ok(UdpSend::TooLarge);
                }
                Err(error) => return Err(error).context("write media UDP socket"),
            }
        }
        // Keep the same packet for another event-loop turn if signals continue.
        Ok(UdpSend::Blocked)
    }
}

struct ArrivalFeedback {
    controller: Controller,
    received_bytes: u64,
    received_packets: u64,
    last_sequence: u16,
    last_arrival: Duration,
    reported_packets: u64,
    serial: u32,
    next_report: Instant,
}

impl ArrivalFeedback {
    fn new(initial_mbps: f64, desired_mbps: f64, now: Instant) -> Result<Self> {
        Ok(Self {
            controller: Controller::new(initial_mbps, desired_mbps)?,
            received_bytes: 0,
            received_packets: 0,
            last_sequence: 0,
            last_arrival: Duration::ZERO,
            reported_packets: 0,
            serial: 0,
            next_report: now,
        })
    }

    fn record_arrival(&mut self, sequence: u16, at: Duration, bytes: usize) {
        let advance = sequence.wrapping_sub(self.last_sequence);
        if self.received_packets == 0 || (advance > 0 && advance < 32768) {
            self.last_sequence = sequence;
            self.last_arrival = at;
        }
        self.received_packets += 1;
        self.received_bytes += bytes as u64;
    }

    fn due(&self, now: Instant) -> bool {
        now >= self.next_report && self.received_packets > self.reported_packets
    }

    fn report(&mut self, now: Instant, bitrate_mbps: f64) -> Frame {
        self.serial = next_serial(self.serial);
        self.reported_packets = self.received_packets;
        let interval_ms = if bitrate_mbps > 1.0 { 20 } else { 100 };
        self.next_report = now + Duration::from_millis(interval_ms);
        let report = ArrivalReport {
            serial: self.serial,
            received_bytes: self.received_bytes,
            received_packets: self.received_packets,
            last_sequence: self.last_sequence,
            arrival_ns: self.last_arrival.as_nanos().min(u64::MAX as u128) as u64,
        };
        Frame {
            kind: Kind::Datagram,
            flow: ARRIVAL_FLOW,
            sequence: report.serial,
            payload: report.encode(),
        }
    }
}

struct ProbeCheck {
    until: Instant,
    sent: u32,
    replies_ms: Vec<f64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IpIngress {
    Handshake,
    Tun,
    ControlOnly,
}

struct GroupedFrame {
    timestamp: u32,
    frame_end: Instant,
}

struct CameraCover {
    next_frame: Instant,
    previous_ipv4_bytes: u64,
    packet_overhead: usize,
    slot: u64,
    size_key: RandomState,
    size_phase: i64,
}

impl CameraCover {
    fn new(now: Instant, ipv4_bytes: u64) -> Self {
        Self {
            next_frame: now + RTP_FRAME_SPAN,
            previous_ipv4_bytes: ipv4_bytes,
            packet_overhead: RTP_ADMISSION_OVERHEAD,
            slot: 0,
            size_key: RandomState::new(),
            size_phase: 0,
        }
    }

    fn take_slot(&mut self, now: Instant, ipv4_bytes: u64) -> Option<usize> {
        if now < self.next_frame {
            return None;
        }
        // Keep the nominal phase when the wakeup is prompt and avoid a short
        // gap between packets after a late wakeup.
        self.next_frame =
            (self.next_frame + RTP_FRAME_SPAN).max(now + RTP_FRAME_SPAN - CAMERA_MAX_SLOT_SLIP);
        let wire_bytes = ipv4_bytes.saturating_sub(self.previous_ipv4_bytes);
        self.previous_ipv4_bytes = ipv4_bytes;
        // Vary frame size while bounding accumulated deviation over every
        // window. Only the two endpoint phases contribute to the difference.
        let span = (2 * CAMERA_SIZE_PHASE_BYTES + 1) as u64;
        let phase = (self.size_key.hash_one(self.slot) % span) as i64 - CAMERA_SIZE_PHASE_BYTES;
        self.slot = self.slot.wrapping_add(1);
        let target = CAMERA_IPV4_BYTES_PER_SLOT.saturating_add_signed(phase - self.size_phase);
        self.size_phase = phase;
        let bytes = target.saturating_sub(wire_bytes.saturating_add(self.packet_overhead as u64));
        Some((bytes as usize).min(MAX_DATA))
    }

    fn observe_cover(&mut self, udp_payload_bytes: usize, cover_payload_bytes: usize) {
        self.packet_overhead =
            (udp_payload_bytes + IPV4_UDP_OVERHEAD).saturating_sub(cover_payload_bytes);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RtpDelivery {
    Ordinary,
    Sample,
    Cover { payload_bytes: usize },
}

const FEEDBACK_COPY_DELAY: Duration = Duration::from_millis(64);
const FEEDBACK_COPY_GRACE: Duration = Duration::from_millis(24);
const MAX_FEEDBACK_COPIES: usize = 8;
const SHORT_REPAIR_RTT_MAX_AGE: Duration = Duration::from_secs(3);

struct FeedbackCopy {
    due: Instant,
    sequence: u32,
    payload: [u8; repair::Request::ENCODED_LEN],
}

struct RepairState {
    tx: repair::Sender,
    rx: repair::Receiver,
    feedback: Option<(Instant, repair::Request)>,
    feedback_seq: u32,
    feedback_copies: VecDeque<FeedbackCopy>,
    credit: f64,
    updated: Instant,
    credited_wire_bytes: u64,
}

impl RepairState {
    fn new(now: Instant) -> Self {
        Self {
            tx: repair::Sender::default(),
            rx: repair::Receiver::default(),
            feedback: None,
            feedback_seq: 0,
            feedback_copies: VecDeque::new(),
            credit: 0.0,
            updated: now,
            credited_wire_bytes: 0,
        }
    }

    fn refresh(
        &mut self,
        now: Instant,
        bitrate: f64,
        role: Role,
        rtt: Option<(Duration, Instant)>,
    ) {
        let share = Self::share(role, now, rtt);
        let repair_bytes_per_second = bitrate * 125_000.0 * share;
        let burst = (repair_bytes_per_second * 0.04).clamp(2_048.0, 64_000.0);
        self.credit = (self.credit
            + now.duration_since(self.updated).as_secs_f64() * repair_bytes_per_second)
            .min(burst);
        self.updated = now;
    }
    fn refresh_from_wire(
        &mut self,
        sent: u64,
        now: Instant,
        role: Role,
        rtt: Option<(Duration, Instant)>,
    ) {
        // Repairs keep a separate budget earned by actual sends; data admission stays unlimited.
        if self.credited_wire_bytes == 0 {
            self.credit = self.credit.max(2_048.0);
        }
        let bytes = sent.saturating_sub(self.credited_wire_bytes);
        self.credited_wire_bytes = sent;
        self.credit = (self.credit + bytes as f64 * Self::share(role, now, rtt)).min(64_000.0);
    }

    fn share(role: Role, now: Instant, rtt: Option<(Duration, Instant)>) -> f64 {
        let fresh_rtt = rtt
            .filter(|&(_, at)| now.saturating_duration_since(at) < SHORT_REPAIR_RTT_MAX_AGE)
            .map(|(rtt, _)| rtt);
        if matches!(role, Role::Client)
            && (repair::short_rtt(fresh_rtt) || repair::extended_rtt(fresh_rtt).is_some())
        {
            0.225
        } else {
            0.15
        }
    }
}

struct Peer {
    rtc: Rtc,
    socket: UdpSocket,
    udp_egress: UdpEgress,
    role: Role,
    config: TunnelConfig,
    path_mtu: PathMtu,
    mtu_probe_seq: u32,
    mtu_echo: Option<u32>,
    next_mtu_echo: Instant,
    local: SocketAddrV4,
    public: SocketAddrV4,
    mid: Option<Mid>,
    start: Instant,
    deadline: Instant,
    ice_nominated: bool,
    rtp_seq: u64,
    rtp_timestamp_origin: u32,
    last_rtp_clock: u64,
    rtp_lengths: RandomState,
    grouped_frame: Option<GroupedFrame>,
    camera_cover: Option<CameraCover>,
    tx_ssrc: Option<u32>,
    native_pending: VecDeque<(u16, RtpDelivery)>,
    #[cfg(test)]
    drop_rtp_once: Option<u16>,
    #[cfg(test)]
    drop_rtp_flow_once: Option<u32>,
    arrival: Option<ArrivalFeedback>,
    rx_datagram: Option<(u16, u32, usize, bool)>,
    delivery: Option<delivery::Observer>,
    delivery_receiver: Option<Box<delivery::matched::Receiver>>,
    delivery_timed: bool,
    session_ticket: Option<SessionTicket>,
    delivery_rx_ssrc: Option<u32>,
    delivery_payload_pending: bool,
    data_seq: u32,
    last_ip_frame: u32,
    repair: Option<RepairState>,
    probe_seq: u32,
    probes: VecDeque<(u32, Instant)>,
    check: Option<ProbeCheck>,
    next_probe: Instant,
    next_echo: Instant,
    echo: Option<u32>,
    last_echo: Option<Instant>,
    rtt: Option<Duration>,
    bitrate_mbps: f64,
    adaptive_pacing: Option<pacing::Pacing>,
    bwe_can_probe: bool,
    pacer_bytes: f64,
    pacer_wire_bytes: u64,
    pacer_at: Instant,
    ip_ingress: IpIngress,
    incoming: VecDeque<(Instant, Vec<u8>)>,
    reassembly: Reassembly,
    stats: Stats,
}

impl Peer {
    fn send_binding_indication(&mut self) -> Result<()> {
        let mut bytes = [0; 64];
        let hmac = str0m::crypto::from_feature_flags().sha1_hmac_provider;
        let size = StunMessageBuilder::new()
            .binding()
            .indication()
            .build(TransId::new())
            .to_bytes(None, &mut bytes, |key, payload| {
                hmac.sha1_hmac(key, payload)
            })
            .context("encode STUN Binding Indication")?;
        let packet = Transmit {
            proto: Protocol::Udp,
            source: self.local.into(),
            destination: self.public.into(),
            contents: bytes[..size].to_vec().into(),
        };
        let retry_until = Instant::now() + MAX_PENDING_UDP_AGE;
        loop {
            let outcome = UdpEgress::try_send(&packet, &mut self.stats, &mut |packet| {
                self.socket.send(&packet.contents)
            })
            .context("send STUN Binding Indication")?;
            match outcome {
                UdpSend::Sent => break,
                UdpSend::Blocked if Instant::now() < retry_until => {
                    thread::sleep(UDP_RETRY_INTERVAL);
                }
                UdpSend::Blocked => bail!("STUN Binding Indication write timed out"),
                UdpSend::TooLarge => bail!("STUN Binding Indication too large"),
            }
        }
        thread::sleep(BINDING_INDICATION_DELAY);
        Ok(())
    }

    fn new(
        socket: UdpSocket,
        local: SocketAddrV4,
        public: SocketAddrV4,
        role: Role,
        config: TunnelConfig,
    ) -> Result<Self> {
        let start = Instant::now();
        let initial = match config.congestion {
            CongestionMode::NativeTwcc | CongestionMode::ArrivalFeedback => {
                INITIAL_MBPS.min(config.max_mbps)
            }
            CongestionMode::IpTunnel => config.max_mbps,
        };
        let native = config.congestion == CongestionMode::NativeTwcc;
        let adaptive = config.congestion == CongestionMode::IpTunnel;
        let df = adaptive
            && enable_dont_fragment(&socket).unwrap_or_else(|error| {
                eprintln!("SFERA MEDIA: unable to set IPv4 DF, using base packet size: {error}");
                false
            });
        let mut rtp_origin = [0; 6];
        getrandom::fill(&mut rtp_origin)
            .map_err(|error| anyhow::anyhow!("generate RTP origin: {error}"))?;
        let mut rtc = Rtc::builder()
            .clear_codecs()
            .enable_vp8(true)
            .set_rtp_mode(true)
            .set_ice_lite(matches!(role, Role::Server))
            .set_fingerprint_verification(true)
            .set_dtls_version(if adaptive {
                DtlsVersion::Dtls13
            } else {
                DtlsVersion::Dtls12
            })
            .enable_bwe(native.then(|| Bitrate::from(initial * 1_000_000.0)))
            .build(start);
        if native {
            rtc.bwe()
                .set_bitrate(Bitrate::ZERO, Bitrate::from(config.max_mbps * 1_000_000.0));
        }
        ensure!(
            rtc.add_local_candidate(Candidate::host(local.into(), "udp")?)
                .is_some(),
            "local ICE candidate rejected"
        );
        let stats = media_socket_stats(&socket)?;
        let mut peer = Self {
            rtc,
            socket,
            udp_egress: UdpEgress::default(),
            role,
            config,
            path_mtu: PathMtu::new(start, df),
            mtu_probe_seq: 0,
            mtu_echo: None,
            next_mtu_echo: start,
            local,
            public,
            mid: None,
            start,
            deadline: start,
            ice_nominated: false,
            rtp_seq: u64::from(u16::from_ne_bytes([rtp_origin[0], rtp_origin[1]])),
            rtp_timestamp_origin: u32::from_ne_bytes(rtp_origin[2..].try_into()?),
            last_rtp_clock: 0,
            rtp_lengths: RandomState::new(),
            grouped_frame: None,
            camera_cover: None,
            tx_ssrc: None,
            native_pending: VecDeque::new(),
            #[cfg(test)]
            drop_rtp_once: None,
            #[cfg(test)]
            drop_rtp_flow_once: None,
            arrival: (config.congestion == CongestionMode::ArrivalFeedback)
                .then(|| ArrivalFeedback::new(initial, config.max_mbps, start))
                .transpose()?,
            rx_datagram: None,
            delivery: None,
            delivery_receiver: None,
            delivery_timed: false,
            session_ticket: None,
            delivery_rx_ssrc: None,
            delivery_payload_pending: false,
            data_seq: 0,
            last_ip_frame: 0,
            repair: adaptive.then(|| RepairState::new(start)),
            probe_seq: 0,
            probes: VecDeque::new(),
            check: None,
            next_probe: start,
            next_echo: start,
            echo: None,
            last_echo: None,
            rtt: None,
            bitrate_mbps: initial,
            adaptive_pacing: None,
            bwe_can_probe: false,
            pacer_bytes: 1500.0,
            pacer_wire_bytes: 0,
            pacer_at: start,
            ip_ingress: IpIngress::Handshake,
            incoming: VecDeque::new(),
            reassembly: Reassembly::default(),
            stats,
        };
        peer.drain()?;
        Ok(peer)
    }

    fn enable_matched_delivery(&mut self, timed: bool) {
        self.delivery_timed = timed;
        let origin = timed.then_some(self.start);
        self.stats.delivery_sender = Some(Box::new(delivery::matched::Sender::new(origin)));
        self.delivery_receiver = Some(Box::new(delivery::matched::Receiver::new(origin)));
    }

    fn feedback_updates(&self) -> u64 {
        self.arrival
            .as_ref()
            .map_or(0, |arrival| arrival.controller.feedback_updates())
    }

    fn enter_tun(&mut self, now: Instant) {
        self.ip_ingress = IpIngress::Tun;
        if self.config.uses_adaptive_pacing() && self.delivery_timed {
            let pacing = pacing::Pacing::new(
                now,
                self.stats.udp_tx_ipv4_bytes,
                self.stats.camera_cover_udp_bytes
                    + self.stats.camera_cover_packets * IPV4_UDP_OVERHEAD as u64,
                self.stats.udp_send_would_block,
            );
            self.set_pacing_rate(now, pacing.rate());
            self.adaptive_pacing = Some(pacing);
        }
        // The VPS represents the camera. Start the downlink clock after authentication.
        self.camera_cover = (self.adaptive_pacing.is_some()
            || (matches!(self.role, Role::Server) && self.adaptive_mtu()))
        .then(|| CameraCover::new(now, self.stats.udp_tx_ipv4_bytes));
    }

    fn set_pacing_rate(&mut self, now: Instant, rate: f64) {
        self.pacer_at = now;
        self.pacer_bytes = self.pacer_bytes.min(1500.0);
        self.pacer_wire_bytes = self.stats.udp_tx_ipv4_bytes;
        self.bitrate_mbps = rate;
        self.stats.adaptive_pacing_mbps = Some(rate);
    }

    fn note_backlog(&mut self, backlogged: bool) {
        if let Some(pacing) = &mut self.adaptive_pacing {
            pacing.backlog(backlogged);
        }
        if let Some(arrival) = &mut self.arrival {
            arrival.controller.set_application_backlogged(backlogged);
        }
    }

    fn wait_connected(&mut self, replacements: Option<&Receiver<Peer>>) -> Result<Option<Peer>> {
        self.wait_connected_until(replacements, Instant::now() + HANDSHAKE_TIMEOUT, None)
    }

    fn wait_for_ice_nomination(&mut self, stop: Option<&AtomicBool>) -> Result<bool> {
        let deadline = Instant::now() + ICE_STARTUP_GRACE;
        loop {
            ensure!(
                !stop.is_some_and(|flag| flag.load(Ordering::Relaxed)),
                "media startup interrupted"
            );
            #[cfg(windows)]
            ensure!(
                !CLIENT_INTERRUPTED.load(Ordering::Relaxed),
                "media startup interrupted"
            );
            let active = self.poll()?;
            // Give a nominated ICE pair the full deadline for DTLS and the encrypted echo.
            if self.ice_nominated {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            if !active {
                self.sleep_until_work();
            }
        }
    }

    fn wait_connected_until(
        &mut self,
        replacements: Option<&Receiver<Peer>>,
        deadline: Instant,
        stop: Option<&AtomicBool>,
    ) -> Result<Option<Peer>> {
        loop {
            ensure!(
                !stop.is_some_and(|flag| flag.load(Ordering::Relaxed)),
                "media startup interrupted"
            );
            ensure!(
                !matches!(self.role, Role::Client) || !client_interrupted(),
                "media startup interrupted"
            );
            if let Some(peer) = replacement(replacements) {
                return Ok(Some(peer));
            }
            let active = self.poll()?;
            if self.last_echo.is_some() && self.rtc.is_connected() {
                return Ok(None);
            }
            ensure!(
                Instant::now() < deadline,
                "ICE, DTLS or encrypted RTP probe timed out"
            );
            if !active {
                self.sleep_until_work();
            }
        }
    }

    fn sleep_until_work(&self) {
        let now = Instant::now();
        let deadline = self
            .grouped_frame
            .as_ref()
            .map_or(self.deadline, |group| self.deadline.min(group.frame_end));
        let deadline = if self.adaptive_pacing.is_none() {
            self.camera_cover
                .as_ref()
                .map_or(deadline, |cover| deadline.min(cover.next_frame))
        } else {
            deadline
        };
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(1));
        if !wait.is_zero() {
            thread::sleep(wait);
        }
    }

    fn poll(&mut self) -> Result<bool> {
        let mut active = self.poll_egress()?;
        let mut buffer = [0u8; 2048];
        for _ in 0..MAX_IO_BATCH {
            if !self.can_receive_media() {
                break;
            }
            match self.socket.recv_from(&mut buffer) {
                Ok((size, source)) => active |= self.receive_media(source, &buffer[..size])?,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("read media UDP socket"),
            }
        }
        active |= self.poll_timers()?;
        active |= self.poll_repair(usize::MAX)?;
        Ok(active)
    }

    fn poll_egress(&mut self) -> Result<bool> {
        let too_large = self.stats.drops.udp_message_too_large;
        let mut active = self
            .udp_egress
            .flush(Instant::now(), &mut self.stats, |packet| {
                send_media(&self.socket, self.role, packet)
            })?;
        let now = Instant::now();
        if self.stats.drops.udp_message_too_large > too_large {
            self.path_mtu.too_large(now);
        }
        self.path_mtu.update(now);
        if self
            .grouped_frame
            .as_ref()
            .is_some_and(|group| now >= group.frame_end)
        {
            self.finish_group()?;
            active = true;
        }
        Ok(active)
    }

    fn can_receive_media(&self) -> bool {
        // One RTP datagram can complete at most one IP packet, including
        // when it completes a previously received fragment.
        self.ip_ingress != IpIngress::Tun || self.incoming.len() < MAX_PACKET_QUEUE
    }

    fn receive_media(&mut self, source: SocketAddr, bytes: &[u8]) -> Result<bool> {
        let Ok(receive) = Receive::new(Protocol::Udp, source, self.local.into(), bytes) else {
            return Ok(false);
        };
        let input = Input::Receive(Instant::now(), receive);
        if !self.rtc.accepts(&input) {
            return Ok(false);
        }
        self.stats.udp_rx_bytes += bytes.len() as u64;
        if let Some((sequence, ssrc, padding)) = rtp_header(bytes) {
            self.stats.rtp_rx_candidates += 1;
            if self.delivery.is_some()
                || self.delivery_receiver.is_some()
                || (self.arrival.is_some() && !padding)
            {
                self.rx_datagram = Some((sequence, ssrc, bytes.len(), padding));
            }
        }
        let result = self
            .rtc
            .handle_input(input)
            .map_err(anyhow::Error::from)
            .and_then(|()| self.drain());
        self.rx_datagram = None;
        result?;
        Ok(true)
    }

    fn poll_timers(&mut self) -> Result<bool> {
        let mut active = false;
        let now = Instant::now();
        self.stats.drops.incomplete_fragment += self.reassembly.expire(now);
        if now >= self.deadline {
            self.rtc.handle_input(Input::Timeout(now))?;
            self.drain()?;
        }
        if !self.rtc.is_alive() {
            return Err(MediaDisconnected("DTLS session closed").into());
        }
        if self
            .last_echo
            .is_some_and(|last_echo| now.saturating_duration_since(last_echo) >= PROBE_TIMEOUT)
        {
            return Err(MediaDisconnected("encrypted RTP peer stopped responding").into());
        }
        if let Some(arrival) = &mut self.arrival {
            self.bitrate_mbps = arrival
                .controller
                .rate_mbps(now.saturating_duration_since(self.start));
        }
        if let Some(pacing) = &mut self.adaptive_pacing
            && let Some(rate) = pacing.tick(
                now,
                self.stats.udp_tx_ipv4_bytes,
                self.stats.camera_cover_udp_bytes
                    + self.stats.camera_cover_packets * IPV4_UDP_OVERHEAD as u64,
                self.stats.udp_send_would_block,
            )
        {
            self.set_pacing_rate(now, rate);
            self.stats.adaptive_pacing_updates += 1;
        }
        if self.rtc.is_connected() {
            if let Some(sequence) = self.echo
                && self.admit_control(PROBE_BODY.len())
            {
                self.echo = None;
                self.send_frame(Frame {
                    kind: Kind::Datagram,
                    flow: ECHO_FLOW,
                    sequence,
                    payload: PROBE_BODY.to_vec(),
                })?;
                active = true;
            }
            if self
                .arrival
                .as_ref()
                .is_some_and(|arrival| arrival.due(now))
                && self.admit_control(ArrivalReport::ENCODED_LEN)
                && let Some(arrival) = &mut self.arrival
            {
                let report = arrival.report(now, self.bitrate_mbps);
                self.send_frame(report)?;
                active = true;
            }
            if now >= self.next_probe
                && self.check.as_ref().is_none_or(|check| now < check.until)
                && self.admit_control(PROBE_BODY.len())
            {
                self.probe_seq = next_serial(self.probe_seq);
                self.probes.push_back((self.probe_seq, now));
                while self.probes.len() > 16 {
                    self.probes.pop_front();
                }
                self.next_probe = now
                    + if let Some(check) = &mut self.check {
                        check.sent += 1;
                        Duration::from_millis(110)
                    } else if self.arrival.is_some() {
                        ARRIVAL_PROBE_INTERVAL
                    } else if self.last_echo.is_some() {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_millis(250)
                    };
                self.send_frame(Frame {
                    kind: Kind::Datagram,
                    flow: PING_FLOW,
                    sequence: self.probe_seq,
                    payload: PROBE_BODY.to_vec(),
                })?;
                active = true;
            }
            if let Some(sequence) = self.mtu_echo
                && self.admit_control(PROBE_BODY.len())
            {
                self.mtu_echo = None;
                self.send_frame(Frame {
                    kind: Kind::Datagram,
                    flow: MTU_ECHO_FLOW,
                    sequence,
                    payload: PROBE_BODY.to_vec(),
                })?;
                active = true;
            }
            if self.last_echo.is_some()
                && self.path_mtu.due_at().is_some_and(|due| now >= due)
                && self.admit_control(MAX_WIDE_DATAGRAM + MAX_WIDE_PADDING)
            {
                self.mtu_probe_seq = next_serial(self.mtu_probe_seq);
                self.path_mtu.sent(self.mtu_probe_seq, now);
                self.stats.mtu_probes_sent += 1;
                self.send_frame(Frame {
                    kind: Kind::Datagram,
                    flow: MTU_PROBE_FLOW,
                    sequence: self.mtu_probe_seq,
                    payload: vec![0; MAX_WIDE_DATAGRAM],
                })?;
                active = true;
            }
            if let Some(observer) = &self.delivery {
                self.stats.delivery_report_age_ms = observer.sample_age_ms(now);
            }
            if let Some(at) = self.stats.delivery_matched_at {
                self.stats.delivery_matched_age_ms =
                    Some(now.saturating_duration_since(at).as_millis() as u64);
            }
            let since_start = now.saturating_duration_since(self.start);
            if self.ip_ingress == IpIngress::Tun
                && self
                    .delivery
                    .as_ref()
                    .is_some_and(|observer| observer.due(since_start))
                && self.admit_control(delivery::Report::LEN)
                && let Some(observer) = &mut self.delivery
            {
                let (sequence, report) = observer.report(since_start);
                self.send_frame(Frame {
                    kind: Kind::Datagram,
                    flow: DELIVERY_REPORT_FLOW,
                    sequence,
                    payload: report.encode(),
                })?;
                self.stats.delivery_reports_generated += 1;
                active = true;
            }
            if self.ip_ingress == IpIngress::Tun
                && self.delivery_payload_pending
                && self
                    .delivery_receiver
                    .as_ref()
                    .is_some_and(|receiver| receiver.due(now))
                && self.admit_control(if self.delivery_timed {
                    delivery::matched::Ack::TIMED_LEN
                } else {
                    delivery::matched::Ack::LEN
                })
                && let Some(report) = self
                    .delivery_receiver
                    .as_mut()
                    .and_then(|r| r.take_ack(now))
            {
                self.send_frame(Frame {
                    kind: Kind::Datagram,
                    flow: DELIVERY_ACK_FLOW,
                    sequence: next_serial(self.stats.delivery_ack_reports_generated as u32),
                    payload: report.encode(),
                })?;
                self.delivery_payload_pending = false;
                self.stats.delivery_ack_reports_generated += 1;
                active = true;
            }
        }
        Ok(active)
    }

    fn send_repair_feedback(
        &mut self,
        sequence: u32,
        payload: [u8; repair::Request::ENCODED_LEN],
        shared_credit: &mut usize,
    ) -> Result<()> {
        let sent = self.stats.udp_tx_ipv4_bytes;
        self.send_frame(Frame {
            kind: Kind::Datagram,
            flow: REPAIR_REQUEST_FLOW,
            sequence,
            payload: payload.to_vec(),
        })?;
        *shared_credit =
            shared_credit.saturating_sub((self.stats.udp_tx_ipv4_bytes - sent) as usize);
        Ok(())
    }

    fn poll_repair(&mut self, mut shared_credit: usize) -> Result<bool> {
        if !self.rtc.is_connected() || self.ip_ingress == IpIngress::ControlOnly {
            return Ok(false);
        }
        let now = Instant::now();
        let Some(state) = &mut self.repair else {
            return Ok(false);
        };
        let rtt = self.rtt.zip(self.last_echo);
        if self.bitrate_mbps == UNLIMITED_MBPS {
            state.refresh_from_wire(self.stats.udp_tx_ipv4_bytes, now, self.role, rtt);
        } else {
            state.refresh(now, self.bitrate_mbps, self.role, rtt);
        }
        if state
            .feedback
            .as_ref()
            .is_none_or(|(at, _)| now.duration_since(*at) >= repair::MAX_AGE)
        {
            state.feedback = state.rx.request(now).map(|request| (now, request));
        }
        let feedback_cost = repair::Request::ENCODED_LEN + RTP_ADMISSION_OVERHEAD;
        let mut active = false;
        if state.feedback.is_some()
            && shared_credit >= feedback_cost
            && self.admit_control(repair::Request::ENCODED_LEN)
        {
            let state = self.repair.as_mut().expect("repair enabled");
            let (_, mut request) = state.feedback.take().expect("feedback queued");
            if state.rx.sent(now, &mut request, self.rtt) {
                state.feedback_seq = next_serial(state.feedback_seq);
                let sequence = state.feedback_seq;
                let payload = request.encode();
                if repair::extended_rtt(self.rtt).is_some()
                    && state.feedback_copies.len() < MAX_FEEDBACK_COPIES
                {
                    state.feedback_copies.push_back(FeedbackCopy {
                        due: now + FEEDBACK_COPY_DELAY,
                        sequence,
                        payload,
                    });
                }
                self.send_repair_feedback(sequence, payload, &mut shared_credit)?;
                self.stats.repair_requests_sent += 1;
                active = true;
            }
        }
        let state = self.repair.as_mut().expect("repair enabled");
        while state
            .feedback_copies
            .front()
            .is_some_and(|copy| now >= copy.due + FEEDBACK_COPY_GRACE)
        {
            state.feedback_copies.pop_front();
        }
        if !active
            && state
                .feedback_copies
                .front()
                .is_some_and(|copy| now >= copy.due)
            && shared_credit >= feedback_cost
            && self.admit_control(repair::Request::ENCODED_LEN)
        {
            let state = self.repair.as_mut().expect("repair enabled");
            let copy = state
                .feedback_copies
                .pop_front()
                .expect("feedback copy ready");
            self.send_repair_feedback(copy.sequence, copy.payload, &mut shared_credit)?;
            self.stats.repair_feedback_copies_sent += 1;
            active = true;
        }
        for _ in 0..4 {
            let state = self.repair.as_mut().expect("repair enabled");
            let Some(size) = state.tx.peek_len(now) else {
                break;
            };
            let credit = state.credit;
            let fragments = if size > self.data_limit() { 2 } else { 1 };
            let cost = self.ip_admission_cost(size, fragments);
            if credit < cost as f64 || shared_credit < cost || !self.can_send_ip(size) {
                break;
            }
            let state = self.repair.as_mut().expect("repair enabled");
            let (sequence, packet) = state.tx.next(now).expect("repair queued");
            state.credit -= cost as f64;
            let sent = self.stats.udp_tx_ipv4_bytes;
            self.send_ip_frame(sequence, packet, true)?;
            shared_credit =
                shared_credit.saturating_sub((self.stats.udp_tx_ipv4_bytes - sent) as usize);
            self.stats.repair_packets_sent += 1;
            active = true;
        }
        Ok(active)
    }

    fn drain(&mut self) -> Result<()> {
        loop {
            match self.rtc.poll_output()? {
                Output::Timeout(deadline) => {
                    self.deadline = deadline;
                    return Ok(());
                }
                Output::Transmit(packet) => {
                    if matches!(self.role, Role::Client)
                        && packet.destination != SocketAddr::V4(self.public)
                    {
                        continue;
                    }
                    let bytes = &packet.contents;
                    let rtp = rtp_header(bytes);
                    if let Some((sequence, ssrc, false)) = rtp
                        && self.tx_ssrc == Some(ssrc)
                        && let Some(index) = self
                            .native_pending
                            .iter()
                            .position(|&(seq, _)| seq == sequence)
                        && let Some((_, delivery)) = self.native_pending.remove(index)
                    {
                        if let RtpDelivery::Cover { payload_bytes } = delivery {
                            if self
                                .udp_egress
                                .send_cover(&packet, &mut self.stats, |packet| {
                                    send_media(&self.socket, self.role, packet)
                                })
                                && let Some(cover) = &mut self.camera_cover
                            {
                                cover.observe_cover(bytes.len(), payload_bytes);
                            }
                            continue;
                        }
                        if delivery == RtpDelivery::Sample
                            && let Some(arrival) = &mut self.arrival
                        {
                            arrival
                                .controller
                                .on_sent(sequence, self.start.elapsed(), bytes.len());
                        }
                        #[cfg(test)]
                        if self.drop_rtp_once == Some(sequence) {
                            // Simulate losing this datagram after a successful UDP send.
                            self.drop_rtp_once = None;
                            self.stats.record_udp_send(bytes);
                            continue;
                        }
                    }
                    let too_large = self.stats.drops.udp_message_too_large;
                    self.udp_egress
                        .submit(Instant::now(), packet, &mut self.stats, |packet| {
                            send_media(&self.socket, self.role, packet)
                        })?;
                    if self.stats.drops.udp_message_too_large > too_large {
                        self.path_mtu.too_large(Instant::now());
                    }
                }
                Output::Event(Event::IceConnectionStateChange(state)) if state.is_connected() => {
                    self.ice_nominated = true;
                }
                Output::Event(Event::MediaAdded(media)) => {
                    ensure!(
                        media.kind == MediaKind::Video
                            && media.direction == Direction::SendRecv
                            && media.simulcast.is_none()
                            && self.mid.is_none_or(|mid| mid == media.mid),
                        "unexpected SDP media"
                    );
                    self.mid = Some(media.mid);
                }
                Output::Event(Event::RtpPacket(packet)) => {
                    self.stats.rtp_rx_authenticated += 1;
                    if let Some(frame) =
                        media::extract_with_wide_datagrams(&packet.payload, self.adaptive_mtu())
                    {
                        let now = Instant::now();
                        let datagram = self.rx_datagram.take().filter(|(seq, ssrc, _, _)| {
                            *seq == packet.header.sequence_number && *ssrc == *packet.header.ssrc
                        });
                        if self.ip_ingress == IpIngress::Tun
                            && let Some((seq, ssrc, bytes, padding)) = datagram
                        {
                            let payload = ip_payload_flow(frame.flow);
                            if let Some(observer) = &mut self.delivery {
                                observer.receive(bytes + IPV4_UDP_OVERHEAD, payload);
                            }
                            if !padding
                                && frame.kind == Kind::Datagram
                                && let Some(receiver) = &mut self.delivery_receiver
                                && *self.delivery_rx_ssrc.get_or_insert(ssrc) == ssrc
                            {
                                receiver.record(seq, now);
                                self.delivery_payload_pending |= payload;
                            }
                        }
                        if frame.kind == Kind::Datagram
                            && sampled_flow(frame.flow)
                            && (self.ip_ingress != IpIngress::ControlOnly
                                || frame.flow == PING_FLOW)
                            && let Some((seq, _, bytes, false)) = datagram
                            && let Some(arrival) = &mut self.arrival
                        {
                            arrival.record_arrival(
                                seq,
                                now.saturating_duration_since(self.start),
                                bytes,
                            );
                        }
                        self.receive_frame(frame, now);
                    } else {
                        self.stats.rtp_rx_invalid_frame += 1;
                    }
                }
                Output::Event(Event::EgressBitrateEstimate(BweKind::Twcc {
                    estimate,
                    can_probe,
                })) => {
                    self.bitrate_mbps =
                        (estimate.as_f64() / 1_000_000.0).clamp(0.05, self.config.max_mbps);
                    self.bwe_can_probe = can_probe;
                }
                Output::Event(_) => {}
            }
        }
    }

    fn receive_frame(&mut self, frame: Frame, now: Instant) {
        let repaired = matches!(frame.flow, REPAIRED_DATA_FLOW | REPAIRED_FRAGMENT_FLOW);
        if frame.kind != Kind::Datagram || (repaired && self.repair.is_none()) {
            return;
        }
        match frame.flow {
            DATA_FLOW | REPAIRED_DATA_FLOW if self.ip_ingress != IpIngress::ControlOnly => {
                if let Some(index) = self
                    .reassembly
                    .0
                    .iter()
                    .position(|part| part.sequence == frame.sequence)
                {
                    self.reassembly.0.remove(index);
                }
                self.enqueue_incoming(now, frame.sequence, frame.payload, repaired)
            }
            FRAGMENT_FLOW | REPAIRED_FRAGMENT_FLOW if self.ip_ingress != IpIngress::ControlOnly => {
                match self
                    .reassembly
                    .push(frame.sequence, &frame.payload, self.config.mtu, now)
                {
                    Ok((packet, dropped)) => {
                        self.stats.drops.incomplete_fragment += dropped;
                        if let Some(packet) = packet {
                            self.enqueue_incoming(now, frame.sequence, packet, repaired);
                        }
                    }
                    Err(_) => self.stats.drops.invalid_fragment += 1,
                }
            }
            REPAIR_REQUEST_FLOW if self.ip_ingress != IpIngress::ControlOnly => {
                if let Some(state) = &mut self.repair
                    && let Some(request) = repair::Request::decode(&frame.payload)
                {
                    state.tx.request(now, frame.sequence, &request);
                }
            }
            FRAME_END_FLOW | CAMERA_COVER_FLOW if self.ip_ingress != IpIngress::ControlOnly => {
                if let Some(state) = &mut self.repair
                    && let Some(bytes) = frame.payload.first_chunk::<4>()
                {
                    state.rx.observe_sent(now, u32::from_be_bytes(*bytes));
                }
            }
            PING_FLOW if frame.payload == PROBE_BODY && now >= self.next_echo => {
                self.echo = Some(frame.sequence);
                self.next_echo = now + Duration::from_millis(60);
            }
            ECHO_FLOW if frame.payload == PROBE_BODY => {
                if let Some(index) = self
                    .probes
                    .iter()
                    .position(|(seq, _)| *seq == frame.sequence)
                {
                    let (_, sent) = self.probes.remove(index).expect("matching probe exists");
                    self.last_echo = Some(now);
                    let rtt = now.saturating_duration_since(sent);
                    self.rtt = Some(rtt);
                    if let Some(state) = &mut self.repair {
                        state.tx.observe_rtt(rtt);
                        state.tx.observe_current_rtt(Some((rtt, now)));
                        state.rx.observe_current_rtt(Some((rtt, now)));
                    }
                    if let Some(check) = &mut self.check {
                        check.replies_ms.push(rtt.as_secs_f64() * 1000.0);
                    }
                }
            }
            DELIVERY_REPORT_FLOW => {
                if let Some(observer) = &mut self.delivery
                    && let Some(report) = delivery::Report::decode(&frame.payload)
                    && let Some(kbps) = observer.observe(
                        frame.sequence,
                        report,
                        now,
                        self.stats.rtp_tx_ipv4_bytes,
                        self.stats.rtp_tx_packets,
                    )
                {
                    self.stats.delivery_report_samples += 1;
                    self.stats.delivery_arrived_ipv4_kbps = kbps;
                }
            }
            DELIVERY_ACK_FLOW => {
                if let Some(sender) = &mut self.stats.delivery_sender
                    && let Some(ack) = delivery::matched::Ack::decode(&frame.payload)
                    && let Some(sample) = sender.observe(ack, now)
                {
                    if let Some(pacing) = &mut self.adaptive_pacing {
                        pacing.observe(now, sample);
                    }
                    self.stats.delivery_matched_sample = Some(sample);
                    self.stats.delivery_matched_at = Some(now);
                }
            }
            ARRIVAL_FLOW => {
                if let Some(arrival) = &mut self.arrival
                    && ArrivalReport::decode(frame.sequence, &frame.payload)
                        .and_then(|report| {
                            arrival
                                .controller
                                .on_feedback(&report, now.saturating_duration_since(self.start))
                        })
                        .is_err()
                {
                    self.stats.drops.invalid_feedback += 1;
                }
            }
            MTU_PROBE_FLOW
                if self.adaptive_mtu()
                    && frame.payload.len() == MAX_WIDE_DATAGRAM
                    && now >= self.next_mtu_echo =>
            {
                self.mtu_echo = Some(frame.sequence);
                self.next_mtu_echo = now + MTU_ECHO_INTERVAL;
            }
            MTU_ECHO_FLOW
                if frame.payload == PROBE_BODY && self.path_mtu.ack(frame.sequence, now) =>
            {
                self.stats.mtu_probes_acked += 1;
            }
            _ => {}
        }
    }

    fn enqueue_incoming(&mut self, now: Instant, sequence: u32, packet: Vec<u8>, repaired: bool) {
        if !self.role.valid_packet(self.config, &packet, true) {
            self.stats.drops.invalid_incoming_ip += 1;
        } else if self.incoming.len() >= MAX_PACKET_QUEUE {
            self.stats.drops.incoming_queue_full += 1;
        } else if self
            .repair
            .as_mut()
            .is_some_and(|state| !state.rx.receive(now, sequence))
        {
            self.stats.repair_duplicate_or_late += 1;
        } else {
            if repaired && let Some(state) = &mut self.repair {
                state.rx.observe_repair(now);
            }
            self.stats.repair_packets_received += u64::from(repaired);
            self.incoming.push_back((now, packet));
        }
    }

    fn send_frame(&mut self, frame: Frame) -> Result<()> {
        let now = Instant::now();
        if self
            .grouped_frame
            .as_ref()
            .is_some_and(|group| now >= group.frame_end)
        {
            self.finish_group()?;
        }
        if let Some(group) = &self.grouped_frame {
            return self.emit_frame(frame, group.timestamp, false, false);
        }
        let timestamp = self.next_rtp_timestamp(now);
        if self.adaptive_mtu() && ip_payload_flow(frame.flow) {
            self.grouped_frame = Some(GroupedFrame {
                timestamp,
                frame_end: now + RTP_FRAME_SPAN,
            });
            return self.emit_frame(frame, timestamp, true, false);
        }
        self.emit_frame(frame, timestamp, true, true)
    }

    fn finish_group(&mut self) -> Result<()> {
        if let Some(group) = self.grouped_frame.take() {
            let span = FRAME_END_MAX_PAYLOAD - FRAME_END_MIN_PAYLOAD + 1;
            let bytes =
                FRAME_END_MIN_PAYLOAD + self.rtp_lengths.hash_one(self.rtp_seq) as usize % span;
            let mut payload = vec![0; bytes];
            payload[..4].copy_from_slice(&self.last_ip_frame.to_be_bytes());
            // End the visible frame without delaying the last IP packet.
            self.emit_frame(
                Frame {
                    kind: Kind::Datagram,
                    flow: FRAME_END_FLOW,
                    sequence: next_serial(self.rtp_seq as u32),
                    payload,
                },
                group.timestamp,
                false,
                true,
            )?;
        }
        Ok(())
    }

    fn next_rtp_timestamp(&mut self, now: Instant) -> u32 {
        let clock = (now.duration_since(self.start).as_nanos() * 90_000 / 1_000_000_000) as u64;
        self.last_rtp_clock = clock.max(self.last_rtp_clock + 1);
        self.rtp_timestamp_origin
            .wrapping_add(self.last_rtp_clock as u32)
    }

    fn emit_frame(
        &mut self,
        frame: Frame,
        timestamp: u32,
        starts_frame: bool,
        marker: bool,
    ) -> Result<()> {
        let now = Instant::now();
        let mid = self.mid.context("VP8 media was not negotiated")?;
        let negotiated = self
            .rtc
            .media(mid)
            .context("missing SDP media")?
            .remote_pts();
        let pt = self
            .rtc
            .codec_config()
            .params()
            .iter()
            .find(|param| param.spec().codec == Codec::Vp8 && negotiated.contains(&param.pt()))
            .context("VP8 payload type missing")?
            .pt();
        let mut payload = VP8_PREFIX.to_vec();
        if !starts_frame {
            payload[0] = 0;
        }
        // Authenticate the largest wide packet before using this small
        // per-packet length variation. Base-size recovery adds no padding.
        let cover = match frame.flow {
            MTU_PROBE_FLOW => MAX_WIDE_PADDING,
            DATA_FLOW | REPAIRED_DATA_FLOW if frame.payload.len() > MAX_DATA => {
                self.rtp_lengths.hash_one(self.rtp_seq) as usize % (MAX_WIDE_PADDING + 1)
            }
            _ => 0,
        };
        payload.resize(VP8_PREFIX_LEN + HEADER + frame.payload.len() + cover, 0);
        media::embed_with_wide_datagrams(&mut payload, &frame, self.adaptive_mtu())?;
        let mut direct = self.rtc.direct_api();
        let stream = direct
            .stream_tx_by_mid(mid, None)
            .context("missing negotiated RTP stream")?;
        self.tx_ssrc = Some(*stream.ssrc());
        if self.stats.delivery_sender.is_some() {
            self.stats.delivery_tx_ssrc = self.tx_ssrc;
        }
        let delivery = if frame.flow == CAMERA_COVER_FLOW {
            RtpDelivery::Cover {
                payload_bytes: frame.payload.len(),
            }
        } else if sampled_flow(frame.flow) {
            RtpDelivery::Sample
        } else {
            RtpDelivery::Ordinary
        };
        self.native_pending
            .push_back((self.rtp_seq as u16, delivery));
        #[cfg(test)]
        if self.drop_rtp_flow_once == Some(frame.flow) {
            self.drop_rtp_flow_once = None;
            self.drop_rtp_once = Some(self.rtp_seq as u16);
        }
        stream.write_rtp(
            RtpWrite::new(pt, self.rtp_seq.into(), timestamp, now, payload).marker(marker),
        );
        self.rtp_seq += 1;
        self.drain()
    }

    fn adaptive_mtu(&self) -> bool {
        self.config.congestion == CongestionMode::IpTunnel
    }

    fn data_limit(&self) -> usize {
        if self.path_mtu.wide() {
            MAX_WIDE_DATAGRAM
        } else {
            MAX_DATA
        }
    }

    fn can_send_ip(&mut self, bytes: usize) -> bool {
        let fragments = if bytes > self.data_limit() { 2 } else { 1 };
        if self.udp_egress.is_pending()
            || !self.rtc.is_connected()
            || self.native_pending.len() + fragments > MAX_NATIVE_PENDING - 2
        {
            return false;
        }
        self.admit_cost(self.ip_admission_cost(bytes, fragments))
    }

    fn ip_admission_cost(&self, bytes: usize, fragments: usize) -> usize {
        // Charge carrier overhead for every datagram, including both fragments
        // in the legacy path. In IpTunnel this is the only RTP pacing.
        let padding = if fragments == 1 && bytes > MAX_DATA {
            MAX_WIDE_PADDING
        } else {
            0
        };
        // Reserve the bounded end-of-frame packet when opening a frame.
        let frame_end = if self.adaptive_mtu()
            && self
                .grouped_frame
                .as_ref()
                .is_none_or(|group| Instant::now() >= group.frame_end)
        {
            FRAME_END_MAX_PAYLOAD + RTP_ADMISSION_OVERHEAD
        } else {
            0
        };
        bytes + fragments * RTP_ADMISSION_OVERHEAD + padding + frame_end
    }

    fn admit_control(&mut self, payload_bytes: usize) -> bool {
        !self.udp_egress.is_pending()
            && self.native_pending.len() < MAX_NATIVE_PENDING
            && (self.config.congestion == CongestionMode::NativeTwcc
                || self.admit_cost(payload_bytes + VP8_PREFIX_LEN + HEADER + 80))
    }

    fn admit_cost(&mut self, cost: usize) -> bool {
        self.admit_cost_with_reserve(cost, 0)
    }

    fn admit_cost_with_reserve(&mut self, cost: usize, reserve: usize) -> bool {
        if self.bitrate_mbps == UNLIMITED_MBPS {
            return true;
        }
        self.refill_pacer(Instant::now());
        if self.pacer_bytes < (cost + reserve) as f64 {
            return false;
        }
        if self.adaptive_pacing.is_none() {
            self.pacer_bytes -= cost as f64;
        }
        true
    }

    fn refill_pacer(&mut self, now: Instant) {
        let credit = now.saturating_duration_since(self.pacer_at).as_secs_f64()
            * self.bitrate_mbps
            * 125_000.0;
        self.pacer_at = now;
        let burst = (self.bitrate_mbps * 250.0).max(4_800.0);
        if self.adaptive_pacing.is_some() {
            let sent = self.stats.udp_tx_ipv4_bytes - self.pacer_wire_bytes;
            self.pacer_wire_bytes = self.stats.udp_tx_ipv4_bytes;
            self.pacer_bytes = (self.pacer_bytes + credit - sent as f64).min(burst);
        } else {
            self.pacer_bytes = (self.pacer_bytes + credit).min(burst.min(32_000.0));
        }
    }

    fn send_camera_cover(&mut self, now: Instant, ip_pending: bool) -> Result<bool> {
        let Some(cover) = &mut self.camera_cover else {
            return Ok(false);
        };
        if self.adaptive_pacing.is_some() {
            if ip_pending
                || !self.incoming.is_empty()
                || self.udp_egress.is_pending()
                || !self.native_pending.is_empty()
                || !self.rtc.is_connected()
            {
                return Ok(false);
            }
            let overhead = cover.packet_overhead;
            self.refill_pacer(now);
            let available =
                (self.pacer_bytes as usize).saturating_sub(WIRE_FILL_RESERVE + overhead);
            if available < MAX_DATA {
                return Ok(false);
            }
            self.emit_cover(now, MAX_DATA)?;
            return Ok(true);
        }
        let cover_wire_bytes = self.stats.camera_cover_udp_bytes
            + self.stats.camera_cover_packets * IPV4_UDP_OVERHEAD as u64;
        let Some(bytes) = cover.take_slot(now, self.stats.udp_tx_ipv4_bytes - cover_wire_bytes)
        else {
            return Ok(false);
        };
        if bytes < FRAME_END_MIN_PAYLOAD
            || ip_pending
            || !self.incoming.is_empty()
            || self
                .grouped_frame
                .as_ref()
                .is_some_and(|group| group.frame_end <= now)
            || self.udp_egress.is_pending()
            || !self.native_pending.is_empty()
            || !self.rtc.is_connected()
            || !self
                .admit_cost_with_reserve(bytes + RTP_ADMISSION_OVERHEAD, CAMERA_COVER_IP_RESERVE)
        {
            self.stats.camera_cover_skipped += 1;
            return Ok(false);
        }
        self.emit_cover(now, bytes)?;
        Ok(true)
    }

    fn emit_cover(&mut self, now: Instant, bytes: usize) -> Result<()> {
        let standalone = self.grouped_frame.is_none();
        let timestamp = self
            .grouped_frame
            .as_ref()
            .map(|group| group.timestamp)
            .unwrap_or_else(|| self.next_rtp_timestamp(now));
        let mut payload = vec![0; bytes];
        payload[..4].copy_from_slice(&self.last_ip_frame.to_be_bytes());
        self.emit_frame(
            Frame {
                kind: Kind::Datagram,
                flow: CAMERA_COVER_FLOW,
                sequence: next_serial(self.rtp_seq as u32),
                payload,
            },
            timestamp,
            standalone,
            standalone,
        )
    }

    fn send_ip(&mut self, packet: Vec<u8>) -> Result<()> {
        if let Some(pacing) = &mut self.adaptive_pacing {
            pacing.payload_sent();
        }
        self.data_seq = next_serial(self.data_seq);
        self.stats.tun_tx_packets += 1;
        self.stats.tun_tx_bytes += packet.len() as u64;
        if let Some(state) = &mut self.repair {
            state.tx.remember(Instant::now(), self.data_seq, &packet);
        }
        self.send_ip_frame(self.data_seq, packet, false)?;
        self.last_ip_frame = self.data_seq;
        Ok(())
    }

    fn send_ip_frame(&mut self, sequence: u32, packet: Vec<u8>, repaired: bool) -> Result<()> {
        if packet.len() <= self.data_limit() {
            return self.send_frame(Frame {
                kind: Kind::Datagram,
                flow: if repaired {
                    REPAIRED_DATA_FLOW
                } else {
                    DATA_FLOW
                },
                sequence,
                payload: packet,
            });
        }
        let (head, tail) = packet.split_at(FIRST_FRAGMENT_BYTES);
        for (index, data) in [(0, head), (1, tail)] {
            let mut payload = Vec::with_capacity(data.len() + 1);
            payload.push(index);
            payload.extend_from_slice(data);
            self.send_frame(Frame {
                kind: Kind::Datagram,
                flow: if repaired {
                    REPAIRED_FRAGMENT_FLOW
                } else {
                    FRAGMENT_FLOW
                },
                sequence,
                payload,
            })?;
        }
        Ok(())
    }
}

fn configure_media_socket_buffers(socket: &UdpSocket, receive_request: usize) {
    let socket = SockRef::from(socket);
    if let Err(error) = socket.set_recv_buffer_size(receive_request) {
        eprintln!("SFERA MEDIA: UDP receive buffer request unavailable: {error}");
    }
    if let Err(error) = socket.set_send_buffer_size(UDP_BUFFER_REQUEST) {
        eprintln!("SFERA MEDIA: UDP send buffer request unavailable: {error}");
    }
}

fn media_socket_stats(socket: &UdpSocket) -> Result<Stats> {
    let socket = SockRef::from(socket);
    Ok(Stats {
        udp_recv_buffer_bytes: socket
            .recv_buffer_size()
            .context("read effective UDP receive buffer")?,
        udp_send_buffer_bytes: socket
            .send_buffer_size()
            .context("read effective UDP send buffer")?,
        ..Stats::default()
    })
}

fn send_media(socket: &UdpSocket, role: Role, packet: &Transmit) -> io::Result<usize> {
    match role {
        Role::Client => socket.send(&packet.contents),
        Role::Server => socket.send_to(&packet.contents, packet.destination),
    }
}

fn sampled_flow(flow: u32) -> bool {
    ip_payload_flow(flow) || flow == PING_FLOW
}

fn ip_payload_flow(flow: u32) -> bool {
    matches!(
        flow,
        DATA_FLOW | FRAGMENT_FLOW | REPAIRED_DATA_FLOW | REPAIRED_FRAGMENT_FLOW
    )
}

fn rtp_header(bytes: &[u8]) -> Option<(u16, u32, bool)> {
    if bytes.len() < 12 || bytes[0] & 0xc0 != 0x80 || (192..=223).contains(&bytes[1]) {
        return None;
    }
    Some((
        u16::from_be_bytes(bytes[2..4].try_into().ok()?),
        u32::from_be_bytes(bytes[8..12].try_into().ok()?),
        bytes[0] & 0x20 != 0,
    ))
}

fn next_serial(old: u32) -> u32 {
    old.wrapping_add(1).max(1)
}

/// Check authenticated signaling, ICE, DTLS and an encrypted RTP round-trip
/// without creating a TUN device or changing routes.
pub fn check(
    signal_url: &str,
    signal_token_file: &Path,
    config: TunnelConfig,
    seconds: u16,
) -> Result<()> {
    config.validate()?;
    let start = Instant::now();
    ensure!((1..=60).contains(&seconds), "check-seconds must be 1..=60");
    let mut peer = dial_peer(
        signal_url,
        signal_token_file,
        config,
        IpIngress::ControlOnly,
    )?;
    let connected_ms = start.elapsed().as_secs_f64() * 1000.0;
    let began = Instant::now();
    let until = began + Duration::from_secs(seconds.into());
    peer.probes.clear();
    peer.next_probe = began + Duration::from_millis(120);
    peer.check = Some(ProbeCheck {
        until,
        sent: 0,
        replies_ms: Vec::new(),
    });
    while Instant::now() < until + Duration::from_millis(650) {
        if !peer.poll()? {
            peer.sleep_until_work();
        }
        if Instant::now() >= until && peer.probes.is_empty() {
            break;
        }
    }
    let mut samples = peer
        .check
        .take()
        .context("probe collection did not start")?;
    samples.replies_ms.sort_by(f64::total_cmp);
    let replies = samples.replies_ms.len();
    let loss_pct = if samples.sent > 0 {
        Some(100.0 * (1.0 - replies as f64 / f64::from(samples.sent)))
    } else {
        None
    };
    let percentile = |p: f64| {
        (replies > 0).then(|| samples.replies_ms[((replies - 1) as f64 * p).round() as usize])
    };
    println!(
        "{}",
        serde_json::json!({
            "state": "connected",
            "transport": "SFERA VP8 RTP / DTLS-SRTP / UDP",
            "public_ip": peer.public.ip(),
            "udp_port": peer.public.port(),
            "connected_ms": connected_ms,
            "rtt_ms": peer.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
            "probes_sent": samples.sent,
            "probe_replies": replies,
            "probe_loss_pct": loss_pct,
            "rtt_p50_ms": percentile(0.50),
            "rtt_p95_ms": percentile(0.95),
            "bandwidth_mode": peer.config.congestion.name(),
            "wide_frames": peer.path_mtu.wide(),
            "bitrate_mbps": peer.bitrate_mbps.is_finite().then_some(peer.bitrate_mbps),
            "feedback_updates": peer.feedback_updates(),
            "stats": peer.stats,
            "tun_created": false,
        })
    );
    Ok(())
}

fn run_device(
    tun: &impl PacketIo,
    mut peer: Peer,
    status: Option<(&Path, &str)>,
    replacements: Option<&Receiver<Peer>>,
    client_route: Option<SocketAddrV4>,
    stop: Option<&AtomicBool>,
) -> Result<Option<Peer>> {
    peer.enter_tun(Instant::now());
    let mut outgoing = StagedPackets::new(peer.config.congestion);
    let mut buffer = [0u8; TUN_READ_BUFFER_SIZE];
    let mut next_status = Instant::now();
    let mut next_route_check = Instant::now() + Duration::from_secs(1);
    let connect_ms = peer.start.elapsed().as_secs_f64() * 1000.0;
    let result = (|| -> Result<Option<Peer>> {
        loop {
            if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Ok(None);
            }
            #[cfg(windows)]
            if matches!(peer.role, Role::Client) && CLIENT_INTERRUPTED.load(Ordering::Relaxed) {
                return Ok(None);
            }
            if let Some(peer) = replacement(replacements) {
                return Ok(Some(peer));
            }
            let now = Instant::now();
            if let Some(endpoint) = client_route.filter(|_| peer.session_ticket.is_some())
                && now >= next_route_check
            {
                next_route_check = now + Duration::from_secs(1);
                if underlay_source(endpoint).is_ok_and(|source| {
                    source != *peer.local.ip() && source != peer.config.local_ip
                }) {
                    return Err(MediaDisconnected("local underlay address changed").into());
                }
            }
            let mut active = peer.poll().map_err(classify_media_error)?;
            let now = Instant::now();
            for _ in 0..MAX_IO_BATCH {
                let Some((_, packet)) = peer.incoming.front() else {
                    break;
                };
                match tun.send_packet(packet) {
                    Ok(n) if n == packet.len() => {
                        peer.stats.tun_rx_bytes += n as u64;
                        peer.stats.tun_rx_packets += 1;
                        peer.incoming.pop_front();
                        active = true;
                    }
                    Ok(_) => bail!("partial TUN packet write"),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        discard_expired(
                            &mut peer.incoming,
                            now,
                            &mut peer.stats.drops.incoming_queue_expired,
                        );
                        break;
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error).context("write packet to TUN"),
                }
            }
            let reads = outgoing.reads_per_visit();
            if reads > 1 {
                for _ in 0..reads {
                    if outgoing.is_full() {
                        peer.stats.tun_stage_full_visits += 1;
                        break;
                    }
                    match stage_tun_packet(tun, &mut peer, &mut outgoing, &mut buffer) {
                        Ok(()) => active = true,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error).context("read ahead from TUN"),
                    }
                }
            }
            for _ in 0..MAX_IO_BATCH {
                if peer.udp_egress.is_pending() {
                    break;
                }
                if outgoing.is_empty() {
                    match stage_tun_packet(tun, &mut peer, &mut outgoing, &mut buffer) {
                        Ok(()) => active = true,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                        Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error).context("read packet from TUN"),
                    }
                    if outgoing.is_empty() {
                        continue;
                    }
                }
                let packet = outgoing.front().expect("outgoing packet exists");
                if !peer.can_send_ip(packet.len()) {
                    break;
                }
                let packet = outgoing.pop().expect("outgoing packet exists");
                peer.send_ip(packet).map_err(classify_media_error)?;
                active = true;
            }
            peer.note_backlog(!outgoing.is_empty());
            if peer.camera_cover.is_some() {
                active |= peer.send_camera_cover(Instant::now(), !outgoing.is_empty())?;
            }
            if let Some((path, name)) = status
                && now >= next_status
            {
                publish_status(path, name, &peer, connect_ms, "connected")?;
                next_status = now + Duration::from_secs(2);
            }
            if !active {
                peer.sleep_until_work();
            }
        }
    })();
    peer.stats.drops.udp_pending_shutdown += peer.udp_egress.pending.len() as u64;
    if let Some((path, name)) = status {
        let state = if peer.session_ticket.is_some()
            && result
                .as_ref()
                .is_err_and(|error| error.is::<MediaDisconnected>())
        {
            "connecting"
        } else {
            "disconnected"
        };
        let _ = publish_status(path, name, &peer, connect_ms, state);
    }
    eprintln!(
        "SFERA MEDIA: TUN TX {} packets / {} bytes, RX {} packets / {} bytes, dropped {}",
        peer.stats.tun_tx_packets,
        peer.stats.tun_tx_bytes,
        peer.stats.tun_rx_packets,
        peer.stats.tun_rx_bytes,
        peer.stats.drops.total()
    );
    if let Ok(counters) = serde_json::to_string(&peer.stats) {
        let rate = if peer.bitrate_mbps == UNLIMITED_MBPS {
            "uncapped".to_owned()
        } else {
            format!("{:.3} Mbps", peer.bitrate_mbps)
        };
        eprintln!(
            "SFERA MEDIA: {} at {rate}, {} feedback updates, counters {counters}",
            peer.config.congestion.name(),
            peer.feedback_updates()
        );
    }
    result
}

fn classify_media_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            ErrorKind::ConnectionRefused
                | ErrorKind::NetworkDown
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::AddrNotAvailable
        )
    }) {
        error.context(MediaDisconnected("UDP path unavailable"))
    } else {
        error
    }
}

fn stage_tun_packet(
    tun: &impl PacketIo,
    peer: &mut Peer,
    outgoing: &mut StagedPackets,
    buffer: &mut [u8],
) -> io::Result<()> {
    let size = tun.receive_packet(buffer)?;
    let packet = &buffer[..size];
    if peer.role.valid_packet(peer.config, packet, false) {
        outgoing.push(packet.to_vec());
        peer.stats.tun_stage_peak_packets = peer.stats.tun_stage_peak_packets.max(outgoing.len());
    } else {
        peer.stats.drops.invalid_outgoing_ip += 1;
    }
    Ok(())
}

/// Nonblocking packet interface supplied by the OS or a platform adapter.
pub trait PacketIo {
    fn receive_packet(&self, buffer: &mut [u8]) -> io::Result<usize>;
    fn send_packet(&self, packet: &[u8]) -> io::Result<usize>;
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
impl PacketIo for SyncDevice {
    fn receive_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        recv_tun(self, buffer)
    }

    fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        send_tun(self, packet)
    }
}

/// Connect a platform-owned IPv4 packet interface without changing OS routes.
pub fn connect_mobile(
    host: Ipv4Addr,
    local: Ipv4Addr,
    credential: &[u8],
    device: &impl PacketIo,
    stop: &AtomicBool,
    on_connection: impl Fn(bool),
) -> Result<()> {
    ensure!(
        local.is_private() && u32::from(local) & 3 == 2,
        "invalid mobile peer address"
    );
    let config = TunnelConfig {
        local_ip: local,
        peer_ip: Ipv4Addr::from(u32::from(local) - 1),
        mtu: DEFAULT_MTU,
        max_mbps: UNLIMITED_MBPS,
        congestion: CongestionMode::IpTunnel,
    };
    config.validate()?;
    let endpoint = Endpoint::parse(&format!("https://{host}/api/session"))?;
    let token = Token::parse(credential)?;
    let mut ticket = None;
    let mut backoff = Duration::from_secs(1);
    while !stop.load(Ordering::Relaxed) {
        let peer = match dial_endpoint(
            &endpoint,
            &token,
            config,
            IpIngress::Handshake,
            ticket,
            Some(stop),
        ) {
            Ok(peer) => peer,
            Err(error) if ticket.is_none() || error.is::<signaling::SessionReplaced>() => {
                return Err(error);
            }
            Err(_) => {
                let deadline = Instant::now() + backoff;
                while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(100));
                }
                backoff = (backoff * 2).min(Duration::from_secs(8));
                continue;
            }
        };
        if stop.load(Ordering::Relaxed) {
            break;
        }
        ticket = peer.session_ticket;
        backoff = Duration::from_secs(1);
        on_connection(true);
        let result = run_device(
            device,
            peer,
            None,
            None,
            Some(endpoint.route_to),
            Some(stop),
        );
        on_connection(false);
        match result {
            Err(error) if ticket.is_some() && error.is::<MediaDisconnected>() => continue,
            result => return result.map(|_| ()),
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn recv_tun(tun: &SyncDevice, buffer: &mut [u8]) -> io::Result<usize> {
    #[cfg(windows)]
    return tun.try_recv(buffer);
    #[cfg(unix)]
    tun.recv(buffer)
}

#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn send_tun(tun: &SyncDevice, packet: &[u8]) -> io::Result<usize> {
    #[cfg(windows)]
    return tun.try_send(packet);
    #[cfg(unix)]
    tun.send(packet)
}

fn discard_expired(queue: &mut VecDeque<(Instant, Vec<u8>)>, now: Instant, dropped: &mut u64) {
    while queue
        .front()
        .is_some_and(|(queued, _)| now.saturating_duration_since(*queued) > MAX_QUEUE_AGE)
    {
        queue.pop_front();
        *dropped += 1;
    }
}

#[derive(Serialize)]
struct Status<'a> {
    state: &'a str,
    interface: &'a str,
    public_ip: Ipv4Addr,
    udp_port: u16,
    tun_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    mtu: u16,
    pid: u32,
    connected_ms: f64,
    rtt_ms: Option<f64>,
    bitrate_mbps: Option<f64>,
    bwe_can_probe: bool,
    max_mbps: Option<f64>,
    bandwidth_mode: &'static str,
    wide_frames: bool,
    feedback_updates: u64,
    dropped_packets: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    #[serde(flatten)]
    stats: &'a Stats,
}

fn publish_status(
    path: &Path,
    name: &str,
    peer: &Peer,
    connected_ms: f64,
    state: &str,
) -> Result<()> {
    let status = Status {
        state,
        interface: name,
        public_ip: *peer.public.ip(),
        udp_port: peer.public.port(),
        tun_ip: peer.config.local_ip,
        peer_ip: peer.config.peer_ip,
        mtu: peer.config.mtu,
        pid: std::process::id(),
        connected_ms,
        rtt_ms: peer.rtt.map(|rtt| rtt.as_secs_f64() * 1000.0),
        bitrate_mbps: peer.bitrate_mbps.is_finite().then_some(peer.bitrate_mbps),
        bwe_can_probe: peer.bwe_can_probe,
        max_mbps: peer
            .config
            .max_mbps
            .is_finite()
            .then_some(peer.config.max_mbps),
        bandwidth_mode: peer.config.congestion.name(),
        wide_frames: peer.path_mtu.wide(),
        feedback_updates: peer.feedback_updates(),
        dropped_packets: peer.stats.drops.total(),
        tx_bytes: peer.stats.tun_tx_bytes,
        rx_bytes: peer.stats.tun_rx_bytes,
        stats: &peer.stats,
    };
    write_status(path, &status)
}

fn write_status(path: &Path, status: &impl Serialize) -> Result<()> {
    let filename = path.file_name().context("status file must name a file")?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(filename);
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("create status file {}", tmp.display()))?;
    let result = (|| -> Result<()> {
        let mut json = serde_json::to_vec(status)?;
        json.push(b'\n');
        file.write_all(&json)?;
        drop(file);
        fs::rename(&tmp, path)
            .with_context(|| format!("publish status file {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncapped_ip_tunnel_admits_bulk_and_bounds_repair_credit() -> Result<()> {
        let (mut client, _) = connected_loopback_peers(CongestionMode::IpTunnel, UNLIMITED_MBPS)?;
        client.config.validate()?;
        for _ in 0..1024 {
            assert!(client.can_send_ip(usize::from(DEFAULT_MTU)));
        }
        let now = Instant::now();
        let repair = client.repair.as_mut().expect("repair enabled");
        repair.refresh_from_wire(1_000_000, now, Role::Client, None);
        assert_eq!(repair.credit, 64_000.0);
        repair.credit -= 2_000.0;
        repair.refresh_from_wire(1_000_000, now, Role::Client, None);
        assert_eq!(repair.credit, 62_000.0);
        Ok(())
    }

    #[test]
    fn client_repair_credit_uses_measured_short_rtt() {
        let now = Instant::now();
        let short = Some((Duration::from_millis(44), now));
        let boundary = Some((Duration::from_millis(201), now));
        let after_refill = now + Duration::from_millis(10);
        for (role, rtt, expected) in [
            (Role::Client, short, 5_625.0),
            (Role::Server, short, 3_750.0),
            (Role::Client, None, 3_750.0),
            (Role::Client, Some((Duration::ZERO, now)), 3_750.0),
            (Role::Client, boundary, 3_750.0),
        ] {
            let mut state = RepairState::new(now);
            state.refresh(after_refill, 20.0, role, rtt);
            assert!((state.credit - expected).abs() < 0.001);
        }

        let mut state = RepairState::new(now);
        let after_burst = now + Duration::from_millis(100);
        state.refresh(after_burst, 20.0, Role::Client, short);
        assert!((state.credit - 22_500.0).abs() < 0.001);
        state.refresh(after_burst, 20.0, Role::Client, boundary);
        assert!((state.credit - 15_000.0).abs() < 0.001);
        state.refresh(now + SHORT_REPAIR_RTT_MAX_AGE, 20.0, Role::Client, short);
        assert!((state.credit - 15_000.0).abs() < 0.001);
    }

    #[test]
    fn high_client_repair_credit_boundaries_freshness_and_role() {
        let now = Instant::now();
        let after = now + Duration::from_millis(10);
        for role in [Role::Client, Role::Server] {
            for sample in [
                None,
                Some((Duration::ZERO, now)),
                Some((Duration::from_millis(99), now)),
                Some((Duration::from_millis(100), now)),
                Some((Duration::from_millis(160), now)),
                Some((Duration::from_millis(200), now)),
                Some((Duration::from_millis(201), now)),
                Some((
                    Duration::from_millis(160),
                    after - Duration::from_millis(2999),
                )),
                Some((
                    Duration::from_millis(160),
                    after - Duration::from_millis(3000),
                )),
            ] {
                let mut state = RepairState::new(now);
                state.refresh(after, 20.0, role, sample);
                let eligible = matches!(role, Role::Client)
                    && sample.is_some_and(|(rtt, at)| {
                        after.duration_since(at) < Duration::from_secs(3)
                            && !rtt.is_zero()
                            && rtt <= Duration::from_millis(200)
                    });
                assert!((state.credit - if eligible { 5625.0 } else { 3750.0 }).abs() < 0.001);
            }
        }
    }

    #[test]
    fn high_client_repair_credit_transitions_clamp_without_free_refill() {
        let now = Instant::now();
        let high = Some((Duration::from_millis(160), now));
        let outside = Some((Duration::from_millis(201), now));
        let mut state = RepairState::new(now);
        let filled = now + Duration::from_millis(100);
        state.refresh(filled, 20.0, Role::Client, high);
        assert_eq!(state.credit, 22500.0);
        state.refresh(filled, 20.0, Role::Client, outside);
        assert_eq!(state.credit, 15000.0);
        state.refresh(filled, 20.0, Role::Client, high);
        assert_eq!(state.credit, 15000.0);
        state.refresh(
            filled + Duration::from_millis(100),
            20.0,
            Role::Client,
            high,
        );
        assert_eq!(state.credit, 22500.0);
        state.refresh(now + Duration::from_secs(3), 20.0, Role::Client, high);
        assert_eq!(state.credit, 15000.0);
        let fresh = Some((Duration::from_millis(160), now + Duration::from_secs(3)));
        state.refresh(now + Duration::from_secs(3), 20.0, Role::Client, fresh);
        assert_eq!(state.credit, 15000.0);
        state.refresh(now + Duration::from_millis(3100), 20.0, Role::Client, fresh);
        assert_eq!(state.credit, 22500.0);
        state.refresh(now + Duration::from_millis(3100), 20.0, Role::Server, fresh);
        assert_eq!(state.credit, 15000.0);
    }

    #[test]
    fn high_client_repair_credit_preserves_bucket_bounds() {
        let now = Instant::now();
        for bitrate in [0.01, 20.0, 1000.0] {
            for (role, rtt, share) in [
                (Role::Client, 44, 0.225),
                (Role::Client, 160, 0.225),
                (Role::Server, 160, 0.15),
            ] {
                let mut state = RepairState::new(now);
                state.refresh(
                    now + Duration::from_secs(1),
                    bitrate,
                    role,
                    Some((Duration::from_millis(rtt), now)),
                );
                let rate = bitrate * 125000.0 * share;
                assert_eq!(state.credit, (rate * 0.04).clamp(2048.0, 64000.0).min(rate));
            }
        }
    }

    #[test]
    fn matching_echo_keeps_latest_rtt_and_feeds_fourth_request_freshness() -> Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let SocketAddr::V4(local) = socket.local_addr()? else {
            bail!("not IPv4")
        };
        let mut peer = Peer::new(
            socket,
            local,
            local,
            Role::Client,
            TunnelConfig {
                congestion: CongestionMode::IpTunnel,
                ..config(false)
            },
        )?;
        let start = Instant::now();
        for (index, ms) in [44, 160, 44, 201, 160].into_iter().enumerate() {
            let now = start + Duration::from_secs(index as u64 + 1);
            let sequence = index as u32 + 1;
            let rtt = Duration::from_millis(ms);
            peer.probes.push_back((sequence, now - rtt));
            let echo = Frame {
                kind: Kind::Datagram,
                flow: ECHO_FLOW,
                sequence,
                payload: PROBE_BODY.to_vec(),
            };
            peer.receive_frame(echo.clone(), now);
            assert_eq!(peer.rtt, Some(rtt));
            assert_eq!(peer.last_echo, Some(now));
            // Replay has no matching outstanding probe, so it cannot refresh RTT.
            peer.receive_frame(echo, now + Duration::from_millis(1));
            assert_eq!(peer.rtt, Some(rtt));
            assert_eq!(peer.last_echo, Some(now));
        }
        let discovered = start + Duration::from_secs(5);
        let state = peer.repair.as_mut().unwrap();
        state.rx.receive(discovered, 2);
        for ms in [3, 203, 403, 603] {
            let at = discovered + Duration::from_millis(ms);
            let mut request = state.rx.request(at).expect("high RTT request due");
            assert!(state.rx.sent(at, &mut request, peer.rtt));
        }
        assert!(
            state
                .rx
                .request(discovered + Duration::from_millis(803))
                .is_none()
        );
        Ok(())
    }

    fn udp_packet(port: u16, contents: Vec<u8>) -> Transmit {
        Transmit {
            proto: Protocol::Udp,
            source: (Ipv4Addr::LOCALHOST, 1000).into(),
            destination: (Ipv4Addr::LOCALHOST, port).into(),
            contents: contents.into(),
        }
    }

    #[test]
    fn camera_cover_never_enters_the_udp_retry_queue() -> Result<()> {
        let now = Instant::now();
        let mut queue = UdpEgress::default();
        let mut stats = Stats::default();
        let cover = udp_packet(2001, vec![0; 256]);
        queue.send_cover(&cover, &mut stats, |_| Err(ErrorKind::WouldBlock.into()));
        assert!(!queue.is_pending());
        assert_eq!(stats.camera_cover_send_failures, 1);
        assert_eq!(stats.drops.total(), 0);

        queue.submit(now, udp_packet(2001, vec![1]), &mut stats, |_| {
            Err(ErrorKind::WouldBlock.into())
        })?;
        queue.send_cover(&cover, &mut stats, |_| panic!("cover would overtake IP"));
        assert_eq!(stats.camera_cover_skipped, 1);
        assert!(queue.flush(now + UDP_RETRY_INTERVAL, &mut stats, |packet| {
            assert_eq!(&packet.contents[..], &[1]);
            Ok(1)
        })?);
        assert_eq!(stats.drops.total(), 0);
        Ok(())
    }

    #[test]
    fn camera_cover_never_catches_up_after_a_late_wakeup() {
        let now = Instant::now();
        let mut cover = CameraCover::new(now, 0);
        let late = now + RTP_FRAME_SPAN + Duration::from_millis(32);
        assert_eq!(cover.take_slot(now, 0), None);
        assert!((1..=MAX_DATA).contains(&cover.take_slot(late, 0).unwrap()));
        assert_eq!(cover.take_slot(now + RTP_FRAME_SPAN * 2, 0), None);
        assert!(cover.next_frame - late >= RTP_FRAME_SPAN - CAMERA_MAX_SLOT_SLIP);
    }

    #[test]
    fn camera_cover_budgets_sent_ipv4_bytes_and_never_carries_payload_debt() {
        let now = Instant::now();
        let mut cover = CameraCover::new(now, 100);
        cover.observe_cover(872, 800);
        assert!((552..=648).contains(&cover.take_slot(now + RTP_FRAME_SPAN, 400).unwrap()));
        assert_eq!(cover.take_slot(now + RTP_FRAME_SPAN * 2, 1800), Some(0));
        assert!((804..=996).contains(&cover.take_slot(now + RTP_FRAME_SPAN * 3, 1800).unwrap()));

        let mut cover = CameraCover::new(now, 0);
        cover.observe_cover(872, 800);
        let sizes: Vec<_> = (1..=60)
            .map(|slot| cover.take_slot(now + RTP_FRAME_SPAN * slot, 0).unwrap() + 100)
            .collect();
        assert!(sizes.windows(2).any(|pair| pair[0] != pair[1]));
        for window in sizes.windows(30) {
            let total: usize = window.iter().sum();
            assert!(total.abs_diff(240_000 / 8) <= (2 * CAMERA_SIZE_PHASE_BYTES) as usize);
        }
    }

    #[test]
    fn camera_cover_reserves_three_maximum_ip_packets_on_the_narrow_path() -> Result<()> {
        let (mut client, mut server) = connected_loopback_peers(CongestionMode::IpTunnel, 24.0)?;
        poll_idle(&mut client, &mut server, Duration::from_millis(150))?;
        let now = Instant::now();
        server.path_mtu.too_large(now);
        server.pacer_at = now;
        server.pacer_bytes = 6_000.0;
        assert!(server.admit_cost_with_reserve(1_000, CAMERA_COVER_IP_RESERVE));
        for id in 0..3 {
            let ip = large_packet(SERVER_TUN_IP, CLIENT_TUN_IP, id);
            assert!(server.can_send_ip(ip.len()));
            server.send_ip(ip)?;
        }
        flush_loopback_egress(&mut server)?;
        for id in 0..3 {
            assert_eq!(
                wait_datagram(&mut client)?,
                large_packet(SERVER_TUN_IP, CLIENT_TUN_IP, id)
            );
        }
        assert_eq!(server.stats.drops.total() + client.stats.drops.total(), 0);

        server.bitrate_mbps = 1.0;
        server.pacer_bytes = 4_800.0;
        assert!(!server.admit_cost_with_reserve(1_000, CAMERA_COVER_IP_RESERVE));
        assert_eq!(server.pacer_bytes, 4_800.0);
        Ok(())
    }

    #[test]
    fn camera_cover_is_authenticated_but_only_ip_reaches_tun() -> Result<()> {
        let (mut client, mut server) = connected_loopback_peers(CongestionMode::IpTunnel, 100.0)?;
        poll_idle(&mut client, &mut server, Duration::from_millis(150))?;
        let now = Instant::now();
        assert!(server.camera_cover.is_none());
        server.enter_tun(now);
        client.enter_tun(now);
        assert!(server.camera_cover.is_some());
        assert!(client.camera_cover.is_none());
        let authenticated_before = client.stats.rtp_rx_authenticated;
        assert!(!server.send_camera_cover(now + RTP_FRAME_SPAN, true)?);
        assert_eq!(server.stats.camera_cover_skipped, 1);
        poll_idle(&mut client, &mut server, RTP_FRAME_SPAN * 2)?;
        assert!(server.send_camera_cover(Instant::now(), false)?);
        flush_loopback_egress(&mut server)?;
        client.poll()?;
        assert!(client.stats.rtp_rx_authenticated > authenticated_before);
        assert!(client.incoming.is_empty());
        assert_eq!(client.stats.rtp_rx_invalid_frame, 0);
        assert_eq!(server.stats.camera_cover_packets, 1);
        assert_eq!(server.stats.camera_cover_send_failures, 0);

        let small = packet(SERVER_TUN_IP, CLIENT_TUN_IP, 8);
        server.send_ip(small.clone())?;
        flush_loopback_egress(&mut server)?;
        let now = Instant::now();
        server.camera_cover.as_mut().unwrap().next_frame = now;
        let after_small = server.stats.udp_tx_ipv4_bytes;
        assert!(
            server.send_camera_cover(now, false)?,
            "small IP packet must leave a fillable deficit with credit {} and {} pending RTP packets",
            server.pacer_bytes,
            server.native_pending.len()
        );
        flush_loopback_egress(&mut server)?;
        let cover_bytes = server.stats.udp_tx_ipv4_bytes - after_small;
        assert!(
            (1..1000).contains(&cover_bytes),
            "cover sent {cover_bytes} IPv4 bytes"
        );
        assert_eq!(wait_datagram(&mut client)?, small);

        let ip = large_packet(SERVER_TUN_IP, CLIENT_TUN_IP, 9);
        assert!(server.can_send_ip(ip.len()));
        server.send_ip(ip.clone())?;
        let next_slot = server.camera_cover.as_ref().unwrap().next_frame;
        assert!(!server.send_camera_cover(next_slot, false)?);
        flush_loopback_egress(&mut server)?;
        assert_eq!(wait_datagram(&mut client)?, ip);
        assert_eq!(server.stats.camera_cover_packets, 2);
        assert_eq!(server.stats.drops.total() + client.stats.drops.total(), 0);
        Ok(())
    }

    #[test]
    fn udp_backpressure_retries_identical_datagrams_in_order() -> Result<()> {
        let now = Instant::now();
        let mut queue = UdpEgress::default();
        let mut stats = Stats::default();
        let mut attempts = Vec::new();
        let mut send = |packet: &Transmit| {
            attempts.push((packet.destination.port(), packet.contents.to_vec()));
            match attempts.len() {
                1 => Err(ErrorKind::WouldBlock.into()),
                2 => Err(ErrorKind::Interrupted.into()),
                _ => Ok(packet.contents.len()),
            }
        };
        queue.submit(now, udp_packet(2001, vec![4, 5]), &mut stats, &mut send)?;
        queue.submit(now, udp_packet(2002, vec![6, 7, 8]), &mut stats, &mut send)?;
        assert!(queue.is_pending());
        assert_eq!(stats.udp_tx_bytes, 0);
        assert!(!queue.flush(now, &mut stats, |_| panic!("retry interval not reached"))?);
        assert!(queue.flush(now + Duration::from_millis(1), &mut stats, send)?);
        assert!(!queue.is_pending());
        assert_eq!(
            attempts,
            vec![
                (2001, vec![4, 5]),
                (2001, vec![4, 5]),
                (2001, vec![4, 5]),
                (2002, vec![6, 7, 8])
            ]
        );
        assert_eq!(stats.udp_send_would_block, 1);
        assert_eq!(stats.udp_send_interruptions, 1);
        assert_eq!(stats.udp_pending_sent, 2);
        assert_eq!(stats.udp_tx_bytes, 5);
        assert_eq!(stats.drops.total(), 0);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn udp_enobufs_retries_the_same_datagram() -> Result<()> {
        let now = Instant::now();
        let mut queue = UdpEgress::default();
        let mut stats = Stats::default();
        let contents = vec![4, 5];
        let mut attempts = Vec::new();
        let mut send = |packet: &Transmit| {
            attempts.push((packet.destination.port(), packet.contents.to_vec()));
            if attempts.len() == 1 {
                Err(io::Error::from_raw_os_error(libc::ENOBUFS))
            } else {
                Ok(packet.contents.len())
            }
        };
        queue.submit(
            now,
            udp_packet(2001, contents.clone()),
            &mut stats,
            &mut send,
        )?;
        assert!(queue.is_pending());
        assert_eq!(stats.udp_tx_bytes, 0);
        assert!(queue.flush(now + UDP_RETRY_INTERVAL, &mut stats, send)?);
        assert!(!queue.is_pending());
        assert_eq!(attempts, [(2001, contents.clone()), (2001, contents)]);
        assert_eq!(stats.udp_send_no_buffer, 1);
        assert_eq!(stats.udp_send_would_block, 0);
        assert_eq!(stats.udp_pending_sent, 1);
        Ok(())
    }

    #[test]
    fn udp_backpressure_bounds_packets_bytes_and_age() -> Result<()> {
        let now = Instant::now();
        let mut queue = UdpEgress::default();
        let mut stats = Stats::default();
        let block = |_: &Transmit| Err(ErrorKind::WouldBlock.into());
        for _ in 0..=MAX_PENDING_UDP_PACKETS {
            queue.submit(now, udp_packet(2001, vec![1]), &mut stats, block)?;
        }
        assert_eq!(stats.udp_pending_peak_packets, MAX_PENDING_UDP_PACKETS);
        assert_eq!(stats.drops.udp_pending_full, 1);
        assert!(
            !queue.flush(now + MAX_PENDING_UDP_AGE, &mut stats, |_| panic!(
                "expired packets must not be sent"
            ))?
        );
        assert_eq!(
            stats.drops.udp_pending_expired,
            MAX_PENDING_UDP_PACKETS as u64
        );

        let now = now + MAX_PENDING_UDP_AGE;
        // These datagrams reach the byte cap before the packet cap.
        for id in 0..3u8 {
            queue.submit(
                now,
                udp_packet(2002, vec![id; MAX_PENDING_UDP_BYTES / 2]),
                &mut stats,
                block,
            )?;
        }
        assert_eq!(stats.udp_pending_peak_bytes, MAX_PENDING_UDP_BYTES);
        assert_eq!(stats.drops.udp_pending_full, 2);
        let mut ids = Vec::new();
        assert!(queue.flush(now + UDP_RETRY_INTERVAL, &mut stats, |packet| {
            ids.push(packet.contents[0]);
            Ok(packet.contents.len())
        })?);
        assert_eq!(ids, [0, 1]);
        assert_eq!(queue.bytes, 0);
        Ok(())
    }

    fn config(server: bool) -> TunnelConfig {
        let (local_ip, peer_ip) = if server {
            (SERVER_TUN_IP, CLIENT_TUN_IP)
        } else {
            (CLIENT_TUN_IP, SERVER_TUN_IP)
        };
        TunnelConfig {
            local_ip,
            peer_ip,
            mtu: DEFAULT_MTU,
            max_mbps: DEFAULT_MAX_MBPS,
            congestion: CongestionMode::NativeTwcc,
        }
    }

    fn packet(source: Ipv4Addr, destination: Ipv4Addr, id: u8) -> Vec<u8> {
        let mut data = vec![0u8; 52];
        data[0] = 0x45;
        data[3] = 52;
        data[5] = id;
        data[8] = 64;
        data[9] = 17;
        data[12..16].copy_from_slice(&source.octets());
        data[16..20].copy_from_slice(&destination.octets());
        data
    }

    fn large_packet(source: Ipv4Addr, destination: Ipv4Addr, id: u8) -> Vec<u8> {
        let mut data = packet(source, destination, id);
        data.resize(usize::from(DEFAULT_MTU), id);
        data[2..4].copy_from_slice(&DEFAULT_MTU.to_be_bytes());
        data
    }

    #[test]
    fn invalid_packets_cannot_reach_tun() {
        let destination = Ipv4Addr::new(8, 8, 8, 8);
        let valid = packet(CLIENT_TUN_IP, destination, 1);
        assert!(Role::Server.valid_packet(config(true), &valid, true));
        let spoofed = packet(Ipv4Addr::new(10, 203, 0, 3), destination, 2);
        assert!(!Role::Server.valid_packet(config(true), &spoofed, true));
        assert!(!Role::Client.valid_packet(config(false), &valid, true));
        assert!(ipv4_addresses(&valid[..51], DEFAULT_MTU).is_none());
        for (index, value) in [(0, 0x64), (0, 0x44), (6, 0x80), (8, 0)] {
            let mut malformed = valid.clone();
            malformed[index] = value;
            assert!(ipv4_addresses(&malformed, DEFAULT_MTU).is_none());
        }
    }

    #[test]
    fn fragment_reassembly_handles_reordering_and_bounds_unfinished_packets() -> Result<()> {
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        let packet = large_packet(CLIENT_TUN_IP, Ipv4Addr::new(1, 1, 1, 1), 17);
        let mut head = vec![0];
        head.extend_from_slice(&packet[..FIRST_FRAGMENT_BYTES]);
        let mut tail = vec![1];
        tail.extend_from_slice(&packet[FIRST_FRAGMENT_BYTES..]);
        assert!(reassembly.push(1, &tail, DEFAULT_MTU, now)?.0.is_none());
        assert_eq!(reassembly.push(1, &head, DEFAULT_MTU, now)?.0, Some(packet));
        assert!(reassembly.push(2, &[7, 1, 2], DEFAULT_MTU, now).is_err());
        assert!(reassembly.push(2, &[1, 1], DEFAULT_MTU, now).is_err());
        assert!(reassembly.push(2, &head, 1000, now).is_err());
        for id in 2..=MAX_REASSEMBLIES as u32 + 2 {
            assert!(reassembly.push(id, &tail, DEFAULT_MTU, now)?.0.is_none());
        }
        assert_eq!(reassembly.0.len(), MAX_REASSEMBLIES);
        assert_eq!(
            reassembly.expire(now + REASSEMBLY_AGE),
            MAX_REASSEMBLIES as u64
        );
        assert!(reassembly.0.is_empty());
        Ok(())
    }

    #[test]
    fn failed_signaling_listener_cannot_interrupt_media() {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(sender);
        assert!(replacement(Some(&receiver)).is_none());
    }

    #[test]
    fn http_closes_before_encrypted_media_and_replacement_can_reconnect() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let SocketAddr::V4(signaling) = listener.local_addr()? else {
            bail!("not IPv4")
        };
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        configure_media_socket_buffers(&socket, UDP_BUFFER_REQUEST);
        let SocketAddr::V4(public) = socket.local_addr()? else {
            bail!("not IPv4")
        };
        let peers = listen_for_peers(
            listener,
            signaling::test_token(),
            socket,
            public,
            config(true),
        )?;
        let connect = || {
            negotiate_client(signaling, config(false), IceStartup::Direct, |offer| {
                signaling::exchange_loopback(signaling, &offer)
            })
        };
        let mut client = connect()?;
        let mut server = peers.recv_timeout(Duration::from_secs(2))?;
        activate_test_peers(&mut client, &mut server)?;
        let internet = Ipv4Addr::new(1, 1, 1, 1);
        let request = large_packet(CLIENT_TUN_IP, internet, 1);
        let response = packet(internet, CLIENT_TUN_IP, 2);
        client.send_ip(request.clone())?;
        flush_loopback_egress(&mut client)?;
        assert_eq!(wait_datagram(&mut server)?, request);
        server.send_ip(response.clone())?;
        flush_loopback_egress(&mut server)?;
        assert_eq!(wait_datagram(&mut client)?, response);

        // A valid token alone cannot replace an established media peer.
        assert!(signaling::exchange_loopback::<SessionAnswer>(signaling, &"malformed").is_err());
        assert!(replacement(Some(&peers)).is_none());
        client.send_ip(request.clone())?;
        flush_loopback_egress(&mut client)?;
        assert_eq!(wait_datagram(&mut server)?, request);

        // The old client is still alive and the encrypted liveness deadline
        // has not elapsed. Only the replacement owns UDP reception now.
        let mut next_client = connect()?;
        server = peers.recv_timeout(Duration::from_secs(2))?;
        activate_test_peers(&mut next_client, &mut server)?;
        next_client.send_ip(request.clone())?;
        flush_loopback_egress(&mut next_client)?;
        assert_eq!(wait_datagram(&mut server)?, request);
        Ok(())
    }

    #[test]
    fn arrival_feedback_stays_live_across_idle_and_resumes_data_without_padding() -> Result<()> {
        let (mut client, mut server) =
            connected_loopback_peers(CongestionMode::ArrivalFeedback, DEFAULT_MAX_MBPS)?;
        let idle_tx = client.stats.udp_tx_bytes;
        poll_idle(&mut client, &mut server, Duration::from_millis(1250))?;
        assert!(client.stats.udp_tx_bytes - idle_tx < 16 * 1024);
        assert_eq!(client.stats.rtp_padding_tx_bytes, 0);
        assert_eq!(server.stats.rtp_padding_tx_bytes, 0);
        assert!(client.feedback_updates() >= 4);
        assert!(
            client.bitrate_mbps >= 1.0,
            "idle rate {} Mbps",
            client.bitrate_mbps
        );

        let target = Ipv4Addr::new(1, 1, 1, 1);
        let deadline = Instant::now() + Duration::from_millis(600);
        let mut sent = 0u8;
        let mut received = 0u8;
        while received < 32 {
            ensure!(
                Instant::now() < deadline,
                "paced data did not resume after idle"
            );
            client.poll()?;
            server.poll()?;
            while let Some((_, packet)) = server.incoming.pop_front() {
                assert_eq!(packet, large_packet(CLIENT_TUN_IP, target, received));
                received += 1;
            }
            while sent < 32 && client.can_send_ip(usize::from(DEFAULT_MTU)) {
                client.send_ip(large_packet(CLIENT_TUN_IP, target, sent))?;
                sent += 1;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(client.stats.drops.total(), 0);
        assert_eq!(server.stats.drops.total(), 0);
        Ok(())
    }

    #[test]
    fn default_ip_tunnel_adapts_each_direction_independently() -> Result<()> {
        let mut client_config = config(false);
        client_config.congestion = CongestionMode::IpTunnel;
        client_config.max_mbps = UNLIMITED_MBPS;
        let mut server_config = config(true);
        server_config.congestion = CongestionMode::IpTunnel;
        server_config.max_mbps = UNLIMITED_MBPS;
        let (mut client, mut server) = loopback_peers(client_config, server_config)?;
        client.enter_tun(Instant::now());
        server.enter_tun(Instant::now());
        let starting_rate = client.bitrate_mbps;
        assert!(client.stats.adaptive_pacing_mbps.is_some());
        assert_eq!(server.stats.adaptive_pacing_mbps, Some(starting_rate));
        let target = Ipv4Addr::new(192, 0, 2, 1);
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut id = 0u8;
        while client.stats.adaptive_pacing_updates == 0 && Instant::now() < deadline {
            client.poll()?;
            server.poll()?;
            server.incoming.clear();
            for _ in 0..MAX_IO_BATCH {
                if !client.can_send_ip(usize::from(DEFAULT_MTU)) {
                    client.note_backlog(true);
                    break;
                }
                client.send_ip(large_packet(CLIENT_TUN_IP, target, id))?;
                id = id.wrapping_add(1);
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(client.bitrate_mbps > starting_rate);
        assert!(server.stats.delivery_ack_reports_generated > 0);
        assert!(server.bitrate_mbps <= starting_rate);
        Ok(())
    }

    #[test]
    fn delivery_feedback_observes_authenticated_bulk_without_changing_the_rate() -> Result<()> {
        let ceiling = 6.0;
        let (mut client, mut server) = connected_loopback_peers(CongestionMode::IpTunnel, ceiling)?;
        client.enter_tun(Instant::now());
        server.enter_tun(Instant::now());
        assert!(client.delivery.is_some() && server.delivery.is_some());
        assert!(client.delivery_receiver.is_some() && server.delivery_receiver.is_some());
        poll_idle(&mut client, &mut server, Duration::from_millis(300))?;
        assert_eq!(client.stats.delivery_reports_generated, 0);
        assert_eq!(server.stats.delivery_reports_generated, 0);
        assert_eq!(client.stats.delivery_ack_reports_generated, 0);
        assert_eq!(server.stats.delivery_ack_reports_generated, 0);

        let target = Ipv4Addr::new(1, 1, 1, 1);
        let until = Instant::now() + Duration::from_millis(1_050);
        let mut id = 0u8;
        while Instant::now() < until {
            client.poll()?;
            server.poll()?;
            server.incoming.clear();
            while client.can_send_ip(usize::from(DEFAULT_MTU)) {
                client.send_ip(large_packet(CLIENT_TUN_IP, target, id))?;
                id = id.wrapping_add(1);
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(client.stats.delivery_report_samples >= 2);
        assert!(client.stats.delivery_arrived_ipv4_kbps > 1_000);
        let sample = client
            .stats
            .delivery_matched_sample
            .context("matched delivery sample")?;
        assert!(sample.sent_packets > 1 && sample.received_packets > 0);
        assert!(sample.received_packets <= sample.sent_packets);
        assert!(sample.received_bytes <= sample.sent_bytes);
        assert!(sample.span_ms > 0);
        assert_eq!(client.stats.delivery_ack_reports_generated, 0);
        assert_eq!(client.bitrate_mbps, ceiling);
        assert_eq!(server.bitrate_mbps, ceiling);
        Ok(())
    }

    #[test]
    fn ip_tunnel_idles_without_padding_and_paces_bidirectional_mtu_packets() -> Result<()> {
        let ceiling = 0.2;
        let (mut client, mut server) = connected_loopback_peers(CongestionMode::IpTunnel, ceiling)?;
        let client_idle_tx = client.stats.udp_tx_bytes;
        let server_idle_tx = server.stats.udp_tx_bytes;
        poll_idle(&mut client, &mut server, Duration::from_millis(1100))?;
        assert!(client.stats.udp_tx_bytes - client_idle_tx < 8 * 1024);
        assert!(server.stats.udp_tx_bytes - server_idle_tx < 8 * 1024);
        assert_eq!(
            client.stats.rtp_padding_tx_bytes + server.stats.rtp_padding_tx_bytes,
            0
        );
        assert_eq!(client.feedback_updates() + server.feedback_updates(), 0);

        let target = Ipv4Addr::new(1, 1, 1, 1);
        let count = 12u8;
        let mut client_sent = 0u8;
        let mut server_sent = 0u8;
        let mut client_received = 0u8;
        let mut server_received = 0u8;
        let started = Instant::now();
        while client_received < count || server_received < count {
            ensure!(
                started.elapsed() < Duration::from_secs(3),
                "paced TUN datagrams timed out"
            );
            client.poll()?;
            server.poll()?;
            while let Some((_, packet)) = server.incoming.pop_front() {
                assert_eq!(packet, large_packet(CLIENT_TUN_IP, target, server_received));
                server_received += 1;
            }
            while let Some((_, packet)) = client.incoming.pop_front() {
                assert_eq!(packet, large_packet(target, CLIENT_TUN_IP, client_received));
                client_received += 1;
            }
            while client_sent < count && client.can_send_ip(usize::from(DEFAULT_MTU)) {
                client.send_ip(large_packet(CLIENT_TUN_IP, target, client_sent))?;
                client_sent += 1;
            }
            while server_sent < count && server.can_send_ip(usize::from(DEFAULT_MTU)) {
                server.send_ip(large_packet(target, CLIENT_TUN_IP, server_sent))?;
                server_sent += 1;
            }
            thread::sleep(Duration::from_millis(1));
        }
        // At 200 kbit/s, even allowing the initial burst, this amount of
        // inner traffic cannot be admitted immediately.
        assert!(started.elapsed() >= Duration::from_millis(380));
        assert_eq!(client.bitrate_mbps, ceiling);
        assert_eq!(server.bitrate_mbps, ceiling);
        assert_eq!(client.stats.drops.total() + server.stats.drops.total(), 0);
        Ok(())
    }

    #[test]
    fn ip_tunnel_probes_wide_size_in_both_directions_and_falls_back() -> Result<()> {
        let (mut client, mut server) =
            connected_loopback_peers(CongestionMode::IpTunnel, DEFAULT_MAX_MBPS)?;
        poll_idle(&mut client, &mut server, Duration::from_millis(100))?;
        assert!(client.path_mtu.wide() && server.path_mtu.wide());
        assert_eq!(
            (client.stats.mtu_probes_acked, server.stats.mtu_probes_acked),
            (1, 1)
        );

        let target = Ipv4Addr::new(1, 1, 1, 1);
        let packet = large_packet(CLIENT_TUN_IP, target, 1);
        let next_rtp_seq = client.rtp_seq;
        let udp_tx_bytes = client.stats.udp_tx_bytes;
        client.send_ip(packet.clone())?;
        flush_loopback_egress(&mut client)?;
        assert_eq!(client.rtp_seq, next_rtp_seq + 1);
        let udp_payload_bytes = client.stats.udp_tx_bytes - udp_tx_bytes;
        assert!(udp_payload_bytes >= u64::from(DEFAULT_MTU));
        assert!(udp_payload_bytes + 20 + 8 <= 1400);
        assert_eq!(wait_datagram(&mut server)?, packet);

        server.path_mtu.too_large(Instant::now());
        assert!(client.path_mtu.wide());
        assert!(!server.path_mtu.wide());
        let packet = large_packet(target, CLIENT_TUN_IP, 2);
        let next_rtp_seq = server.rtp_seq;
        server.send_ip(packet.clone())?;
        flush_loopback_egress(&mut server)?;
        assert_eq!(server.rtp_seq, next_rtp_seq + 2);
        assert_eq!(wait_datagram(&mut client)?, packet);
        Ok(())
    }

    #[test]
    fn grouped_rtp_uses_one_marker_and_preserves_packet_delivery() -> Result<()> {
        let (mut client, mut server) =
            connected_loopback_peers(CongestionMode::IpTunnel, DEFAULT_MAX_MBPS)?;
        poll_idle(&mut client, &mut server, Duration::from_millis(100))?;
        let target = Ipv4Addr::new(1, 1, 1, 1);
        let markers = client.stats.rtp_tx_markers;
        let packets = client.stats.rtp_tx_packets;
        client.send_ip(packet(CLIENT_TUN_IP, target, 1))?;
        client.grouped_frame.as_mut().unwrap().frame_end = Instant::now() + Duration::from_secs(1);
        for id in 2..=3 {
            client.send_ip(packet(CLIENT_TUN_IP, target, id))?;
        }
        flush_loopback_egress(&mut client)?;
        assert_eq!(client.stats.rtp_tx_packets - packets, 3);
        assert_eq!(client.stats.rtp_tx_markers, markers);
        for id in 1..=3 {
            assert_eq!(
                wait_datagram(&mut server)?,
                packet(CLIENT_TUN_IP, target, id)
            );
        }
        client.finish_group()?;
        flush_loopback_egress(&mut client)?;
        assert_eq!(client.stats.rtp_tx_packets - packets, 4);
        assert_eq!(client.stats.rtp_tx_markers - markers, 1);
        Ok(())
    }

    #[test]
    fn encrypted_edge_rtp_burst_delivery() -> Result<()> {
        const PACKETS: std::ops::RangeInclusive<u8> = 1..=64;
        const BURST: std::ops::Range<u8> = 9..47;

        let clean = replay_wide_rtp_burst(PACKETS, None, true, &[])?;
        assert_eq!(clean, PACKETS.collect::<Vec<_>>());

        let impaired = replay_wide_rtp_burst(PACKETS, Some(BURST), false, &[])?;
        let expected: Vec<_> = clean
            .iter()
            .copied()
            .filter(|id| !BURST.contains(id))
            .collect();
        assert_eq!(impaired, expected, "delivered IP packets without repair");

        let mut recovered = replay_wide_rtp_burst(PACKETS, Some(BURST), true, &[])?;
        assert_eq!(recovered.get(8), Some(&47), "later packets pass the gap");
        recovered.sort_unstable();
        assert_eq!(
            recovered, clean,
            "exactly one delivery for every inner packet"
        );
        let mut recovered_tail = replay_wide_rtp_burst(PACKETS, Some(27..65), true, &[])?;
        recovered_tail.sort_unstable();
        assert_eq!(
            recovered_tail, clean,
            "recover loss at the tail of the burst"
        );
        let mut recovered_first = replay_wide_rtp_burst(PACKETS, Some(1..39), true, &[])?;
        assert_eq!(recovered_first.first(), Some(&39));
        recovered_first.sort_unstable();
        assert_eq!(
            recovered_first, clean,
            "recover loss at the start of the burst"
        );
        // A later VPS edge trace observed a 51-packet run of missing RTP.
        let mut recovered_longer = replay_wide_rtp_burst(PACKETS, Some(9..60), true, &[])?;
        recovered_longer.sort_unstable();
        assert_eq!(recovered_longer, clean, "recover the longer measured burst");
        Ok(())
    }

    #[test]
    fn encrypted_edge_retries_after_feedback_and_repair_losses() -> Result<()> {
        for lost_flows in [
            [REPAIR_REQUEST_FLOW].as_slice(),
            [REPAIRED_DATA_FLOW].as_slice(),
            [REPAIR_REQUEST_FLOW, REPAIRED_DATA_FLOW].as_slice(),
        ] {
            let mut delivered = replay_wide_rtp_burst(1..=8, Some(3..4), true, lost_flows)?;
            assert_eq!(&delivered[..3], &[1, 2, 4], "later packets pass the gap");
            delivered.sort_unstable();
            assert_eq!(
                delivered,
                (1..=8).collect::<Vec<_>>(),
                "lost flows {lost_flows:?}"
            );
        }
        Ok(())
    }

    // The WAN summary gives a longest gap of 38 but no packet offsets. This
    // replays that gap on loopback and does not model WAN RTT, pacing, or TCP.
    fn replay_wide_rtp_burst(
        ids: std::ops::RangeInclusive<u8>,
        burst: Option<std::ops::Range<u8>>,
        repair_enabled: bool,
        lost_repair_flows: &[u32],
    ) -> Result<Vec<u8>> {
        let (mut client, mut server) =
            connected_loopback_peers(CongestionMode::IpTunnel, DEFAULT_MAX_MBPS)?;
        if !repair_enabled {
            client.repair = None;
            server.repair = None;
        }
        poll_idle(&mut client, &mut server, Duration::from_millis(100))?;
        assert!(server.path_mtu.wide());
        let now = Instant::now();
        server.enter_tun(now);
        server.camera_cover.as_mut().unwrap().next_frame = now;
        let authenticated = client.stats.rtp_rx_authenticated;
        assert!(server.send_camera_cover(now, false)?);
        flush_loopback_egress(&mut server)?;
        assert_eq!(server.stats.camera_cover_packets, 1);
        let deadline = Instant::now() + Duration::from_secs(1);
        while client.stats.rtp_rx_authenticated == authenticated {
            ensure!(
                Instant::now() < deadline,
                "encrypted camera cover timed out"
            );
            client.poll()?;
            client.sleep_until_work();
        }
        assert!(client.incoming.is_empty());
        if lost_repair_flows.contains(&REPAIR_REQUEST_FLOW) {
            client.drop_rtp_flow_once = Some(REPAIR_REQUEST_FLOW);
        }
        if lost_repair_flows.contains(&REPAIRED_DATA_FLOW) {
            server.drop_rtp_flow_once = Some(REPAIRED_DATA_FLOW);
        }

        let first_id = *ids.start();
        let first_sequence = server.rtp_seq;
        let mut received = Vec::new();
        for id in ids {
            if burst.as_ref().is_some_and(|range| range.contains(&id)) {
                let sequence = first_sequence + u64::from(id - first_id);
                assert_eq!(
                    server.rtp_seq, sequence,
                    "burst sequences must be consecutive"
                );
                server.drop_rtp_once = Some(sequence as u16);
            }
            server.send_ip(large_packet(SERVER_TUN_IP, CLIENT_TUN_IP, id))?;
            if id == first_id {
                // Keep the primary sequence contiguous even if the test thread
                // pauses. The separate frame-end packet remains on the wire.
                server.grouped_frame.as_mut().unwrap().frame_end =
                    Instant::now() + Duration::from_secs(1);
            }
            flush_loopback_egress(&mut server)?;
            assert!(
                server.drop_rtp_once.is_none(),
                "failed to drop IP packet {id}"
            );
            client.poll()?;
            received.extend(client.incoming.drain(..).map(|(_, packet)| packet));
        }
        server.finish_group()?;
        let until = Instant::now() + Duration::from_millis(150);
        while Instant::now() < until {
            client.poll()?;
            server.poll()?;
            received.extend(client.incoming.drain(..).map(|(_, packet)| packet));
            thread::sleep(Duration::from_millis(1));
        }
        if repair_enabled {
            let expected = burst.as_ref().map_or(0, |range| range.len() as u64);
            let lost_repair = u64::from(lost_repair_flows.contains(&REPAIRED_DATA_FLOW));
            let sent = server.stats.repair_packets_sent;
            // The loopback scheduler can delay feedback long enough to trigger one retry.
            assert!(
                (expected + lost_repair..=2 * expected).contains(&sent),
                "burst {burst:?}: sent {sent} repairs for {expected} missing packets"
            );
            assert_eq!(client.stats.repair_packets_received, expected);
        }
        assert!(client.drop_rtp_flow_once.is_none() && server.drop_rtp_flow_once.is_none());
        assert!(client.drop_rtp_once.is_none() && server.drop_rtp_once.is_none());
        assert_eq!(server.stats.drops.total() + client.stats.drops.total(), 0);
        assert_eq!(client.stats.rtp_rx_invalid_frame, 0);

        Ok(received
            .into_iter()
            .map(|packet| {
                let id = packet[5];
                assert!(
                    packet == large_packet(SERVER_TUN_IP, CLIENT_TUN_IP, id),
                    "corrupted inner IP packet {id}"
                );
                id
            })
            .collect())
    }

    #[test]
    fn udp_burst_waits_in_socket_when_tun_delivery_queue_fills() -> Result<()> {
        let (mut client, mut server) = connected_loopback_peers(CongestionMode::IpTunnel, 100.0)?;
        let target = Ipv4Addr::new(1, 1, 1, 1);
        let count = MAX_PACKET_QUEUE + 12;
        for id in 0..count {
            // Construct a receive burst independent of the ordinary egress pacer.
            client.send_ip(packet(CLIENT_TUN_IP, target, id as u8))?;
        }
        flush_loopback_egress(&mut client)?;

        server.poll()?;
        assert_eq!(server.incoming.len(), MAX_PACKET_QUEUE);
        assert_eq!(server.stats.drops.incoming_queue_full, 0);
        for id in 0..count {
            if server.incoming.is_empty() {
                server.poll()?;
            }
            let (_, bytes) = server
                .incoming
                .pop_front()
                .context("missing datagram from UDP burst")?;
            assert_eq!(bytes, packet(CLIENT_TUN_IP, target, id as u8));
        }
        assert!(server.incoming.is_empty());
        assert_eq!(server.stats.drops.total(), 0);
        Ok(())
    }

    #[test]
    fn control_only_peer_reaches_probe_echo_behind_unsolicited_data() -> Result<()> {
        let (mut client, mut server) = connected_loopback_peers(CongestionMode::IpTunnel, 100.0)?;
        server.ip_ingress = IpIngress::ControlOnly;
        let target = Ipv4Addr::new(1, 1, 1, 1);
        for id in 0..(MAX_PACKET_QUEUE + 12) {
            client.send_ip(packet(CLIENT_TUN_IP, target, id as u8))?;
        }
        let sequence = 4321;
        server.probes.push_back((sequence, Instant::now()));
        client.send_frame(Frame {
            kind: Kind::Datagram,
            flow: ECHO_FLOW,
            sequence,
            payload: PROBE_BODY.to_vec(),
        })?;
        flush_loopback_egress(&mut client)?;

        server.poll()?;
        assert!(server.incoming.is_empty());
        assert!(!server.probes.iter().any(|(seq, _)| *seq == sequence));
        assert_eq!(server.stats.drops.total(), 0);
        Ok(())
    }

    fn flush_loopback_egress(peer: &mut Peer) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !peer.native_pending.is_empty() || peer.udp_egress.is_pending() {
            ensure!(
                Instant::now() < deadline,
                "burst did not reach the loopback socket"
            );
            peer.poll()?;
            peer.sleep_until_work();
        }
        Ok(())
    }

    fn connected_loopback_peers(mode: CongestionMode, max_mbps: f64) -> Result<(Peer, Peer)> {
        let mut server_config = config(true);
        server_config.congestion = mode;
        server_config.max_mbps = max_mbps;
        let mut client_config = config(false);
        client_config.congestion = mode;
        client_config.max_mbps = max_mbps;
        loopback_peers(client_config, server_config)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn peer_creation_preserves_shared_socket_buffers() -> Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        let SocketAddr::V4(local) = socket.local_addr()? else {
            bail!("not IPv4");
        };
        let socket_ref = SockRef::from(&socket);
        // Use a smaller request so the test also works with a low host rmem_max.
        socket_ref.set_recv_buffer_size(16 * 1024)?;
        socket_ref.set_send_buffer_size(16 * 1024)?;
        let receive_size = socket_ref.recv_buffer_size()?;
        let send_size = socket_ref.send_buffer_size()?;
        for _ in 0..2 {
            let peer = Peer::new(
                socket.try_clone()?,
                local,
                local,
                Role::Server,
                config(true),
            )?;
            assert_eq!(peer.stats.udp_recv_buffer_bytes, receive_size);
            assert_eq!(peer.stats.udp_send_buffer_bytes, send_size);
            assert_eq!(socket_ref.recv_buffer_size()?, receive_size);
            assert_eq!(socket_ref.send_buffer_size()?, send_size);
        }
        Ok(())
    }

    #[test]
    fn binding_indication_retry_sends_stun_before_ice() -> Result<()> {
        let media = UdpSocket::bind("127.0.0.1:0")?;
        configure_media_socket_buffers(&media, UDP_BUFFER_REQUEST);
        media.set_read_timeout(Some(Duration::from_millis(250)))?;
        let SocketAddr::V4(public) = media.local_addr()? else {
            bail!("not IPv4");
        };
        let mut client_config = config(false);
        client_config.congestion = CongestionMode::IpTunnel;
        let mut server_config = config(true);
        server_config.congestion = CongestionMode::IpTunnel;
        let mut prepared = None;
        let mut client = negotiate_client(
            public,
            client_config,
            IceStartup::BindingIndication,
            |offer| {
                let (answer, server) = answer_offer(offer, &media, public, server_config)?;
                prepared = Some(server);
                Ok(answer)
            },
        )?;

        let mut bytes = [0; 2048];
        let (size, source) = media
            .recv_from(&mut bytes)
            .context("receive first media datagram")?;
        assert_eq!(source, SocketAddr::V4(client.local));
        assert_eq!(size, 28);
        assert_eq!(bytes[..2], [0, 0x11]);
        assert!(str0m::ice::StunMessage::parse(&bytes[..size]).is_ok());

        media.set_nonblocking(true)?;
        let mut server = prepared.context("server did not prepare a peer")?;
        assert!(!server.receive_media(source, &bytes[..size])?);
        activate_test_peers(&mut client, &mut server)
    }

    #[test]
    fn active_dtls_answer_keeps_ice_and_connects() -> Result<()> {
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        udp.set_nonblocking(true)?;
        let SocketAddr::V4(public) = udp.local_addr()? else {
            bail!("not IPv4");
        };
        let mut client_config = config(false);
        client_config.congestion = CongestionMode::IpTunnel;
        let mut server_config = config(true);
        server_config.congestion = CongestionMode::IpTunnel;
        let mut prepared = None;
        let mut client = negotiate_client(public, client_config, IceStartup::Direct, |offer| {
            let (answer, mut server) = answer_offer(offer, &udp, public, server_config)?;
            let text = answer.answer.to_sdp_string();
            assert!(text.contains("a=ice-lite"));
            assert!(text.contains("a=setup:active\r\n"));
            assert!(text.contains("a=fingerprint:"));
            // Even an initialized active DTLS peer cannot transmit without
            // an ICE-selected destination. No client input has arrived yet.
            server.poll_timers()?;
            assert_eq!(server.stats.udp_tx_bytes, 0);
            assert!(!server.ice_nominated);
            prepared = Some(server);
            Ok(answer)
        })?;
        let mut server = prepared.context("server not prepared")?;
        let mut buf = [0u8; 2048];
        let mut first_client_packet = true;
        let mut client_hello_from = None;
        let deadline = Instant::now() + Duration::from_secs(3);
        while client.last_echo.is_none() || server.last_echo.is_none() {
            ensure!(Instant::now() < deadline, "active DTLS answer timed out");
            client.poll_egress()?;
            client.poll_timers()?;
            server.poll_egress()?;
            server.poll_timers()?;
            for sender_is_client in [true, false] {
                loop {
                    let packet = if sender_is_client {
                        server.socket.recv_from(&mut buf)
                    } else {
                        client.socket.recv_from(&mut buf)
                    };
                    let (n, source) = match packet {
                        Ok(packet) => packet,
                        Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error.into()),
                    };
                    if sender_is_client && first_client_packet {
                        let stun = str0m::ice::StunMessage::parse(&buf[..n])?;
                        assert!(stun.is_binding_request());
                        first_client_packet = false;
                    }
                    // Initial ClientHello is a plaintext epoch-zero DTLS
                    // handshake record in both DTLS 1.2 and 1.3.
                    if n >= 25 && buf[0] == 22 && buf[3..5] == [0, 0] && buf[13] == 1 {
                        assert_eq!(
                            *client_hello_from.get_or_insert(sender_is_client),
                            sender_is_client
                        );
                    }
                    if sender_is_client {
                        server.receive_media(source, &buf[..n])?;
                    } else {
                        client.receive_media(source, &buf[..n])?;
                    }
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(client_hello_from, Some(false));
        assert!(client.rtc.is_connected() && server.rtc.is_connected());
        assert!(client.ice_nominated && server.ice_nominated);
        client.ip_ingress = IpIngress::Tun;
        server.ip_ingress = IpIngress::Tun;
        let up = packet(CLIENT_TUN_IP, SERVER_TUN_IP, 81);
        let down = packet(SERVER_TUN_IP, CLIENT_TUN_IP, 82);
        client.send_ip(up.clone())?;
        server.send_ip(down.clone())?;
        flush_loopback_egress(&mut client)?;
        flush_loopback_egress(&mut server)?;
        assert_eq!(wait_datagram(&mut server)?, up);
        assert_eq!(wait_datagram(&mut client)?, down);
        assert_eq!(client.stats.drops.total() + server.stats.drops.total(), 0);
        Ok(())
    }

    #[test]
    fn active_dtls_answer_preserves_non_actpass_setup() -> Result<()> {
        for remote_setup in ["active", "passive", "missing"] {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.set_nonblocking(true)?;
            let SocketAddr::V4(public) = socket.local_addr()? else {
                bail!("not IPv4")
            };
            let mut offerer = Rtc::builder()
                .clear_codecs()
                .enable_vp8(true)
                .build(Instant::now());
            offerer.add_local_candidate(Candidate::host(public.into(), "udp")?);
            let mut change = offerer.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
            let (offer, _) = change.apply().context("offer")?;
            let setup_line = if remote_setup == "missing" {
                String::new()
            } else {
                format!("a=setup:{remote_setup}\r\n")
            };
            let text = offer
                .to_sdp_string()
                .replace("a=setup:actpass\r\n", &setup_line);
            let request = SessionOffer {
                settings: SessionSettings::new(config(true), Role::Server),
                offer: SdpOffer::from_sdp_string(&text)?,
                delivery_feedback: None,
                delivery_ack: None,
                delivery_ack_timing: None,
                resume_ticket: None,
            };
            let (answer, server) = answer_offer(request, &socket, public, config(true))?;
            assert!(answer.delivery_feedback.is_none() && server.delivery.is_none());
            assert!(answer.delivery_ack.is_none() && server.delivery_receiver.is_none());
            let expected = if remote_setup == "passive" {
                "active"
            } else {
                "passive"
            };
            assert!(
                answer
                    .answer
                    .to_sdp_string()
                    .contains(&format!("a=setup:{expected}\r\n"))
            );
            assert_eq!(server.stats.udp_tx_bytes, 0);
        }
        Ok(())
    }

    fn loopback_peers(
        client_config: TunnelConfig,
        server_config: TunnelConfig,
    ) -> Result<(Peer, Peer)> {
        loopback_peers_with_ack(client_config, server_config, true, true)
    }

    fn loopback_peers_with_ack(
        client_config: TunnelConfig,
        server_config: TunnelConfig,
        accept_ack: bool,
        accept_timing: bool,
    ) -> Result<(Peer, Peer)> {
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        udp.set_nonblocking(true)?;
        configure_media_socket_buffers(&udp, UDP_BUFFER_REQUEST);
        let SocketAddr::V4(public) = udp.local_addr()? else {
            bail!("not IPv4")
        };
        let mut prepared = None;
        let mut client =
            negotiate_client(public, client_config, IceStartup::Direct, |mut offer| {
                if !accept_ack {
                    offer.delivery_ack = None;
                }
                if !accept_timing {
                    offer.delivery_ack_timing = None;
                }
                let (answer, server) = answer_offer(offer, &udp, public, server_config)?;
                prepared = Some(server);
                Ok(answer)
            })?;
        let mut server = prepared.context("server did not prepare a peer")?;
        activate_test_peers(&mut client, &mut server)?;
        Ok((client, server))
    }

    #[test]
    fn client_keeps_v1_with_server_that_ignores_matched_delivery() -> Result<()> {
        let mut client_config = config(false);
        let mut server_config = config(true);
        client_config.congestion = CongestionMode::IpTunnel;
        server_config.congestion = CongestionMode::IpTunnel;
        let (client, server) = loopback_peers_with_ack(client_config, server_config, false, false)?;
        for peer in [client, server] {
            assert!(peer.delivery.is_some());
            assert!(peer.delivery_receiver.is_none());
            assert!(peer.stats.delivery_sender.is_none());
        }
        Ok(())
    }

    #[test]
    fn adaptive_pacing_falls_back_if_the_peer_omits_timing() -> Result<()> {
        let client_config = TunnelConfig {
            congestion: CongestionMode::IpTunnel,
            max_mbps: UNLIMITED_MBPS,
            ..config(false)
        };
        let server_config = TunnelConfig {
            congestion: CongestionMode::IpTunnel,
            max_mbps: UNLIMITED_MBPS,
            ..config(true)
        };
        let mut client = loopback_peers_with_ack(client_config, server_config, true, false)?.0;
        client.enter_tun(Instant::now());
        assert!(client.delivery_receiver.is_some());
        assert!(client.adaptive_pacing.is_none());
        assert_eq!(client.bitrate_mbps, UNLIMITED_MBPS);
        Ok(())
    }

    fn activate_test_peers(client: &mut Peer, server: &mut Peer) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        while client.last_echo.is_none() || server.last_echo.is_none() {
            ensure!(
                Instant::now() < deadline,
                "encrypted probe handshake timed out"
            );
            client.poll()?;
            server.poll()?;
            thread::sleep(Duration::from_millis(1));
        }
        client.ip_ingress = IpIngress::Tun;
        server.ip_ingress = IpIngress::Tun;
        Ok(())
    }

    fn poll_idle(client: &mut Peer, server: &mut Peer, duration: Duration) -> Result<()> {
        let idle_until = Instant::now() + duration;
        while Instant::now() < idle_until {
            client.poll()?;
            server.poll()?;
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    fn wait_datagram(peer: &mut Peer) -> Result<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            peer.poll()?;
            if let Some((_, packet)) = peer.incoming.pop_front() {
                return Ok(packet);
            }
            ensure!(Instant::now() < deadline, "IPv4 datagram timed out");
            peer.sleep_until_work();
        }
    }
}
