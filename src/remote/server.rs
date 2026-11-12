use super::*;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};
use str0m::config::CryptoProvider;
use str0m::ice::{IceCreds, StunMessage};

const PEER_IO_BATCH: usize = 8;
// One socket queues inbound datagrams for all peers during scheduling pauses.
const SHARED_RECEIVE_BUFFER_REQUEST: usize = 2 * UDP_BUFFER_REQUEST;
const SERVICE_QUANTUM: usize = 2048;
const STUN_BURST: f64 = 12.0;
const STUN_PER_SECOND: f64 = 25.0;
const IDLE_WAIT: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 250_000,
};
type SessionTickets = Arc<Mutex<BTreeMap<Ipv4Addr, SessionTicket>>>;

fn permits_resume(
    tickets: &SessionTickets,
    identity: Ipv4Addr,
    requested: Option<SessionTicket>,
) -> bool {
    requested.is_none_or(|ticket| {
        tickets
            .lock()
            .expect("session tickets lock")
            .get(&identity)
            .is_none_or(|current| *current == ticket)
    })
}

#[cfg(test)]
#[test]
fn a_replaced_ticket_cannot_reclaim_an_authenticated_identity() {
    let tickets = SessionTickets::default();
    let identity = CLIENT_TUN_IP;
    let old = [1; 16];
    let new = [2; 16];
    assert!(permits_resume(&tickets, identity, Some(old)));
    tickets.lock().unwrap().insert(identity, old);
    assert!(permits_resume(&tickets, identity, Some(old)));
    assert!(permits_resume(&tickets, identity, None));
    tickets.lock().unwrap().insert(identity, new);
    assert!(!permits_resume(&tickets, identity, Some(old)));
    assert!(permits_resume(&tickets, identity, Some(new)));
}

pub fn serve_multi(
    signal: SocketAddr,
    credentials: &Path,
    public_ip: Ipv4Addr,
    udp_port: u16,
    config: TunnelConfig,
    status: Option<&Path>,
    tun_name: Option<&str>,
) -> Result<()> {
    config.validate()?;
    ensure!(
        signal.ip().is_loopback(),
        "signaling listener must be loopback"
    );
    if let Some(name) = tun_name {
        ensure!(
            (1..=13).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "TUN prefix must be 1..=13 ASCII letters, digits or hyphens"
        );
    }
    let public = SocketAddrV4::new(public_ip, udp_port);
    ensure!(
        valid_media_endpoint(public),
        "invalid advertised media endpoint"
    );
    let credentials = signaling::Credentials::load(credentials)?;
    ensure!(
        credentials.peer_ips().any(|ip| ip == config.peer_ip)
            && gateway(config.peer_ip) == config.local_ip,
        "configured TUN pair is missing from peer credentials"
    );
    let mut addresses = credentials.peer_ips().collect::<Vec<_>>();
    addresses.sort_unstable();
    if config.congestion == CongestionMode::IpTunnel {
        ensure!(
            config.max_mbps > addresses.len() as f64 * 0.24,
            "shared rate must exceed the camera idle rate of the provisioned peers"
        );
    }
    let listener = signaling::bind_listener(signal).context("bind loopback signaling listener")?;
    let signal_address = listener.local_addr()?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, udp_port))
        .context("bind shared media UDP listener")?;
    socket.set_nonblocking(true)?;
    configure_media_socket_buffers(&socket, SHARED_RECEIVE_BUFFER_REQUEST);
    let mut peers = BTreeMap::new();
    let prefix = tun_name.unwrap_or("sfera");
    for (index, ip) in addresses.into_iter().enumerate() {
        let name = format!("{prefix}{index}");
        let pair = TunnelConfig {
            local_ip: gateway(ip),
            peer_ip: ip,
            ..config
        };
        let tun = pair
            .make_named_device(true, Some(&name))
            .with_context(|| format!("create TUN {name} for {ip}"))?;
        peers.insert(
            ip,
            Slot {
                tun,
                active: None,
                pending: None,
            },
        );
        eprintln!("SFERA MEDIA: provisioned {ip} on {name}");
    }
    let tickets = SessionTickets::default();
    let offers = listen(
        listener,
        credentials,
        socket.try_clone()?,
        public,
        config,
        Arc::clone(&tickets),
    )?;
    let rate = if config.max_mbps == UNLIMITED_MBPS {
        "uncapped".to_owned()
    } else {
        format!("{:.3} Mbps", config.max_mbps)
    };
    eprintln!(
        "SFERA MEDIA: signaling {signal_address}, UDP {public}, {} provisioned peers, {rate} shared egress",
        peers.len(),
    );
    run(
        &socket,
        config.max_mbps,
        &mut peers,
        offers,
        status,
        tickets,
    )
}

fn gateway(peer: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(peer) - 1)
}

fn listen(
    listener: TcpListener,
    credentials: signaling::Credentials,
    socket: UdpSocket,
    public: SocketAddrV4,
    defaults: TunnelConfig,
    tickets: SessionTickets,
) -> Result<Receiver<Session>> {
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
                if let Some(session) =
                    signaling::handle_for_peer(stream, &credentials, |ip, offer: SessionOffer| {
                        if !permits_resume(&tickets, ip, offer.resume_ticket) {
                            return Err(signaling::SessionReplaced.into());
                        }
                        Session::prepare(
                            offer,
                            &socket,
                            public,
                            TunnelConfig {
                                local_ip: gateway(ip),
                                peer_ip: ip,
                                ..defaults
                            },
                        )
                    })
                    && send.send(session).is_err()
                {
                    return;
                }
            }
        })
        .context("start signaling listener")?;
    Ok(receive)
}

struct Session {
    peer: Peer,
    resume_ticket: Option<SessionTicket>,
    local_ice: IceCreds,
    remote_ufrag: String,
    source: Option<SocketAddr>,
    outgoing: StagedPackets,
    deficit: usize,
    stun_credit: f64,
    stun_at: Instant,
}

impl Session {
    fn prepare(
        request: SessionOffer,
        socket: &UdpSocket,
        public: SocketAddrV4,
        config: TunnelConfig,
    ) -> Result<(SessionAnswer, Self)> {
        let remote_ice = request
            .offer
            .session
            .ice_creds()
            .or_else(|| request.offer.media_lines.first()?.ice_creds())
            .context("missing remote ICE credentials")?;
        let resume_ticket = request.resume_ticket;
        let (mut answer, mut peer) = answer_offer(request, socket, public, config)?;
        let ticket = if let Some(ticket) = resume_ticket {
            ticket
        } else {
            let mut ticket = [0; 16];
            getrandom::fill(&mut ticket).context("generate SFERA session ticket")?;
            ticket
        };
        answer.session_ticket = Some(ticket);
        peer.session_ticket = Some(ticket);
        let local_ice = peer.rtc.direct_api().local_ice_credentials();
        let stun_at = peer.start;
        peer.ip_ingress = IpIngress::ControlOnly;
        Ok((
            answer,
            Self {
                peer,
                resume_ticket,
                local_ice,
                remote_ufrag: remote_ice.ufrag,
                source: None,
                outgoing: StagedPackets::new(config.congestion),
                deficit: 0,
                stun_credit: STUN_BURST,
                stun_at,
            },
        ))
    }

    fn matches_stun(&self, request: &StunMessage<'_>) -> bool {
        static CRYPTO: OnceLock<CryptoProvider> = OnceLock::new();
        request.split_username() == Some((&self.local_ice.ufrag, &self.remote_ufrag))
            && request.verify(self.local_ice.pass.as_bytes(), |key, payload| {
                CRYPTO
                    .get_or_init(str0m::crypto::from_feature_flags)
                    .sha1_hmac_provider
                    .sha1_hmac(key, payload)
            })
    }

    fn admit_stun(&mut self, now: Instant) -> bool {
        let refill = now.duration_since(self.stun_at).as_secs_f64() * STUN_PER_SECOND;
        self.stun_at = now;
        self.stun_credit = (self.stun_credit + refill).min(STUN_BURST);
        if self.stun_credit < 1.0 {
            return false;
        }
        self.stun_credit -= 1.0;
        true
    }

    fn flush_outgoing(&mut self, wire: &mut WireBudget) -> Result<bool> {
        let peer = &mut self.peer;
        let sent = peer.stats.udp_tx_ipv4_bytes;
        let result = peer.poll_repair(wire.available());
        wire.charge(peer.stats.udp_tx_ipv4_bytes - sent);
        let mut active = result?;
        self.deficit = (self.deficit + SERVICE_QUANTUM).min(2 * SERVICE_QUANTUM);
        if let Some(packet) = self.outgoing.front() {
            let fragments = if packet.len() > peer.data_limit() {
                2
            } else {
                1
            };
            let cost = peer.ip_admission_cost(packet.len(), fragments);
            if cost <= self.deficit && wire.permits_payload(cost) && peer.can_send_ip(packet.len())
            {
                let packet = self.outgoing.pop().expect("outgoing packet exists");
                wire.admit_payload(cost);
                let sent = peer.stats.udp_tx_ipv4_bytes;
                let result = peer.send_ip(packet);
                wire.charge(peer.stats.udp_tx_ipv4_bytes - sent);
                result?;
                self.deficit -= cost;
                active = true;
            }
        }
        let backlogged = !self.outgoing.is_empty();
        if !backlogged {
            self.deficit = 0;
        }
        peer.note_backlog(backlogged);
        if peer.camera_cover.is_some() {
            let sent = peer.stats.udp_tx_ipv4_bytes;
            let result = peer.send_camera_cover(
                Instant::now(),
                backlogged || !wire.permits(CAMERA_MAX_IPV4_BYTES_PER_SLOT as usize),
            );
            wire.charge(peer.stats.udp_tx_ipv4_bytes - sent);
            active |= result?;
        }
        Ok(active)
    }
}

struct WireBudget {
    bytes_per_second: f64,
    burst: f64,
    credit: f64,
    payload_credit: f64,
    updated: Instant,
}

impl WireBudget {
    fn new(mbps: f64, now: Instant) -> Self {
        let bytes_per_second = mbps * 125_000.0;
        let burst = if mbps == UNLIMITED_MBPS {
            f64::INFINITY
        } else {
            (bytes_per_second * 0.001).clamp(2.0 * SERVICE_QUANTUM as f64, 32_000.0)
        };
        Self {
            bytes_per_second,
            burst,
            credit: burst,
            payload_credit: burst,
            updated: now,
        }
    }

    fn refresh(&mut self, now: Instant) {
        if self.bytes_per_second.is_infinite() {
            return;
        }
        let refill = now.duration_since(self.updated).as_secs_f64() * self.bytes_per_second;
        self.credit = (self.credit + refill).min(self.burst);
        self.payload_credit = (self.payload_credit + refill).min(self.burst);
        self.updated = now;
    }

    fn permits(&self, cost: usize) -> bool {
        self.credit >= cost as f64
    }

    fn available(&self) -> usize {
        self.credit as usize
    }

    fn admit_payload(&mut self, cost: usize) {
        self.payload_credit -= cost as f64;
    }

    fn permits_payload(&self, cost: usize) -> bool {
        self.payload_credit >= cost as f64 && self.permits(cost)
    }

    fn charge(&mut self, sent: u64) {
        // Connectivity traffic can borrow against the next data allowance.
        self.credit -= sent as f64;
    }
}

struct Slot {
    tun: SyncDevice,
    active: Option<Session>,
    pending: Option<Session>,
}

impl Slot {
    fn sessions_mut(&mut self) -> impl Iterator<Item = &mut Session> {
        self.active.iter_mut().chain(&mut self.pending)
    }
}

fn run(
    socket: &UdpSocket,
    max_mbps: f64,
    peers: &mut BTreeMap<Ipv4Addr, Slot>,
    offers: Receiver<Session>,
    status: Option<&Path>,
    tickets: SessionTickets,
) -> Result<()> {
    let identities = peers.keys().copied().collect::<Vec<_>>();
    let mut udp = [0u8; 2048];
    let mut packet = [0u8; TUN_READ_BUFFER_SIZE];
    let mut wire = WireBudget::new(max_mbps, Instant::now());
    let mut first_peer = 0;
    let mut next_status = Instant::now();
    loop {
        let mut active = false;
        wire.refresh(Instant::now());
        if let Ok(session) = offers.try_recv() {
            let ip = session.peer.config.peer_ip;
            if let Some(slot) = peers.get_mut(&ip)
                && (session.resume_ticket.is_none()
                    || slot
                        .pending
                        .as_ref()
                        .is_none_or(|pending| pending.resume_ticket.is_some()))
                && permits_resume(&tickets, ip, session.resume_ticket)
            {
                slot.pending = Some(session);
            }
            active = true;
        }

        for &ip in identities
            .iter()
            .cycle()
            .skip(first_peer)
            .take(identities.len())
        {
            let slot = peers.get_mut(&ip).expect("provisioned peer");
            for session in [&mut slot.active, &mut slot.pending] {
                if let Some(current) = session {
                    let sent = current.peer.stats.udp_tx_ipv4_bytes;
                    let result = current
                        .peer
                        .poll_egress()
                        .and_then(|sent| Ok(sent | current.peer.poll_timers()?));
                    wire.charge(current.peer.stats.udp_tx_ipv4_bytes - sent);
                    active |= retain_session(session, result);
                }
            }
            if let Some(pending) = &slot.pending {
                if pending.peer.rtc.is_connected() && pending.peer.last_echo.is_some() {
                    let mut ready = slot
                        .pending
                        .take()
                        .expect("authenticated pending peer exists");
                    if !permits_resume(&tickets, ip, ready.resume_ticket) {
                        continue;
                    }
                    if let Err(error) = discard_stale_tun(&slot.tun) {
                        eprintln!(
                            "SFERA MEDIA: peer {ip} could not replace its session: {error:#}"
                        );
                        continue;
                    }
                    ready.peer.enter_tun(Instant::now());
                    tickets.lock().expect("session tickets lock").insert(
                        ip,
                        ready.peer.session_ticket.expect("prepared session ticket"),
                    );
                    eprintln!(
                        "SFERA MEDIA: authenticated peer {} connected",
                        ready.peer.config.peer_ip
                    );
                    slot.active = Some(ready);
                    active = true;
                } else if pending.peer.start.elapsed() >= HANDSHAKE_TIMEOUT {
                    slot.pending = None;
                }
            }
        }

        for _ in 0..PEER_IO_BATCH {
            match socket.recv_from(&mut udp) {
                Ok((size, source)) => {
                    active = true;
                    route_datagram(peers, source, &udp[..size], &mut wire);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("read shared media UDP socket"),
            }
        }
        for &ip in identities
            .iter()
            .cycle()
            .skip(first_peer)
            .take(identities.len())
        {
            let slot = peers.get_mut(&ip).expect("provisioned peer");
            if let Some(session) = &mut slot.active {
                let result = service_tun(&slot.tun, session, &identities, &mut packet, &mut wire);
                active |= retain_session(&mut slot.active, result);
            }
        }
        first_peer = (first_peer + 1) % identities.len();
        let now = Instant::now();
        if let Some(path) = status
            && now >= next_status
        {
            let counters = peers
                .iter()
                .filter_map(|(ip, slot)| Some((ip, &slot.active.as_ref()?.peer.stats)))
                .collect::<BTreeMap<_, _>>();
            if let Err(error) = write_status(path, &counters) {
                eprintln!("SFERA MEDIA: publish server counters: {error:#}");
            }
            next_status = now + Duration::from_secs(2);
        }
        if !active {
            // Revisit TUN, signaling, and timers after the timeout even without UDP input.
            let mut events = [PollFd::new(socket, PollFlags::IN)];
            if let Err(error) = poll(&mut events, Some(&IDLE_WAIT))
                && error != rustix::io::Errno::INTR
            {
                return Err(io::Error::from(error)).context("wait for shared media UDP");
            }
        }
    }
}

fn service_tun(
    tun: &SyncDevice,
    session: &mut Session,
    identities: &[Ipv4Addr],
    packet: &mut [u8],
    wire: &mut WireBudget,
) -> Result<bool> {
    let mut active = flush_incoming(tun, &mut session.peer, identities)?;
    for _ in 0..session.outgoing.reads_per_visit() {
        if session.outgoing.is_full() {
            session.peer.note_full_tun_queue(&session.outgoing);
            break;
        }
        match stage_tun_packet(tun, &mut session.peer, &mut session.outgoing, packet) {
            Ok(()) => active = true,
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                break;
            }
            Err(error) => return Err(error).context("read peer TUN"),
        }
    }
    active |= session.flush_outgoing(wire)?;
    Ok(active)
}

fn retain_session(session: &mut Option<Session>, result: Result<bool>) -> bool {
    match result {
        Ok(work) => work,
        Err(error) => {
            if let Some(session) = session.take() {
                eprintln!(
                    "SFERA MEDIA: peer {} ended: {error:#}",
                    session.peer.config.peer_ip
                );
            }
            true
        }
    }
}

fn route_datagram(
    peers: &mut BTreeMap<Ipv4Addr, Slot>,
    source: SocketAddr,
    bytes: &[u8],
    wire: &mut WireBudget,
) {
    let SocketAddr::V4(address) = source else {
        return;
    };
    if !valid_media_endpoint(address) {
        return;
    }
    let stun = bytes.first().is_some_and(|first| *first < 4);
    if stun {
        // ICE-lite sends no binding requests of its own. Ignore STUN responses
        // and verify request credentials even for a tuple already in use.
        let Ok(request) = StunMessage::parse(bytes) else {
            return;
        };
        if !request.is_binding_request() || wire.credit < -((2 * SERVICE_QUANTUM) as f64) {
            return;
        }
        let owner = peers
            .values()
            .flat_map(|slot| slot.active.iter().chain(&slot.pending))
            .find(|session| session.source == Some(source));
        if owner.is_some_and(|session| !session.matches_stun(&request)) {
            return;
        }
        if let Some(session) = peers
            .values_mut()
            .flat_map(Slot::sessions_mut)
            .find(|session| session.matches_stun(&request))
            && session.source.is_none_or(|existing| existing == source)
            && session.admit_stun(Instant::now())
        {
            match receive_session(session, source, bytes, wire) {
                Ok(true) => session.source = Some(source),
                Ok(false) => {}
                Err(error) => close_session(session, error),
            }
        }
    } else if let Some(session) = peers
        .values_mut()
        .flat_map(Slot::sessions_mut)
        .find(|session| session.source == Some(source))
        && let Err(error) = receive_session(session, source, bytes, wire)
    {
        close_session(session, error);
    }
}

fn receive_session(
    session: &mut Session,
    source: SocketAddr,
    bytes: &[u8],
    wire: &mut WireBudget,
) -> Result<bool> {
    let sent = session.peer.stats.udp_tx_ipv4_bytes;
    let result = session.peer.receive_media(source, bytes);
    wire.charge(session.peer.stats.udp_tx_ipv4_bytes - sent);
    result
}

fn flush_incoming(tun: &SyncDevice, peer: &mut Peer, identities: &[Ipv4Addr]) -> Result<bool> {
    let mut active = false;
    for _ in 0..PEER_IO_BATCH {
        let Some((_, packet)) = peer.incoming.front() else {
            break;
        };
        let (_, destination) = ipv4_addresses(packet, peer.config.mtu)
            .expect("incoming packet was validated on admission");
        let destination_subnet = u32::from(destination) & !3;
        if destination != peer.config.local_ip
            && identities
                .iter()
                .any(|&ip| u32::from(ip) & !3 == destination_subnet)
        {
            peer.stats.drops.invalid_incoming_ip += 1;
            peer.incoming.pop_front();
            active = true;
            continue;
        }
        match send_tun(tun, packet) {
            Ok(n) if n == packet.len() => {
                peer.stats.tun_rx_bytes += n as u64;
                peer.stats.tun_rx_packets += 1;
                peer.incoming.pop_front();
                active = true;
            }
            Ok(_) => bail!("partial shared TUN packet write"),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                discard_expired(
                    &mut peer.incoming,
                    Instant::now(),
                    &mut peer.stats.drops.incoming_queue_expired,
                );
                break;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("write packet to shared TUN"),
        }
    }
    Ok(active)
}

fn close_session(session: &mut Session, error: anyhow::Error) {
    eprintln!(
        "SFERA MEDIA: peer {} rejected media: {error:#}",
        session.peer.config.peer_ip
    );
    session.peer.rtc.disconnect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncapped_wire_budget_is_never_depleted_by_bulk_traffic() {
        let now = Instant::now();
        let mut wire = WireBudget::new(UNLIMITED_MBPS, now);
        for _ in 0..1024 {
            assert_eq!(wire.available(), usize::MAX);
            assert!(wire.permits_payload(1_000_000));
            wire.admit_payload(1_000_000);
            wire.charge(1_000_000);
            wire.refresh(now);
        }
    }
}
