use std::{
    io,
    net::UdpSocket,
    time::{Duration, Instant},
};

const ACK_TIMEOUT: Duration = Duration::from_millis(1500);
const RECHECK_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

enum Probe {
    Disabled,
    Scheduled(Instant),
    AwaitingAck { sequence: u32, deadline: Instant },
}

/// Tracks the wide size for one outbound path. The caller supplies acknowledgments
/// received over the authenticated media stream.
pub(crate) struct PathMtu {
    wide: bool,
    probe: Probe,
}

impl PathMtu {
    pub(crate) fn new(now: Instant, enabled: bool) -> Self {
        Self {
            wide: false,
            probe: if enabled {
                Probe::Scheduled(now)
            } else {
                Probe::Disabled
            },
        }
    }

    pub(crate) fn wide(&self) -> bool {
        self.wide
    }

    pub(crate) fn due_at(&self) -> Option<Instant> {
        match self.probe {
            Probe::Scheduled(at) => Some(at),
            _ => None,
        }
    }

    pub(crate) fn sent(&mut self, sequence: u32, now: Instant) {
        if self.due_at().is_some_and(|at| now >= at) {
            self.probe = Probe::AwaitingAck {
                sequence,
                deadline: now + ACK_TIMEOUT,
            };
        }
    }

    pub(crate) fn ack(&mut self, sequence: u32, now: Instant) -> bool {
        self.update(now);
        if matches!(self.probe, Probe::AwaitingAck { sequence: sent, .. } if sequence == sent) {
            self.wide = true;
            self.probe = Probe::Scheduled(now + RECHECK_INTERVAL);
            true
        } else {
            false
        }
    }

    pub(crate) fn update(&mut self, now: Instant) {
        if matches!(self.probe, Probe::AwaitingAck { deadline, .. } if now >= deadline) {
            self.too_large(now);
        }
    }

    pub(crate) fn too_large(&mut self, now: Instant) {
        self.wide = false;
        if !matches!(self.probe, Probe::Disabled) {
            self.probe = Probe::Scheduled(now + RETRY_INTERVAL);
        }
    }
}

/// Enables don't-fragment behavior on the IPv4 media socket.
#[cfg(target_os = "linux")]
pub(crate) fn enable_dont_fragment(socket: &UdpSocket) -> io::Result<bool> {
    use rustix::net::sockopt::{Ipv4PathMtuDiscovery, set_ip_mtu_discover};

    // Let an authenticated datagram probe a larger size even if a previous
    // route had a smaller kernel-cached PMTU.
    set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::PROBE)?;
    Ok(true)
}

#[cfg(target_os = "macos")]
pub(crate) fn enable_dont_fragment(socket: &UdpSocket) -> io::Result<bool> {
    use nix::sys::socket::{setsockopt, sockopt::IpDontFrag};

    setsockopt(socket, IpDontFrag, &true)?;
    Ok(true)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn enable_dont_fragment(_socket: &UdpSocket) -> io::Result<bool> {
    Ok(false)
}

pub(crate) fn is_message_too_large(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_live_matching_ack_promotes_and_revalidates() {
        let now = Instant::now();
        let mut mtu = PathMtu::new(now, true);
        assert!(!mtu.wide());
        assert_eq!(mtu.due_at(), Some(now));
        assert!(!mtu.ack(1, now));

        mtu.sent(1, now);
        mtu.sent(2, now);
        assert_eq!(mtu.due_at(), None);
        assert!(!mtu.ack(2, now));
        let ack_at = now + Duration::from_millis(100);
        assert!(mtu.ack(1, ack_at));
        assert!(!mtu.ack(1, ack_at));
        assert!(mtu.wide());

        let due = ack_at + RECHECK_INTERVAL;
        assert_eq!(mtu.due_at(), Some(due));
        mtu.sent(3, due);
        let timeout = due + ACK_TIMEOUT;
        mtu.update(timeout - Duration::from_millis(1));
        assert!(mtu.wide());
        assert!(!mtu.ack(3, timeout));
        assert!(!mtu.wide());
        assert_eq!(mtu.due_at(), Some(timeout + RETRY_INTERVAL));
    }

    #[test]
    fn too_large_downgrades_and_invalidates_probe_until_retry() {
        let now = Instant::now();
        let mut mtu = PathMtu::new(now, true);
        mtu.sent(1, now);
        assert!(mtu.ack(1, now));
        let due = now + RECHECK_INTERVAL;
        mtu.sent(2, due);
        mtu.too_large(due);
        assert!(!mtu.wide());
        assert!(!mtu.ack(2, due));
        let retry_at = due + RETRY_INTERVAL;
        assert_eq!(mtu.due_at(), Some(retry_at));
        mtu.sent(3, retry_at - Duration::from_millis(1));
        assert!(!mtu.ack(3, retry_at));
        mtu.sent(4, retry_at);
        assert!(mtu.ack(4, retry_at));
        assert!(mtu.wide());
    }

    #[test]
    fn disabled_stays_at_base_size() {
        let now = Instant::now();
        let mut mtu = PathMtu::new(now, false);
        mtu.sent(1, now);
        mtu.too_large(now);
        assert!(!mtu.ack(1, now));
        assert_eq!(mtu.due_at(), None);
        assert!(!mtu.wide());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn enables_df_on_an_ipv4_udp_socket() -> io::Result<()> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        assert!(enable_dont_fragment(&socket)?);
        #[cfg(target_os = "linux")]
        {
            use rustix::net::sockopt::{Ipv4PathMtuDiscovery, ip_mtu_discover};
            assert_eq!(ip_mtu_discover(&socket)?, Ipv4PathMtuDiscovery::PROBE);
        }
        #[cfg(target_os = "macos")]
        {
            use nix::sys::socket::{getsockopt, sockopt::IpDontFrag};
            assert!(getsockopt(&socket, IpDontFrag)?);
        }
        assert!(is_message_too_large(&io::Error::from_raw_os_error(
            libc::EMSGSIZE
        )));
        assert!(!is_message_too_large(&io::Error::from_raw_os_error(
            libc::EWOULDBLOCK
        )));
        Ok(())
    }
}
