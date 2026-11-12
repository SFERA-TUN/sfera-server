use sfera::remote::{PacketIo, connect_mobile};
use std::{
    ffi::{CStr, c_char},
    fs::File,
    io::{self, Read, Write},
    os::fd::FromRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
};

pub struct SferaSession {
    stopping: AtomicBool,
    status: AtomicI32,
}

struct PacketFile(File);

impl PacketIo for PacketFile {
    fn receive_packet(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = (&self.0).read(buffer)?;
        if size == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok(size)
    }

    fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        (&self.0).write(packet)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sfera_session_new() -> *mut SferaSession {
    Box::into_raw(Box::new(SferaSession {
        stopping: AtomicBool::new(false),
        status: AtomicI32::new(0),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sfera_session_run(
    session: *const SferaSession,
    fd: i32,
    host: *const c_char,
    peer: *const c_char,
    token: *const c_char,
) -> i32 {
    // The bridge owns the strings and keeps the session alive for this call.
    let Some(session) = (unsafe { session.as_ref() }) else {
        return -1;
    };
    let run = || -> Option<()> {
        if host.is_null() || peer.is_null() || token.is_null() {
            return None;
        }
        let host = unsafe { CStr::from_ptr(host) }
            .to_str()
            .ok()?
            .parse()
            .ok()?;
        let peer = unsafe { CStr::from_ptr(peer) }
            .to_str()
            .ok()?
            .parse()
            .ok()?;
        let token = unsafe { CStr::from_ptr(token) }.to_bytes();
        let owned = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if owned < 0 {
            return None;
        }
        let packets = PacketFile(unsafe { File::from_raw_fd(owned) });
        let flags = unsafe { libc::fcntl(owned, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(owned, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return None;
        }
        connect_mobile(host, peer, token, &packets, &session.stopping, |ready| {
            session.status.store(i32::from(ready), Ordering::Release);
        })
        .ok()
    };
    let result = catch_unwind(AssertUnwindSafe(run));
    let status = if session.stopping.load(Ordering::Acquire) || matches!(result, Ok(Some(()))) {
        2
    } else {
        -1
    };
    session.status.store(status, Ordering::Release);
    status
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sfera_session_status(session: *const SferaSession) -> i32 {
    unsafe { session.as_ref() }.map_or(-1, |session| session.status.load(Ordering::Acquire))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sfera_session_stop(session: *const SferaSession) {
    if let Some(session) = unsafe { session.as_ref() } {
        session.stopping.store(true, Ordering::Release);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sfera_session_free(session: *mut SferaSession) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, os::unix::net::UnixDatagram};

    #[test]
    fn stopped_session_does_not_dial_or_take_ownership_of_the_callers_fd() -> io::Result<()> {
        let (host, peer) = UnixDatagram::pair()?;
        let session = sfera_session_new();
        unsafe {
            sfera_session_stop(session);
            let result = sfera_session_run(
                session,
                host.as_raw_fd(),
                c"192.0.2.1".as_ptr(),
                c"10.203.0.2".as_ptr(),
                c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_ptr(),
            );
            assert_eq!(result, 2);
            assert_eq!(sfera_session_status(session), 2);
            sfera_session_free(session);
        }
        host.send(b"packet")?;
        let mut buffer = [0; 16];
        let count = peer.recv(&mut buffer)?;
        assert_eq!(&buffer[..count], b"packet");
        Ok(())
    }
}
