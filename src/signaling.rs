//! Bounded, one-shot HTTP signaling between an HTTPS client and the loopback backend.

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::File,
    io::{self, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::Path,
    time::{Duration, Instant},
};
#[cfg(any(target_os = "linux", test))]
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;
use ureq::{
    Agent,
    http::{HeaderValue, StatusCode, Uri},
    tls::TlsConfig,
};

const SESSION_PATH: &str = "/api/session";
const JSON: &str = "application/json";
const MAX_HEADER: usize = 8 * 1024;
const MAX_BODY: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const TOKEN_LEN: usize = 64;
const BEARER: &[u8] = b"Bearer ";

pub(crate) struct Token([u8; TOKEN_LEN]);

#[derive(Debug)]
pub(crate) struct SessionReplaced;

impl std::fmt::Display for SessionReplaced {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("another client has taken over this tunnel identity")
    }
}

impl std::error::Error for SessionReplaced {}

impl Token {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::with_capacity(TOKEN_LEN + 2);
        File::open(path)
            .context("open signaling token file")?
            .take((TOKEN_LEN + 2) as u64)
            .read_to_end(&mut bytes)
            .context("read signaling token file")?;
        Self::parse(bytes.strip_suffix(b"\n").unwrap_or(&bytes))
    }

    pub(crate) fn parse(line: &[u8]) -> Result<Self> {
        let token = <[u8; TOKEN_LEN]>::try_from(line)
            .ok()
            .filter(|token| {
                token
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            })
            .context("signaling token file must contain one line of 64 lowercase hex digits")?;
        Ok(Self(token))
    }

    fn matches(&self, header: &[u8]) -> bool {
        header
            .strip_prefix(BEARER)
            .and_then(|token| <&[u8; TOKEN_LEN]>::try_from(token).ok())
            .is_some_and(|token| bool::from(self.0.ct_eq(token)))
    }

    fn authorization(&self) -> Result<HeaderValue> {
        let mut bytes = [0; BEARER.len() + TOKEN_LEN];
        bytes[..BEARER.len()].copy_from_slice(BEARER);
        bytes[BEARER.len()..].copy_from_slice(&self.0);
        let mut header = HeaderValue::from_bytes(&bytes)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

/// Bounded static identities. Each nonempty line is `PEER_IP 64-lowercase-hex`.
/// Credentials deliberately do not implement Debug.
#[cfg(any(target_os = "linux", test))]
pub(crate) struct Credentials(Vec<(Ipv4Addr, Token)>);

#[cfg(any(target_os = "linux", test))]
impl Credentials {
    #[cfg(target_os = "linux")]
    pub(crate) fn load(path: &Path) -> Result<Self> {
        const MAX_CONFIG: usize = 4096;
        let mut bytes = Vec::new();
        File::open(path)
            .context("open signaling credentials file")?
            .take((MAX_CONFIG + 1) as u64)
            .read_to_end(&mut bytes)
            .context("read signaling credentials file")?;
        ensure!(
            bytes.len() <= MAX_CONFIG,
            "signaling credentials file too large"
        );
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("invalid signaling credentials encoding"))?;
        let mut entries: Vec<(Ipv4Addr, Token)> = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            ensure!(
                entries.len() < 16,
                "at most 16 signaling identities are allowed"
            );
            let mut fields = line.split_whitespace();
            let peer_ip: Ipv4Addr = fields
                .next()
                .and_then(|v| v.parse().ok())
                .context("invalid signaling peer address")?;
            ensure!(
                peer_ip.is_private() && u32::from(peer_ip) & 3 == 2,
                "signaling peer address must be a private /30 second host"
            );
            let token = fields
                .next()
                .and_then(|v| <[u8; TOKEN_LEN]>::try_from(v.as_bytes()).ok())
                .filter(|v| {
                    v.iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                })
                .context("invalid signaling credential")?;
            ensure!(
                fields.next().is_none(),
                "unexpected signaling credential fields"
            );
            ensure!(
                !entries
                    .iter()
                    .any(|(ip, old)| *ip == peer_ip || bool::from(old.0.ct_eq(&token))),
                "duplicate signaling identity or credential"
            );
            entries.push((peer_ip, Token(token)));
        }
        ensure!(
            !entries.is_empty(),
            "signaling credentials must not be empty"
        );
        Ok(Self(entries))
    }

    pub(crate) fn peer_ips(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.0.iter().map(|(ip, _)| *ip)
    }

    fn authenticate(&self, header: &[u8]) -> Option<Ipv4Addr> {
        let supplied = header
            .strip_prefix(BEARER)
            .and_then(|v| <&[u8; TOKEN_LEN]>::try_from(v).ok())?;
        let mut found = subtle::Choice::from(0);
        let mut address = 0u32;
        // Scan every configured token; do not reveal the matched entry by early exit.
        for (ip, token) in &self.0 {
            let matches = token.0.ct_eq(supplied);
            address = u32::conditional_select(&address, &u32::from(*ip), matches);
            found |= matches;
        }
        bool::from(found).then(|| Ipv4Addr::from(address))
    }
}

pub(crate) struct Endpoint {
    uri: Uri,
    pub(crate) route_to: SocketAddrV4,
}

impl Endpoint {
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let uri: Uri = url.parse().context("invalid signaling URL")?;
        ensure!(
            uri.scheme_str() == Some("https")
                && uri
                    .path_and_query()
                    .is_some_and(|path| path.as_str() == SESSION_PATH)
                && !url.contains(['@', '#']),
            "signaling URL must use https:// and the exact /api/session path"
        );
        let host: Ipv4Addr = uri
            .host()
            .context("signaling URL has no host")?
            .parse()
            .context("signaling URL host must be an IPv4 address")?;
        let port = match uri.port() {
            Some(port) => port.as_u16(),
            None => 443,
        };
        let route_to = SocketAddrV4::new(host, port);
        ensure!(valid_media_endpoint(route_to), "invalid signaling endpoint");
        Ok(Self { uri, route_to })
    }

    pub(crate) fn exchange<R: DeserializeOwned>(
        &self,
        token: &Token,
        request: &impl Serialize,
    ) -> Result<R> {
        let agent = client_agent(true, TlsConfig::default());
        send_request(&agent, self.uri.clone(), token, request)
    }
}

fn client_agent(https_only: bool, tls: TlsConfig) -> Agent {
    Agent::config_builder()
        .https_only(https_only)
        .tls_config(tls)
        .proxy(None)
        .max_redirects(0)
        .http_status_as_error(false)
        .max_response_header_size(MAX_HEADER)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into()
}

fn send_request<R: DeserializeOwned>(
    agent: &Agent,
    uri: Uri,
    token: &Token,
    request: &impl Serialize,
) -> Result<R> {
    let body = encode(request)?;
    let mut response = agent
        .post(uri)
        .header("Authorization", token.authorization()?)
        .header("Content-Type", JSON)
        .header("Accept", JSON)
        .header("Connection", "close")
        .send(body.as_slice())
        .context("HTTPS signaling request")?;
    if response.status() == StatusCode::CONFLICT {
        return Err(SessionReplaced.into());
    }
    ensure!(
        response.status() == StatusCode::OK,
        "HTTPS signaling returned status {}",
        response.status().as_u16()
    );
    ensure!(
        response.body().mime_type() == Some(JSON),
        "signaling answer must use application/json"
    );
    let body = response
        .body_mut()
        .with_config()
        .limit((MAX_BODY + 1) as u64)
        .read_to_vec()
        .context("read HTTPS signaling answer")?;
    serde_json::from_slice(&body).context("parse HTTPS signaling answer")
}

#[cfg(test)]
pub(crate) fn test_token() -> Token {
    Token([b'a'; TOKEN_LEN])
}

#[cfg(test)]
pub(crate) fn exchange_loopback<R: DeserializeOwned>(
    addr: SocketAddrV4,
    request: &impl Serialize,
) -> Result<R> {
    let agent = client_agent(false, TlsConfig::default());
    let uri = format!("http://{addr}{SESSION_PATH}").parse()?;
    send_request(&agent, uri, &test_token(), request)
}

pub(crate) fn bind_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    // An old HTTP connection in TIME_WAIT must not prevent a service restart.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

pub(crate) fn valid_media_endpoint(address: SocketAddrV4) -> bool {
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && !address.ip().is_broadcast()
}

pub(crate) fn handle<O: DeserializeOwned, A: Serialize, P>(
    stream: TcpStream,
    token: &Token,
    prepare: impl FnOnce(O) -> Result<(A, P)>,
) -> Option<P> {
    handle_authenticated(
        stream,
        |header| token.matches(header).then_some(()),
        |(), offer| prepare(offer),
    )
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn handle_for_peer<O: DeserializeOwned, A: Serialize, P>(
    stream: TcpStream,
    credentials: &Credentials,
    prepare: impl FnOnce(Ipv4Addr, O) -> Result<(A, P)>,
) -> Option<P> {
    handle_authenticated(stream, |header| credentials.authenticate(header), prepare)
}

fn handle_authenticated<I, O: DeserializeOwned, A: Serialize, P>(
    mut stream: TcpStream,
    authenticate: impl Fn(&[u8]) -> Option<I>,
    prepare: impl FnOnce(I, O) -> Result<(A, P)>,
) -> Option<P> {
    let request = read_request(&mut stream, &authenticate);
    let (status, body, prepared) = match request {
        Ok((identity, offer)) => {
            match prepare(identity, offer).and_then(|(answer, peer)| Ok((encode(&answer)?, peer))) {
                Ok((body, peer)) => ("200 OK", body, Some(peer)),
                Err(error) if error.is::<SessionReplaced>() => ("409 Conflict", Vec::new(), None),
                Err(_) => ("400 Bad Request", Vec::new(), None),
            }
        }
        Err(RequestError::NotFound) => ("404 Not Found", Vec::new(), None),
        Err(RequestError::BadRequest) => ("400 Bad Request", Vec::new(), None),
    };
    stream.set_write_timeout(Some(TIMEOUT)).ok()?;
    write!(
        stream,
        "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: {JSON}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .ok()?;
    stream.write_all(&body).ok()?;
    prepared
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_BODY,
        "signaling JSON exceeds the size limit"
    );
    Ok(bytes)
}

enum RequestError {
    NotFound,
    BadRequest,
}

fn read_request<I, O: DeserializeOwned>(
    stream: &mut TcpStream,
    authenticate: &impl Fn(&[u8]) -> Option<I>,
) -> std::result::Result<(I, O), RequestError> {
    let deadline = Instant::now() + TIMEOUT;
    let mut header_bytes = [0u8; MAX_HEADER];
    let mut filled = 0;
    let (header_end, length, identity) = loop {
        if filled == header_bytes.len() {
            return Err(RequestError::NotFound);
        }
        filled += read_by(stream, &mut header_bytes[filled..], deadline)
            .map_err(|_| RequestError::NotFound)?;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(header_end) = request
            .parse(&header_bytes[..filled])
            .map_err(|_| RequestError::NotFound)?
        {
            let (length, identity) = request_length(&request, authenticate)?;
            break (header_end, length, identity);
        }
    };
    let already_read = &header_bytes[header_end..filled];
    if already_read.len() > length {
        return Err(RequestError::BadRequest);
    }
    let mut body = vec![0; length];
    body[..already_read.len()].copy_from_slice(already_read);
    let mut offset = already_read.len();
    while offset < body.len() {
        offset +=
            read_by(stream, &mut body[offset..], deadline).map_err(|_| RequestError::BadRequest)?;
    }
    serde_json::from_slice(&body)
        .map(|offer| (identity, offer))
        .map_err(|_| RequestError::BadRequest)
}

fn request_length<I>(
    request: &httparse::Request<'_, '_>,
    authenticate: &impl Fn(&[u8]) -> Option<I>,
) -> std::result::Result<(usize, I), RequestError> {
    if request.method != Some("POST") || request.path != Some(SESSION_PATH) {
        return Err(RequestError::NotFound);
    }
    let identity = single_header(request.headers, "Authorization")
        .and_then(authenticate)
        .ok_or(RequestError::NotFound)?;
    if !single_header(request.headers, "Content-Type")
        .is_some_and(|value| value.eq_ignore_ascii_case(JSON.as_bytes()))
        || request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("Transfer-Encoding"))
    {
        return Err(RequestError::BadRequest);
    }
    single_header(request.headers, "Content-Length")
        .filter(|value| !value.is_empty() && value.iter().all(u8::is_ascii_digit))
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| (1..=MAX_BODY).contains(length))
        .map(|length| (length, identity))
        .ok_or(RequestError::BadRequest)
}

fn single_header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a [u8]> {
    let mut matches = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name));
    let value = matches.next()?.value;
    matches.next().is_none().then_some(value)
}

fn read_by(stream: &mut TcpStream, bytes: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        sync::Arc,
        thread,
    };
    use ureq::tls::{Certificate, RootCerts};

    fn response_headers(stream: TcpStream) -> Result<String> {
        let mut reader = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let start = headers.len();
            ensure!(
                reader.read_line(&mut headers)? != 0,
                "incomplete HTTP response"
            );
            if &headers[start..] == "\r\n" {
                return Ok(headers);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn signaling_can_restart_after_an_http_connection_closes() -> Result<()> {
        let listener = bind_listener("127.0.0.1:0".parse()?)?;
        let address = listener.local_addr()?;
        assert!(bind_listener(address).is_err());

        let mut client = TcpStream::connect(address)?;
        let (connection, _) = listener.accept()?;
        connection.shutdown(std::net::Shutdown::Write)?;
        assert_eq!(client.read(&mut [0])?, 0);
        drop(client);
        drop(connection);
        drop(listener);

        let replacement = bind_listener(address)?;
        assert_eq!(replacement.local_addr()?, address);
        Ok(())
    }

    #[test]
    fn credentials_are_bounded_unique_and_do_not_echo_secrets() -> Result<()> {
        let rows: Vec<_> = (0..16)
            .map(|n| format!("10.203.0.{} {:064x}", n * 4 + 2, n + 1))
            .collect();
        let valid = rows.join("\n");
        let credentials = Credentials::parse(valid.as_bytes())?;
        assert_eq!(credentials.peer_ips().count(), 16);
        for n in 0..16 {
            let header = format!("Bearer {:064x}", n + 1);
            assert_eq!(
                credentials.authenticate(header.as_bytes()),
                Some(Ipv4Addr::new(10, 203, 0, n * 4 + 2))
            );
        }
        assert!(
            credentials
                .authenticate(format!("Bearer {:064x}", 99).as_bytes())
                .is_none()
        );
        assert!(credentials.authenticate(b"Bearer short").is_none());
        let secret = "a".repeat(TOKEN_LEN);
        for invalid in [
            String::new(),
            format!("{valid}\n10.203.0.66 {:064x}", 17),
            format!("10.203.0.2 {secret}\n10.203.0.6 {secret}"),
            format!("10.203.0.2 {secret}\n10.203.0.2 {}", "b".repeat(TOKEN_LEN)),
            format!("8.8.8.2 {secret}"),
            format!("10.203.0.1 {secret}"),
            format!("10.203.0.2 {secret} extra"),
            format!("10.203.0.2 {}", "A".repeat(TOKEN_LEN)),
        ] {
            let error = Credentials::parse(invalid.as_bytes())
                .err()
                .expect("invalid config accepted");
            assert!(!format!("{error:#}").contains(&secret));
        }
        assert!(Credentials::parse(&[0xff]).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_peer_identity_is_selected_by_credential_only() -> Result<()> {
        let credentials = Credentials::parse(
            format!(
                "10.203.0.2 {}\n10.203.0.6 {}",
                "a".repeat(TOKEN_LEN),
                "b".repeat(TOKEN_LEN)
            )
            .as_bytes(),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<()> {
            for expected in [2, 6] {
                let (stream, _) = listener.accept()?;
                let identity = handle_for_peer::<serde_json::Value, (), _>(
                    stream,
                    &credentials,
                    |ip, offer| {
                        // The body deliberately claims the other peer's address.
                        assert!(offer.get("peer_ip").is_some());
                        Ok(((), ip))
                    },
                );
                assert_eq!(identity, Some(Ipv4Addr::new(10, 203, 0, expected)));
            }
            let (stream, _) = listener.accept()?;
            assert!(
                handle_for_peer::<serde_json::Value, (), ()>(stream, &credentials, |_, _| panic!(
                    "unknown credential admitted"
                ))
                .is_none()
            );
            Ok(())
        });
        for (token, expected) in [('a', 200), ('b', 200), ('c', 404)] {
            let mut stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            let body = r#"{"peer_ip":"10.203.0.10"}"#;
            let request = format!(
                "POST {SESSION_PATH} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: {JSON}\r\nContent-Length: {}\r\n\r\n{body}",
                token.to_string().repeat(TOKEN_LEN),
                body.len()
            );
            stream.write_all(request.as_bytes())?;
            // An early HTTP rejection may close with unread request bytes.
            // The status is framed by HTTP headers, independent of TCP EOF.
            let response = response_headers(stream)?;
            assert!(response.starts_with(&format!("HTTP/1.1 {expected} ")));
        }
        server.join().expect("identity test thread panicked")?;
        Ok(())
    }

    #[test]
    fn unauthorized_and_other_paths_get_the_same_response() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let bearer = format!("Authorization: Bearer {}\r\n", "a".repeat(TOKEN_LEN));
        let wrong = format!("Authorization: Bearer {}\r\n", "b".repeat(TOKEN_LEN));
        let duplicate = format!("{bearer}{wrong}");
        let server = thread::spawn(move || -> Result<()> {
            for _ in 0..5 {
                let (stream, _) = listener.accept()?;
                assert_eq!(
                    handle::<serde_json::Value, (), ()>(stream, &test_token(), |_| {
                        panic!("unauthorized request reached SDP negotiation")
                    }),
                    None
                );
            }
            Ok(())
        });
        let mut first = None;
        for (method, path, auth) in [
            ("POST", SESSION_PATH, ""),
            ("POST", SESSION_PATH, wrong.as_str()),
            ("POST", SESSION_PATH, duplicate.as_str()),
            ("POST", "/api/session/extra", bearer.as_str()),
            ("GET", SESSION_PATH, bearer.as_str()),
        ] {
            let mut stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: {JSON}\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            stream.write_all(request.as_bytes())?;
            let response = response_headers(stream)?;
            assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
            assert_eq!(&response, first.get_or_insert_with(|| response.clone()));
        }
        server.join().expect("signaling test thread panicked")?;
        Ok(())
    }

    #[test]
    fn client_verifies_the_ipv4_san_before_sending_authorization() -> Result<()> {
        for (san, expected_ok) in [("127.0.0.1", true), ("127.0.0.2", false)] {
            let cert = rcgen::generate_simple_self_signed(vec![san.into()])?;
            let trust = Certificate::from_der(cert.cert.der().as_ref()).to_owned();
            let tls = TlsConfig::builder()
                .root_certs(RootCerts::new_with_certs(&[trust]))
                .build();
            let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into();
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)?;
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let endpoint =
                Endpoint::parse(&format!("https://{}{SESSION_PATH}", listener.local_addr()?))?;
            let server = thread::spawn(move || -> Result<()> {
                let (stream, _) = listener.accept()?;
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
                let conn = ServerConnection::new(Arc::new(config))?;
                let mut stream = BufReader::new(StreamOwned::new(conn, stream));
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    ensure!(stream.read_line(&mut line)? != 0, "missing HTTP request");
                    if line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }
                assert!(request.starts_with("POST /api/session HTTP/1.1\r\n"));
                assert!(request.to_ascii_lowercase().contains(&format!(
                    "\r\nauthorization: bearer {}\r\n",
                    "a".repeat(TOKEN_LEN)
                )));
                let mut body = [0; 4];
                stream.read_exact(&mut body)?;
                assert_eq!(&body, b"null");
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 200 OK\r\nContent-Type: {JSON}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull"
                )?;
                stream.get_mut().flush()?;
                Ok(())
            });
            let result =
                send_request::<()>(&client_agent(true, tls), endpoint.uri, &test_token(), &());
            let server_result = server.join().expect("TLS test thread panicked");
            if expected_ok {
                result?;
                server_result?;
            } else {
                assert!(result.is_err());
                assert!(server_result.is_err());
            }
        }
        Ok(())
    }
}
