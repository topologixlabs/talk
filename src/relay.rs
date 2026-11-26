//! A store-and-forward relay bound to this machine only. It holds no message keys.
//! Connections use TLS 1.3 with hybrid X25519MLKEM768 and require a client certificate.

use crate::pki::{ClientTls, TestPki};
use rustls::crypto::{aws_lc_rs, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_FRAME: usize = 256 * 1024;
pub const MAX_QUEUE: usize = 256;
const MAX_BOX: usize = 64;
const MAX_CONNECTIONS: usize = 64;
pub const MAX_CANDIDATES: usize = 16;

const EMPTY: u8 = 0;
const OK: u8 = 1;
const RATE_LIMITED: u8 = 2;
const QUEUE_FULL: u8 = 3;
const DENIED: u8 = 4;
const CONFLICT: u8 = 5;

fn tls_provider() -> Arc<CryptoProvider> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(p)
}

#[derive(Default)]
struct State {
    boxes: HashMap<String, VecDeque<Vec<u8>>>,
    logs: HashMap<String, BTreeMap<u64, Vec<(String, Vec<u8>)>>>,
    seen: Vec<Vec<u8>>,
    buckets: HashMap<String, (f64, Instant)>,
}

struct Shared {
    state: Mutex<State>,
    accounts: HashMap<Vec<u8>, String>,
    puts_per_second: f64,
    active: AtomicUsize,
}

#[derive(Clone)]
pub struct Relay {
    pub port: u16,
    shared: Arc<Shared>,
}

impl Relay {
    pub fn start(pki: &TestPki) -> Result<Self, String> {
        Self::start_with_limit(pki, 2000.0)
    }

    pub fn start_with_limit(pki: &TestPki, puts_per_second: f64) -> Result<Self, String> {
        Self::start_bound(&pki.ca_der, &pki.server_cert, &pki.server_key, pki.accounts.clone(), Ipv4Addr::LOCALHOST, 0, puts_per_second)
    }

    /// Starts on one address. Only loopback and private Tailscale addresses are allowed.
    pub fn start_bound(
        ca_der: &[u8],
        server_cert: &[u8],
        server_key: &[u8],
        accounts: HashMap<Vec<u8>, String>,
        ip: Ipv4Addr,
        bind_port: u16,
        puts_per_second: f64,
    ) -> Result<Self, String> {
        let [a, b, ..] = ip.octets();
        if !(ip.is_loopback() || (a == 100 && (64..128).contains(&b))) {
            return Err("relay may only bind to loopback or a Tailscale address".into());
        }
        let e = |x: &dyn std::fmt::Debug| format!("{x:?}");
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der.to_vec())).map_err(|x| e(&x))?;
        let provider = tls_provider();
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build().map_err(|x| e(&x))?;
        let config = Arc::new(ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13]).map_err(|x| e(&x))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(server_cert.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.to_vec())),
            ).map_err(|x| e(&x))?);
        let listener = TcpListener::bind((ip, bind_port)).map_err(|x| e(&x))?;
        let port = listener.local_addr().map_err(|x| e(&x))?.port();
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            accounts,
            puts_per_second,
            active: AtomicUsize::new(0),
        });
        let s = shared.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                if s.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    s.active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let (s2, cfg) = (s.clone(), config.clone());
                thread::spawn(move || {
                    let _ = handle(stream, cfg, &s2);
                    s2.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok(Self { port, shared })
    }

    /// Every payload the relay has handled, for tests to inspect.
    pub fn seen(&self) -> Vec<Vec<u8>> {
        self.shared.state.lock().unwrap().seen.clone()
    }

    /// Simulates a malicious relay by flipping one bit in the oldest queued item.
    pub fn tamper_next(&self, mailbox: &str, byte: usize) -> bool {
        let mut s = self.shared.state.lock().unwrap();
        match s.boxes.get_mut(mailbox).and_then(|q| q.front_mut()) {
            Some(item) if byte < item.len() => { item[byte] ^= 1; true }
            _ => false,
        }
    }

    /// Simulates a malicious relay re-queuing an item it saw earlier.
    pub fn inject(&self, mailbox: &str, data: Vec<u8>) {
        self.shared.state.lock().unwrap().boxes.entry(mailbox.into()).or_default().push_back(data);
    }
}

fn allowed(me: &str, op: u8, mailbox: &str, accounts: &HashMap<Vec<u8>, String>) -> bool {
    let Some((kind, who)) = mailbox.split_once('/') else { return false };
    if who.is_empty() { return false; }
    let known = accounts.values().any(|n| n == who);
    match (op, kind) {
        (1, "kp") => who == me,
        (1, "in" | "welcome" | "reinvite") => known,
        (2, "kp") => known,
        (2, "in" | "welcome" | "reinvite") => who == me,
        (3 | 4, "log") => who.len() <= 48 && who.bytes().all(|b| b.is_ascii_hexdigit()),
        _ => false,
    }
}

fn take_token(st: &mut State, me: &str, rate: f64) -> bool {
    let now = Instant::now();
    let b = st.buckets.entry(me.to_string()).or_insert((rate, now));
    b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * rate).min(rate);
    b.1 = now;
    if b.0 >= 1.0 { b.0 -= 1.0; true } else { false }
}

fn read_vec<R: Read>(s: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0; len];
    s.read_exact(&mut v)?;
    Ok(v)
}
fn read_u32<R: Read>(s: &mut R) -> io::Result<usize> {
    let mut b = [0; 4]; s.read_exact(&mut b)?; Ok(u32::from_be_bytes(b) as usize)
}
fn read_u64<R: Read>(s: &mut R) -> io::Result<u64> {
    let mut b = [0; 8]; s.read_exact(&mut b)?; Ok(u64::from_be_bytes(b))
}
fn reply<W: Write>(s: &mut W, item: Option<Vec<u8>>) -> io::Result<()> {
    match item {
        Some(d) => { s.write_all(&[OK])?; s.write_all(&(d.len() as u32).to_be_bytes())?; s.write_all(&d)?; }
        None => s.write_all(&[EMPTY])?,
    }
    s.flush()
}

fn handle(mut tcp: TcpStream, config: Arc<ServerConfig>, shared: &Shared) -> io::Result<()> {
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_nodelay(true)?;
    let mut conn = ServerConnection::new(config).map_err(io::Error::other)?;
    while conn.is_handshaking() { conn.complete_io(&mut tcp)?; }
    let me = conn.peer_certificates().and_then(|c| c.first())
        .and_then(|c| shared.accounts.get(c.as_ref())).cloned();
    let Some(me) = me else { return Ok(()) }; // valid certificate, but no account
    let mut s = StreamOwned::new(conn, tcp);
    loop {
        let mut head = [0u8; 3];
        s.read_exact(&mut head)?;
        let box_len = u16::from_be_bytes([head[1], head[2]]) as usize;
        if box_len == 0 || box_len > MAX_BOX || !(1..=4).contains(&head[0]) { return Ok(()); }
        let mailbox = String::from_utf8(read_vec(&mut s, box_len)?).map_err(io::Error::other)?;
        let permitted = allowed(&me, head[0], &mailbox, &shared.accounts);
        match head[0] {
            1 => {
                let len = read_u32(&mut s)?;
                if len > MAX_FRAME { return Ok(()); }
                let data = read_vec(&mut s, len)?;
                let status = if !permitted { DENIED } else {
                    let mut st = shared.state.lock().unwrap();
                    if !take_token(&mut st, &me, shared.puts_per_second) { RATE_LIMITED }
                    else if st.boxes.get(&mailbox).is_some_and(|q| q.len() >= MAX_QUEUE) { QUEUE_FULL }
                    else {
                        st.seen.push(data.clone());
                        st.boxes.entry(mailbox).or_default().push_back(data);
                        OK
                    }
                };
                s.write_all(&[status])?; s.flush()?;
            }
            2 => {
                if !permitted { s.write_all(&[DENIED])?; s.flush()?; continue; }
                let item = shared.state.lock().unwrap().boxes.get_mut(&mailbox).and_then(|q| q.pop_front());
                reply(&mut s, item)?;
            }
            3 => {
                let epoch = read_u64(&mut s)?;
                let len = read_u32(&mut s)?;
                if len > MAX_FRAME { return Ok(()); }
                let data = read_vec(&mut s, len)?;
                let mut position = 0u32;
                let status = if !permitted { DENIED } else {
                    let mut st = shared.state.lock().unwrap();
                    if !take_token(&mut st, &me, shared.puts_per_second) { RATE_LIMITED }
                    else {
                        // Candidates are kept in arrival order. Clients apply the first valid one,
                        // so junk from one account cannot block a group.
                        let list = st.logs.entry(mailbox).or_default().entry(epoch).or_default();
                        if list.iter().any(|(who, _)| *who == me) { CONFLICT }
                        else if list.len() >= MAX_CANDIDATES { QUEUE_FULL }
                        else {
                            position = list.len() as u32;
                            list.push((me.clone(), data.clone()));
                            st.seen.push(data);
                            OK
                        }
                    }
                };
                s.write_all(&[status])?;
                if status == OK { s.write_all(&position.to_be_bytes())?; }
                s.flush()?;
            }
            _ => {
                let epoch = read_u64(&mut s)?;
                let index = read_u32(&mut s)?;
                if !permitted { s.write_all(&[DENIED])?; s.flush()?; continue; }
                let item = shared.state.lock().unwrap().logs.get(&mailbox)
                    .and_then(|l| l.get(&epoch)).and_then(|c| c.get(index)).map(|(_, d)| d.clone());
                reply(&mut s, item)?;
            }
        }
    }
}

fn status_error(code: u8) -> io::Error {
    let (kind, text) = match code {
        RATE_LIMITED => (io::ErrorKind::WouldBlock, "rate limited"),
        QUEUE_FULL => (io::ErrorKind::StorageFull, "mailbox full"),
        DENIED => (io::ErrorKind::PermissionDenied, "not permitted"),
        _ => (io::ErrorKind::InvalidData, "bad relay response"),
    };
    io::Error::new(kind, text)
}

pub struct Conn(StreamOwned<ClientConnection, TcpStream>);

impl Conn {
    pub fn connect(port: u16, tls: &ClientTls) -> Result<Self, String> {
        Self::connect_host(Ipv4Addr::LOCALHOST, port, tls)
    }

    /// Connects to a relay and checks its certificate against this exact address.
    pub fn connect_host(host: Ipv4Addr, port: u16, tls: &ClientTls) -> Result<Self, String> {
        let e = |x: &dyn std::fmt::Debug| format!("{x:?}");
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(tls.ca_der.clone())).map_err(|x| e(&x))?;
        let builder = ClientConfig::builder_with_provider(tls_provider())
            .with_protocol_versions(&[&rustls::version::TLS13]).map_err(|x| e(&x))?
            .with_root_certificates(roots);
        let config = match (&tls.cert_der, &tls.key_der) {
            (Some(c), Some(k)) => builder.with_client_auth_cert(
                vec![CertificateDer::from(c.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.clone())),
            ).map_err(|x| e(&x))?,
            _ => builder.with_no_client_auth(),
        };
        let name = if host.is_loopback() {
            ServerName::try_from("localhost").map_err(|x| e(&x))?
        } else {
            ServerName::IpAddress(IpAddr::V4(host).into())
        };
        let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|x| e(&x))?;
        let mut tcp = TcpStream::connect_timeout(&(host, port).into(), Duration::from_secs(8)).map_err(|x| e(&x))?;
        tcp.set_nodelay(true).map_err(|x| e(&x))?;
        tcp.set_read_timeout(Some(Duration::from_secs(10))).map_err(|x| e(&x))?;
        while conn.is_handshaking() { conn.complete_io(&mut tcp).map_err(|x| e(&x))?; }
        Ok(Self(StreamOwned::new(conn, tcp)))
    }

    /// The negotiated TLS key exchange, for tests.
    pub fn key_exchange(&self) -> String {
        self.0.conn.negotiated_key_exchange_group().map(|g| format!("{:?}", g.name())).unwrap_or_default()
    }

    fn head(&mut self, op: u8, mailbox: &str) -> io::Result<()> {
        let mut h = vec![op];
        h.extend((mailbox.len() as u16).to_be_bytes());
        h.extend(mailbox.as_bytes());
        self.0.write_all(&h)
    }

    fn status(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.0.read_exact(&mut b)?;
        Ok(b[0])
    }

    pub fn put(&mut self, mailbox: &str, data: &[u8]) -> io::Result<()> {
        self.head(1, mailbox)?;
        self.0.write_all(&(data.len() as u32).to_be_bytes())?;
        self.0.write_all(data)?;
        self.0.flush()?;
        match self.status()? { OK => Ok(()), c => Err(status_error(c)) }
    }

    fn item(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.status()? {
            EMPTY => Ok(None),
            OK => { let n = read_u32(&mut self.0)?; if n > MAX_FRAME { return Err(status_error(255)); } Ok(Some(read_vec(&mut self.0, n)?)) }
            c => Err(status_error(c)),
        }
    }

    pub fn try_get(&mut self, mailbox: &str) -> io::Result<Option<Vec<u8>>> {
        self.head(2, mailbox)?;
        self.0.flush()?;
        self.item()
    }

    pub fn get(&mut self, mailbox: &str) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(d) = self.try_get(mailbox)? { return Ok(d); }
            if Instant::now() > deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, mailbox.to_string())); }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Adds a candidate change for this epoch. Returns its position, or None if this
    /// account already submitted one for the epoch.
    pub fn submit_commit(&mut self, log: &str, epoch: u64, data: &[u8]) -> io::Result<Option<u32>> {
        self.head(3, log)?;
        self.0.write_all(&epoch.to_be_bytes())?;
        self.0.write_all(&(data.len() as u32).to_be_bytes())?;
        self.0.write_all(data)?;
        self.0.flush()?;
        match self.status()? {
            OK => { let mut b = [0; 4]; self.0.read_exact(&mut b)?; Ok(Some(u32::from_be_bytes(b))) }
            CONFLICT => Ok(None),
            c => Err(status_error(c)),
        }
    }

    pub fn fetch_commit(&mut self, log: &str, epoch: u64, index: u32) -> io::Result<Option<Vec<u8>>> {
        self.head(4, log)?;
        self.0.write_all(&epoch.to_be_bytes())?;
        self.0.write_all(&index.to_be_bytes())?;
        self.0.flush()?;
        self.item()
    }

    /// Sends a frame claiming a size above the limit, for tests.
    pub fn send_oversized_header(&mut self, mailbox: &str) -> io::Result<u8> {
        self.head(1, mailbox)?;
        self.0.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())?;
        self.0.flush()?;
        self.status()
    }
}
