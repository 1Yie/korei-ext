//! `proxy` — the egress half of the ported srt architecture.
//!
//! One long-lived mux listener per process (a unix socket for bwrap'd
//! commands + a loopback TCP port for backends that can only reach
//! loopback — seatbelt). Every connection's first byte picks the protocol:
//! `0x05` → SOCKS5, anything else → HTTP (CONNECT or absolute-URI
//! forwarding). The sandboxed side never has a route out — it can only
//! reach these sockets, so the allowlist is enforced here, on the host.
//!
//! Per-run isolation: callers `register` a random key with an
//! [`EgressPolicy`]; the run's proxy credentials use that key as the auth
//! username, so each connection inherits exactly the policy of the run that
//! spawned it — parallel commands never share allowlists, and denials are
//! attributable (`denials_for`).
//!
//! Construction is synchronous so `wrap_spawn` (a sync API) can wire a
//! sandboxed child; the accept loops spawn lazily on first use inside a
//! tokio runtime (`ensure_loops`).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::netpolicy::{local_interface_addresses, Decision, EgressPolicy, ResolvedGuard};

/// Proxy auth password shared by every run of this process. The username
/// slot carries the per-run key (and is what selects the policy).
pub struct SandboxProxy {
    inner: Arc<Inner>,
    unix_path: PathBuf,
    tcp_port: u16,
}

struct Inner {
    /// Shared bearer token — required on every connection so other local
    /// processes can't ride the open loopback port.
    token: String,
    /// run key → its egress policy + guard.
    runs: Mutex<HashMap<String, Arc<RunPolicy>>>,
    /// Denied connections, attributed per run key (bounded — see MAX_DENIALS).
    denials: Mutex<Vec<Denial>>,
    /// Bound listeners, parked until `ensure_loops` moves them onto a runtime.
    /// Unix socket exists on unix only — Windows backends reach the TCP port.
    #[cfg(unix)]
    unix_listener: Mutex<Option<std::os::unix::net::UnixListener>>,
    tcp_listener: Mutex<Option<std::net::TcpListener>>,
    loops_started: AtomicBool,
    _tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

struct RunPolicy {
    policy: EgressPolicy,
    guard: ResolvedGuard,
}

/// One blocked connection — surfaced in the tool result so the agent (and
/// the approval UI) can see *which host* was denied and offer escalation.
#[derive(Debug, Clone)]
pub struct Denial {
    pub run_key: String,
    pub host: String,
    pub port: u16,
    pub reason: String,
    pub when_ms: u64,
}

static RUN_SEQ: AtomicU64 = AtomicU64::new(0);
static START_MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Cap on the un-drained denial store (wrap_spawn children never drain
/// theirs — the buffer must not grow without bound).
const MAX_DENIALS: usize = 1024;

fn now_ms() -> u64 {
    let start = *START_MS.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        .saturating_sub(start)
}

fn fresh_key() -> String {
    let n = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    // Unguessable tail: the proxy token is process-global, so a concurrent
    // narrow-policy run could otherwise guess a wider run's `run-PID-N`
    // key and ride its allowlist.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "run-{}-{n}-{:x}",
        std::process::id(),
        t.wrapping_mul(0x2545f4914f6cdd1d) ^ n as u128
    )
}

fn fresh_token() -> String {
    let n = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", t, n.wrapping_mul(0x9e3779b97f4a7c15))
}

const MAX_HEAD: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

impl SandboxProxy {
    /// Bind the unix socket under `dir` plus a loopback TCP port. Accept
    /// loops are parked until [`ensure_loops`] runs inside a tokio runtime.
    /// Lives until dropped.
    pub fn new(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let unix_path = dir.join(format!("egress-{}.sock", std::process::id()));
        #[cfg(unix)]
        let unix = {
            let _ = std::fs::remove_file(&unix_path);
            let l = std::os::unix::net::UnixListener::bind(&unix_path)?;
            l.set_nonblocking(true)?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&unix_path, std::fs::Permissions::from_mode(0o600));
            }
            l
        };
        let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
        tcp.set_nonblocking(true)?;
        let tcp_port = tcp.local_addr()?.port();

        Ok(Self {
            inner: Arc::new(Inner {
                token: fresh_token(),
                runs: Mutex::new(HashMap::new()),
                denials: Mutex::new(Vec::new()),
                #[cfg(unix)]
                unix_listener: Mutex::new(Some(unix)),
                tcp_listener: Mutex::new(Some(tcp)),
                loops_started: AtomicBool::new(false),
                _tasks: Mutex::new(Vec::new()),
            }),
            unix_path,
            tcp_port,
        })
    }

    /// Spawn the accept loops — no-op after the first call, or when no
    /// tokio runtime drives this thread (returns false so the caller can
    /// degrade the sandbox's network loudly rather than silently).
    pub fn ensure_loops(&self) -> bool {
        if self.inner.loops_started.load(Ordering::Acquire) {
            return true;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        if self.inner.loops_started.swap(true, Ordering::AcqRel) {
            return true;
        }
        let mut tasks = Vec::new();
        #[cfg(unix)]
        if let Some(unix) = self.inner.unix_listener.lock().unwrap().take() {
            match tokio::net::UnixListener::from_std(unix) {
                Ok(l) => {
                    let inner = self.inner.clone();
                    tasks.push(handle.spawn(async move {
                        loop {
                            match l.accept().await {
                                Ok((s, _)) => {
                                    let inner = inner.clone();
                                    tokio::spawn(async move { handle_conn(s, inner).await });
                                }
                                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                            }
                        }
                    }));
                }
                Err(e) => tracing::warn!(?e, "sandbox proxy: unix listener conversion failed"),
            }
        }
        if let Some(tcp) = self.inner.tcp_listener.lock().unwrap().take() {
            match tokio::net::TcpListener::from_std(tcp) {
                Ok(l) => {
                    let inner = self.inner.clone();
                    tasks.push(handle.spawn(async move {
                        loop {
                            match l.accept().await {
                                Ok((s, _)) => {
                                    let inner = inner.clone();
                                    tokio::spawn(async move { handle_conn(s, inner).await });
                                }
                                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                            }
                        }
                    }));
                }
                Err(e) => tracing::warn!(?e, "sandbox proxy: tcp listener conversion failed"),
            }
        }
        self.inner._tasks.lock().unwrap().extend(tasks);
        // The accept loops are spawned, not yet polling: wait until the TCP
        // port takes a connection so a command started right after this
        // never races the listener.
        self.wait_listening();
        true
    }

    /// Block briefly until the loopback listener accepts a connection.
    fn wait_listening(&self) {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], self.tcp_port()));
        for _ in 0..100 {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        tracing::warn!(%addr, "sandbox proxy: listener not ready after 1s");
    }

    /// Unix socket path to bind-mount into the sandbox.
    pub fn unix_path(&self) -> &Path {
        &self.unix_path
    }

    /// Loopback TCP port — for backends that reach loopback but not host
    /// unix sockets (macOS seatbelt `remote tcp localhost:port`).
    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// Register a run's policy; returns the run key to embed in proxy env
    /// credentials, or `None` when no runtime can host the accept loops
    /// (caller should fall back to a loud full-deny). Pair with
    /// [`unregister`] when the command exits.
    pub fn register(&self, policy: EgressPolicy) -> Option<String> {
        if !self.ensure_loops() {
            return None;
        }
        let key = fresh_key();
        let guard = policy.guard();
        self.inner
            .runs
            .lock()
            .unwrap()
            .insert(key.clone(), Arc::new(RunPolicy { policy, guard }));
        Some(key)
    }

    pub fn unregister(&self, key: &str) {
        self.inner.runs.lock().unwrap().remove(key);
    }

    /// Denials attributed to one run, drained.
    pub fn denials_for(&self, key: &str) -> Vec<Denial> {
        let mut store = self.inner.denials.lock().unwrap();
        let (mine, rest) = store.drain(..).partition(|d| d.run_key == key);
        *store = rest;
        mine
    }

    /// `user:pass` for the Proxy-Authorization challenge — the username
    /// slot carries the run key verbatim (no `:` in it — userinfo and
    /// socat's `proxyauth=` split on the first colon).
    pub fn auth(&self, run_key: &str) -> (String, String) {
        (run_key.to_string(), self.inner.token.clone())
    }

    fn deny(inner: &Arc<Inner>, key: &str, host: &str, port: u16, reason: impl Into<String>) {
        let mut store = inner.denials.lock().unwrap();
        if store.len() >= MAX_DENIALS {
            store.remove(0); // drop oldest — bounded diagnostics
        }
        store.push(Denial {
            run_key: key.into(),
            host: host.into(),
            port,
            reason: reason.into(),
            when_ms: now_ms(),
        });
    }
}

impl Drop for SandboxProxy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.unix_path);
        for t in self.inner._tasks.lock().unwrap().iter() {
            t.abort();
        }
    }
}

/// Read one byte → dispatch SOCKS5 vs HTTP.
async fn handle_conn<S>(mut stream: S, inner: Arc<Inner>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut first = [0u8; 1];
    if stream.read_exact(&mut first).await.is_err() {
        return;
    }
    if first[0] == 0x05 {
        let _ = socks5(&mut stream, &inner).await;
    } else {
        let _ = http(first[0], &mut stream, &inner).await;
    }
}

/// Read until `\r\n\r\n` (HTTP head terminator) or cap; returns the buffer.
async fn read_head<S: AsyncRead + Unpin>(s: &mut S, first: u8) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    buf.push(first);
    let mut b = [0u8; 1];
    while buf.len() < MAX_HEAD {
        s.read_exact(&mut b).await?;
        buf.push(b[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(buf);
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"))
}

type HttpHead = (String, String, Vec<(String, String)>);

fn parse_head(buf: &[u8]) -> Option<HttpHead> {
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n");
    let req = lines.next()?;
    let mut parts = req.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        })
        .collect();
    Some((method, target, headers))
}

/// Basic-auth check: `Proxy-Authorization: Basic base64(user:pass)` —
/// user is `run:<key>`, pass is the process token. Returns the run key.
fn check_auth(inner: &Inner, headers: &[(String, String)]) -> Option<String> {
    let raw = headers
        .iter()
        .find(|(k, _)| k == "proxy-authorization")?
        .1
        .clone();
    let b64 = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64_decode(b64.trim()).ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, pass) = creds.split_once(':')?;
    if pass != inner.token || !user.starts_with("run-") {
        return None;
    }
    Some(user.to_string())
}

// Minimal RFC4648 decoder — avoids a base64 dep in this crate.
fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let mut table = [255u8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let s = s.trim_end_matches('=');
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for &c in s.as_bytes() {
        let v = table[c as usize];
        if v == 255 {
            return Err(());
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

/// host:port from a CONNECT authority or absolute-URI host part.
fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let tail = &rest[close + 1..];
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    if s.matches(':').count() > 1 {
        return Some((s.to_string(), default_port)); // bare IPv6
    }
    match s.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().unwrap_or(default_port))),
        None => Some((s.to_string(), default_port)),
    }
}

const DENIED_BODY: &[u8] = b"Connection blocked by sandbox network allowlist";

async fn http<S>(first: u8, stream: &mut S, inner: &Arc<Inner>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = read_head(stream, first).await?;
    let Some((method, target, headers)) = parse_head(&head) else {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    };

    let Some(key) = check_auth(inner, &headers) else {
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"sandbox\"\r\n\r\n",
            )
            .await?;
        return Ok(());
    };

    if method.eq_ignore_ascii_case("connect") {
        let Some((host, port)) = split_host_port(&target, 443) else {
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
            return Ok(());
        };
        return connect_and_tunnel(stream, inner, &key, &host, port, Proto::Http).await;
    }

    // Plain-HTTP forward (absolute-URI only — sandboxed clients get here
    // only via the proxy env vars).
    let Some(rest) = target.strip_prefix("http://") else {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let Some((host, port)) = split_host_port(authority, 80) else {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        return Ok(());
    };

    match allowed_upstream(inner, &key, &host, port).await {
        Ok(mut up) => {
            // Rebuild the request head: origin-form target, drop proxy auth
            // + hop-by-hop headers.
            let mut out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
            for (k, v) in &headers {
                if matches!(
                    k.as_str(),
                    "proxy-authorization"
                        | "proxy-connection"
                        | "connection"
                        | "keep-alive"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                ) {
                    continue;
                }
                out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            out.extend_from_slice(b"connection: close\r\n\r\n");
            up.write_all(&out).await?;
            // Stream the response verbatim; the client's body bytes are
            // already past the head we consumed, so bidirectional copy
            // from here forwards any remainder too.
            let _ = tokio::io::copy_bidirectional(stream, &mut up).await;
            Ok(())
        }
        Err(resp) => stream.write_all(&resp).await,
    }
}

enum Proto {
    Http,
    #[allow(dead_code)]
    Socks, // CONNECT success reply differs; SOCKS path uses connect_socks
}

/// Policy check + DNS + guard + dial; then either tunnel (CONNECT/SOCKS) or
/// hand back the upstream for the plain-HTTP forwarder.
async fn allowed_upstream(
    inner: &Arc<Inner>,
    key: &str,
    host: &str,
    port: u16,
) -> Result<TcpStream, Vec<u8>> {
    let Some(run) = inner.runs.lock().unwrap().get(key).cloned() else {
        return Err(deny_response("unknown run key — policy expired"));
    };

    if let Decision::Deny(reason) = run.policy.decide(host, port) {
        SandboxProxy::deny(inner, key, host, port, &reason);
        return Err(deny_response(&reason));
    }

    // IP-literal destinations skip DNS and the guard (the literal IS the
    // decision); names resolve once, then the guard re-checks each answer.
    let literal: Option<std::net::IpAddr> = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok();
    if let Some(ip) = literal {
        return match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(SocketAddr::new(ip, port)),
        )
        .await
        {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(err_response(&format!("dial {host}:{port}: {e}"))),
            Err(_) => Err(err_response("dial timeout")),
        };
    }

    let addrs = match tokio::net::lookup_host(format!("{host}:{port}")).await {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => {
            SandboxProxy::deny(inner, key, host, port, format!("dns: {e}"));
            return Err(err_response(&format!("resolve {host}: {e}")));
        }
    };
    let local = local_interface_addresses();
    let mut last_why = String::new();
    for sa in addrs {
        if let Some(why) = run.guard.denial(host, &sa.ip(), port, &local) {
            SandboxProxy::deny(inner, key, host, port, why);
            last_why = why.to_string();
            continue;
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(sa)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    if last_why.is_empty() {
        Err(err_response(&format!(
            "dial {host}:{port}: all addresses failed"
        )))
    } else {
        Err(deny_response(&last_why))
    }
}

async fn connect_and_tunnel<S>(
    stream: &mut S,
    inner: &Arc<Inner>,
    key: &str,
    host: &str,
    port: u16,
    proto: Proto,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match allowed_upstream(inner, key, host, port).await {
        Ok(mut up) => {
            match proto {
                Proto::Http => {
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                }
                Proto::Socks => {
                    stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await?;
                }
            }
            let _ = tokio::io::copy_bidirectional(stream, &mut up).await;
            Ok(())
        }
        Err(resp) => stream.write_all(&resp).await,
    }
}

fn deny_response(reason: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 403 Forbidden\r\n\
         X-Proxy-Error: blocked-by-agent-sandbox\r\n\
         Content-Type: text/plain\r\n\
         Connection: close\r\n\r\n\
         {}: {reason}\n",
        String::from_utf8_lossy(DENIED_BODY)
    )
    .into_bytes()
}

fn err_response(msg: &str) -> Vec<u8> {
    format!("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n{msg}\n").into_bytes()
}

/// SOCKS5 — greeting, user/pass subnegotiation (the run key rides the
/// username slot), CONNECT request, then tunnel.
async fn socks5<S>(stream: &mut S, inner: &Arc<Inner>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut m = [0u8; 1];
    stream.read_exact(&mut m).await?; // nmethods
    let mut methods = vec![0u8; m[0] as usize];
    stream.read_exact(&mut methods).await?;
    // Require user/pass (0x02) — anonymous would carry no run key.
    if !methods.contains(&0x02) {
        stream.write_all(&[0x05, 0xff]).await?;
        return Ok(());
    }
    stream.write_all(&[0x05, 0x02]).await?;

    // RFC1929: ver ulen user plen pass
    stream.read_exact(&mut m).await?; // ver (0x01)
    stream.read_exact(&mut m).await?;
    let mut user = vec![0u8; m[0] as usize];
    stream.read_exact(&mut user).await?;
    stream.read_exact(&mut m).await?;
    let mut pass = vec![0u8; m[0] as usize];
    stream.read_exact(&mut pass).await?;
    let user = String::from_utf8_lossy(&user).into_owned();
    let ok = user.starts_with("run-") && pass == inner.token.as_bytes();
    if !ok {
        stream.write_all(&[0x01, 0x01]).await?;
        return Ok(());
    }
    stream.write_all(&[0x01, 0x00]).await?;
    let key = user;

    // request: ver cmd rsv atyp addr port
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[1] != 0x01 {
        // CONNECT only — no BIND/UDP-ASSOCIATE.
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(());
    }
    let host = match hdr[3] {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        0x03 => {
            stream.read_exact(&mut m).await?;
            let mut d = vec![0u8; m[0] as usize];
            stream.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => {
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        }
    };
    let mut pbuf = [0u8; 2];
    stream.read_exact(&mut pbuf).await?;
    let port = u16::from_be_bytes(pbuf);

    match connect_socks(stream, inner, &key, &host, port).await {
        Ok(()) => {}
        Err(rep) => {
            stream
                .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
        }
    }
    Ok(())
}

async fn connect_socks<S>(
    stream: &mut S,
    inner: &Arc<Inner>,
    key: &str,
    host: &str,
    port: u16,
) -> Result<(), u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match allowed_upstream(inner, key, host, port).await {
        Ok(mut up) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|_| 0x02u8)?;
            let _ = tokio::io::copy_bidirectional(stream, &mut up).await;
            Ok(())
        }
        Err(_) => Err(0x02), // connection not allowed by ruleset
    }
}
