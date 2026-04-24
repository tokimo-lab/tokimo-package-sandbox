//! L7 network observer — an in-process HTTP(S) proxy that reports every
//! request the sandbox makes (method + URL for HTTP; CONNECT host + port and
//! TLS SNI for HTTPS) and optionally enforces a host allowlist.
//!
//! Architecture (see `docs/network-observability.md`, Phase 2 `Gated`):
//!
//! ```text
//! sandbox (--share-net, HTTP_PROXY=http://127.0.0.1:<port>)
//!    │
//!    ▼  plain HTTP or CONNECT
//! 127.0.0.1:<port>   ← this module, std::thread + std::net
//!    ├─ parse request line / CONNECT target
//!    ├─ read TLS ClientHello SNI for CONNECT tunnels
//!    ├─ fire NetEvent to sink (sync)
//!    ├─ allowlist check + sink Verdict
//!    └─ forward to upstream host:port (or 403/502)
//! ```
//!
//! Caveat: `--share-net` means a hostile binary in the sandbox can bypass the
//! proxy by dialing arbitrary addresses directly. This mode targets
//! observability + policy for cooperating tools (curl, pip, python-requests,
//! Node fetch, etc.) that honor `HTTP_PROXY` / `HTTPS_PROXY`. The full
//! slirp4netns + netns isolation path described in Phase 2 of the design doc
//! is tracked as future work.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

/// A pattern that matches a DNS hostname.
#[derive(Debug, Clone)]
pub enum HostPattern {
    /// Exact match, case-insensitive. `"pypi.org"` matches only `pypi.org`.
    Exact(String),
    /// Suffix match on DNS labels. `"githubusercontent.com"` matches
    /// `githubusercontent.com` and `*.githubusercontent.com`. Leading `*.` or
    /// `.` are tolerated.
    Suffix(String),
}

impl HostPattern {
    pub fn exact(s: impl Into<String>) -> Self {
        HostPattern::Exact(s.into())
    }
    pub fn suffix(s: impl Into<String>) -> Self {
        HostPattern::Suffix(s.into())
    }
    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        match self {
            HostPattern::Exact(s) => h == s.trim().trim_end_matches('.').to_ascii_lowercase(),
            HostPattern::Suffix(s) => {
                let suf = s
                    .trim()
                    .trim_start_matches('*')
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if suf.is_empty() {
                    return false;
                }
                h == suf || h.ends_with(&format!(".{}", suf))
            }
        }
    }
}

/// DNS handling policy. Advisory in the current proxy-based implementation:
/// the proxy resolves hostnames itself, so DNS visibility is via HTTP/SNI
/// events. Kept in the API so callers can configure the future slirp4netns
/// path without source changes.
#[derive(Debug, Clone)]
pub enum DnsPolicy {
    Resolver { upstream: Vec<SocketAddr> },
    PassThrough,
    Blocked,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        DnsPolicy::PassThrough
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    L3,
    L4,
    L7Sni,
    L7Http,
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
}

/// A single network event observed by the proxy.
#[derive(Debug, Clone)]
pub struct NetEvent {
    pub ts: SystemTime,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub layer: Layer,
    pub protocol: Proto,
    pub remote: Option<SocketAddr>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub sni: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_url: Option<String>,
    pub dns_query: Option<String>,
    pub dns_answers: Vec<IpAddr>,
}

impl NetEvent {
    fn blank(layer: Layer) -> Self {
        Self {
            ts: SystemTime::now(),
            pid: None,
            comm: None,
            layer,
            protocol: Proto::Tcp,
            remote: None,
            host: None,
            port: None,
            sni: None,
            http_method: None,
            http_path: None,
            http_url: None,
            dns_query: None,
            dns_answers: vec![],
        }
    }
}

/// The sink's verdict. `Deny(reason)` short-circuits the request with
/// HTTP 403 and `reason` in the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(String),
}

/// Sink for `NetEvent`s. Called from proxy worker threads; must be
/// `Send + Sync`.
pub trait NetEventSink: Send + Sync {
    fn on_event(&self, ev: &NetEvent) -> Verdict;
}

/// Blanket impl so `|ev| Verdict::Allow` closures work as sinks.
impl<F> NetEventSink for F
where
    F: Fn(&NetEvent) -> Verdict + Send + Sync,
{
    fn on_event(&self, ev: &NetEvent) -> Verdict {
        (self)(ev)
    }
}

/// Config used internally when spawning the proxy. Constructed by the Linux
/// driver from `NetworkPolicy::Observed` / `NetworkPolicy::Gated`.
#[derive(Clone)]
pub(crate) struct ProxyConfig {
    pub sink: Arc<dyn NetEventSink>,
    pub allow_hosts: Vec<HostPattern>,
    /// true for `Gated`; false for `Observed` (report but never block on host rules).
    pub enforce_allow: bool,
}

impl ProxyConfig {
    fn host_allowed(&self, host: &str) -> bool {
        if !self.enforce_allow {
            return true;
        }
        if self.allow_hosts.is_empty() {
            return false;
        }
        self.allow_hosts.iter().any(|p| p.matches(host))
    }
}

/// Handle returned by `start_proxy`. Dropping it shuts the listener down.
pub(crate) struct ProxyHandle {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl ProxyHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Kick the accept loop so it notices the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

pub(crate) fn start_proxy(cfg: ProxyConfig) -> io::Result<ProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    thread::Builder::new()
        .name("tokimo-net-observer".into())
        .spawn(move || accept_loop(listener, sd, cfg))?;
    Ok(ProxyHandle { addr, shutdown })
}

fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, cfg: ProxyConfig) {
    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cfg = cfg.clone();
        thread::spawn(move || {
            if let Err(e) = handle_client(stream, cfg) {
                tracing::debug!("net_observer: client error: {}", e);
            }
        });
    }
}

fn handle_client(mut client: TcpStream, cfg: ProxyConfig) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;

    let headers = match read_headers(&mut client)? {
        Some(h) => h,
        None => return Ok(()),
    };
    let text = String::from_utf8_lossy(&headers).into_owned();

    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if method.is_empty() || target.is_empty() {
        let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    }

    if method == "CONNECT" {
        return handle_connect(client, cfg, &target);
    }
    handle_plain(client, cfg, &method, &target, &version, &text)
}

fn read_headers(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        let n = stream.read(&mut one)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(buf));
        }
        buf.push(one[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(Some(buf));
        }
        if buf.len() > 32 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    }
}

fn handle_connect(mut client: TcpStream, cfg: ProxyConfig, target: &str) -> io::Result<()> {
    let (host, port) = split_host_port(target).unwrap_or_else(|| (target.to_string(), 443));

    // Peek at TLS ClientHello to extract SNI (best-effort) before deciding.
    // We reply with 200 first, then read the hello on the tunneled stream.
    // To keep the pre-connect event informative, record the CONNECT host.
    let allowed_by_pattern = cfg.host_allowed(&host);

    let mut ev = NetEvent::blank(Layer::L7Sni);
    ev.host = Some(host.clone());
    ev.port = Some(port);
    let sink_verdict = cfg.sink.on_event(&ev);
    if !allowed_by_pattern || matches!(sink_verdict, Verdict::Deny(_)) {
        let reason = match sink_verdict {
            Verdict::Deny(r) => r,
            _ => format!("host `{}` is not in the sandbox allowlist", host),
        };
        return write_http_status(&mut client, 403, "Forbidden", &reason);
    }

    let upstream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(e) => {
            return write_http_status(
                &mut client,
                502,
                "Bad Gateway",
                &format!("upstream connect failed: {}", e),
            );
        }
    };
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;

    // Best-effort SNI sniff: peek the first few KB from the client; if it is
    // a TLS ClientHello, extract SNI and fire a refined event.
    let (mut client_peek, client_rest) = (client.try_clone()?, client);
    let mut head = [0u8; 2048];
    let n = client_peek.read(&mut head).unwrap_or(0);
    let sniffed = if n > 0 { extract_sni(&head[..n]) } else { None };
    if let Some(sni) = &sniffed {
        let mut ev2 = NetEvent::blank(Layer::L7Sni);
        ev2.host = Some(host.clone());
        ev2.port = Some(port);
        ev2.sni = Some(sni.clone());
        let v = cfg.sink.on_event(&ev2);
        if !cfg.host_allowed(sni) || matches!(v, Verdict::Deny(_)) {
            // We already replied 200; the only way to signal denial now is
            // to drop. Log and tear down.
            tracing::info!(
                "net_observer: denying tunnel after SNI sniff sni={} host={}",
                sni,
                host
            );
            let _ = client_rest.shutdown(Shutdown::Both);
            return Ok(());
        }
    }

    // Write the bytes we already peeked, then tunnel bidirectionally.
    let upstream_write = upstream.try_clone()?;
    let upstream_read = upstream;
    let mut upstream_write_mut = upstream_write;
    if n > 0 {
        upstream_write_mut.write_all(&head[..n])?;
    }
    let client_for_copy = client_rest.try_clone()?;
    tunnel(client_peek, upstream_write_mut, client_for_copy, upstream_read);
    Ok(())
}

fn handle_plain(
    mut client: TcpStream,
    cfg: ProxyConfig,
    method: &str,
    target: &str,
    version: &str,
    full_headers_text: &str,
) -> io::Result<()> {
    let host_from_hdr = header_value(full_headers_text, "host");
    let (host, port, path) = match parse_http_target(target, host_from_hdr.as_deref()) {
        Some(t) => t,
        None => {
            let _ = write_http_status(
                &mut client,
                400,
                "Bad Request",
                "could not determine target host (no Host header and relative URL)",
            );
            return Ok(());
        }
    };

    let url = format!(
        "http://{}{}{}",
        host,
        if port == 80 {
            String::new()
        } else {
            format!(":{}", port)
        },
        path
    );
    let mut ev = NetEvent::blank(Layer::L7Http);
    ev.host = Some(host.clone());
    ev.port = Some(port);
    ev.http_method = Some(method.to_string());
    ev.http_path = Some(path.clone());
    ev.http_url = Some(url);
    let v = cfg.sink.on_event(&ev);
    if !cfg.host_allowed(&host) || matches!(v, Verdict::Deny(_)) {
        let reason = match v {
            Verdict::Deny(r) => r,
            _ => format!("host `{}` is not in the sandbox allowlist", host),
        };
        return write_http_status(&mut client, 403, "Forbidden", &reason);
    }

    // Rewrite request line to use the relative path (origin form) and strip
    // proxy-specific headers.
    let mut rewritten: Vec<u8> = Vec::with_capacity(full_headers_text.len());
    rewritten.extend_from_slice(format!("{} {} {}\r\n", method, path, version).as_bytes());
    for line in full_headers_text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-connection")
            || lower.starts_with("proxy-authorization")
        {
            continue;
        }
        rewritten.extend_from_slice(line.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");

    let mut upstream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(e) => {
            return write_http_status(
                &mut client,
                502,
                "Bad Gateway",
                &format!("upstream connect failed: {}", e),
            );
        }
    };
    upstream.write_all(&rewritten)?;

    let client_read = client.try_clone()?;
    let upstream_read = upstream.try_clone()?;
    tunnel(client_read, upstream, client, upstream_read);
    Ok(())
}

/// Pipe `c_in → u_out` on one thread and `u_in → c_out` on another; block
/// until both halves finish.
fn tunnel(mut c_in: TcpStream, mut u_out: TcpStream, mut c_out: TcpStream, mut u_in: TcpStream) {
    let t1 = thread::spawn(move || {
        let _ = io::copy(&mut c_in, &mut u_out);
        let _ = u_out.shutdown(Shutdown::Write);
    });
    let t2 = thread::spawn(move || {
        let _ = io::copy(&mut u_in, &mut c_out);
        let _ = c_out.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
}

fn write_http_status(
    client: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    );
    client.write_all(resp.as_bytes())
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    // IPv6 literal: "[::1]:443"
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse().ok())?;
            return Some((host.to_string(), port));
        }
        return None;
    }
    let idx = s.rfind(':')?;
    let (h, p) = s.split_at(idx);
    let port: u16 = p[1..].parse().ok()?;
    Some((h.to_string(), port))
}

fn parse_http_target(target: &str, host_header: Option<&str>) -> Option<(String, u16, String)> {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))
    {
        let slash = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..slash];
        let path = if slash < rest.len() {
            rest[slash..].to_string()
        } else {
            "/".to_string()
        };
        let (host, port) = split_host_port(authority)
            .unwrap_or_else(|| (authority.to_string(), 80));
        return Some((host, port, path));
    }
    // Relative URL — need Host header.
    let hh = host_header?.trim();
    let (host, port) = split_host_port(hh).unwrap_or_else(|| (hh.to_string(), 80));
    Some((host, port, target.to_string()))
}

fn header_value(text: &str, name: &str) -> Option<String> {
    let name_lower = name.to_ascii_lowercase();
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().to_ascii_lowercase() == name_lower {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Minimal TLS ClientHello SNI parser. Returns the first SNI hostname in the
/// `server_name` extension, or `None` if the buffer is not a valid
/// ClientHello or does not carry SNI. Does not allocate on failure paths;
/// ~60 lines of code straight out of RFC 5246 + 6066.
fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: type(1) version(2) length(2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let body = buf.get(5..5 + rec_len).or_else(|| buf.get(5..))?;

    // Handshake header: type(1) length(3)
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    let hs = body.get(4..4 + hs_len).or_else(|| body.get(4..))?;

    let mut p = 0usize;
    // client_version(2) + random(32)
    p += 2 + 32;
    // session_id
    if p + 1 > hs.len() {
        return None;
    }
    let sid_len = hs[p] as usize;
    p += 1 + sid_len;
    // cipher_suites
    if p + 2 > hs.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2 + cs_len;
    // compression_methods
    if p + 1 > hs.len() {
        return None;
    }
    let cm_len = hs[p] as usize;
    p += 1 + cm_len;
    // extensions
    if p + 2 > hs.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([hs[p], hs[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    while p + 4 <= hs.len() && p + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if p + elen > hs.len() {
            return None;
        }
        if etype == 0x0000 {
            // server_name extension
            let sni_block = &hs[p..p + elen];
            if sni_block.len() < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([sni_block[0], sni_block[1]]) as usize;
            let list = sni_block.get(2..2 + list_len)?;
            let mut q = 0usize;
            while q + 3 <= list.len() {
                let name_type = list[q];
                let name_len = u16::from_be_bytes([list[q + 1], list[q + 2]]) as usize;
                q += 3;
                if q + name_len > list.len() {
                    return None;
                }
                if name_type == 0 {
                    // host_name
                    return std::str::from_utf8(&list[q..q + name_len])
                        .ok()
                        .map(|s| s.to_string());
                }
                q += name_len;
            }
            return None;
        }
        p += elen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_pattern_matches() {
        assert!(HostPattern::exact("Pypi.org").matches("pypi.org"));
        assert!(HostPattern::exact("pypi.org").matches("PYPI.ORG."));
        assert!(!HostPattern::exact("pypi.org").matches("files.pypi.org"));

        let suf = HostPattern::suffix("*.githubusercontent.com");
        assert!(suf.matches("raw.githubusercontent.com"));
        assert!(suf.matches("a.b.githubusercontent.com"));
        assert!(suf.matches("githubusercontent.com"));
        assert!(!suf.matches("evilgithubusercontent.com"));
        assert!(!suf.matches("githubusercontent.com.evil.com"));
    }

    #[test]
    fn parse_absolute_url() {
        let (h, p, path) = parse_http_target("http://example.com:8080/x/y?z", None).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/x/y?z");
    }

    #[test]
    fn parse_relative_with_host() {
        let (h, p, path) = parse_http_target("/foo", Some("example.com")).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/foo");
    }

    #[test]
    fn split_ipv6() {
        let (h, p) = split_host_port("[::1]:443").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
    }
}
