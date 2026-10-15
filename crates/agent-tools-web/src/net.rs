//! Guarded outbound HTTP — the shared network boundary for fetch tools.
//!
//! `web_fetch` is readonly but still a network read whose output is untrusted
//! input to the model, so every request passes:
//!
//! ```text
//! URL → scheme check → DNS resolve → IP policy → request
//!                          ↑──── re-checked per redirect hop
//! ```
//!
//! Redirects are followed manually (`redirect::Policy::none()`) so each hop
//! re-runs the checks — a public URL redirecting to `169.254.169.254` or
//! `127.0.0.1` is refused. Bodies stream under a byte cap, and the caller's
//! cancel flag is polled per hop and chunk.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use reqwest::Url;
use tokio::net::lookup_host;

use agent_tool::ToolError;

/// Hard cap on downloaded bytes — applied while streaming, before decode.
pub const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Max redirects followed per request; each hop is re-validated.
pub const MAX_REDIRECTS: usize = 5;
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// The `User-Agent` for outbound requests: the host's own name plus this
/// crate's version. The kernel does not name the product.
pub fn user_agent(app_name: &str) -> String {
    format!("{app_name}/{}", env!("CARGO_PKG_VERSION"))
}

/// One validated response: final URL (post-redirect), status, headers-derived
/// content type, and the byte-capped body.
pub struct FetchResponse {
    pub url: Url,
    pub status: reqwest::StatusCode,
    pub content_type: String,
    pub body: Vec<u8>,
    /// True when the stream hit `MAX_RESPONSE_BYTES` mid-body.
    pub body_truncated: bool,
}

fn cancelled(cancel: &Option<Arc<AtomicBool>>) -> bool {
    cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed))
}

/// Is this address a proxy fake-ip — the DNS placeholder a local
/// Clash/V2Ray/Surge returns in fake-ip mode so it can recover the real
/// hostname from the fake address. 198.18.0.0/15 is the canonical pool
/// (also RFC 2544 benchmarking). A fake-ip answer isn't a routable
/// private target — the proxy owns the connection, so refusing it just
/// bricks every fetch when the user's resolver is a fake-ip proxy.
fn is_fake_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 198 && (o[1] & 0xFE) == 18 // 198.18.0.0/15
        }
        _ => false,
    }
}

/// Is this address reachable without touching private/loopback/metadata
/// space? Anything not public is refused — the agent runs on hosts where
/// `127.0.0.1`, `169.254.169.254`, or a LAN gateway are real attack surface.
pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()                    // 127.0.0.0/8
                || v4.is_private()                // 10/8 · 172.16/12 · 192.168/16
                || v4.is_link_local()             // 169.254/16 — cloud metadata lives here
                || v4.is_unspecified()            // 0.0.0.0
                || v4.is_broadcast()              // 255.255.255.255
                || v4.is_multicast()              // 224/4
                || v4.is_documentation()          // TEST-NET-1/2/3
                || o[0] == 0                      // 0.0.0.0/8 "this network"
                || (o[0] == 100 && (o[1] & 0xC0) == 64)  // CGNAT 100.64/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)   // 192.0.0/24 IETF
                || (o[0] == 198 && (o[1] & 0xFE) == 18)) // 198.18/15 benchmarks
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:x.x.x.x) routes through the v4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_ip(&IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            !(v6.is_loopback()                    // ::1
                || v6.is_unspecified()            // ::
                || v6.is_multicast()              // ff00::/8
                || (seg[0] & 0xFE00) == 0xFC00    // unique-local fc00::/7
                || (seg[0] & 0xFFC0) == 0xFE80    // link-local fe80::/10
                || (seg[0] & 0xFFC0) == 0xFEC0    // site-local fec0::/10 (deprecated)
                || seg[0] == 0x2001 && seg[1] == 0x0DB8) // documentation 2001:db8::/32
        }
    }
}

/// Scheme + host + DNS + resolved-IP validation. Every hop of a redirect
/// chain runs this again — never trust a location you didn't check.
pub async fn validate_url(url: &Url) -> Result<(), ToolError> {
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(ToolError::Args(format!(
                "scheme '{other}://' is not allowed — http/https only"
            )))
        }
    }
    let host = url
        .host_str()
        .ok_or_else(|| ToolError::Args("URL has no host".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(&ip) {
            return Err(ToolError::Failed(format!(
                "refused: '{host}' is a private/reserved address"
            )));
        }
        return Ok(());
    }

    // Resolve first, judge every answer — a hostname that returns even one
    // private address is refused (round-robin could land on it).
    let addrs: Vec<_> = lookup_host((host, port))
        .await
        .map_err(|e| ToolError::Failed(format!("DNS lookup failed for '{host}': {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(ToolError::Failed(format!(
            "DNS lookup for '{host}' returned no addresses"
        )));
    }
    for addr in &addrs {
        let ip = addr.ip();
        // fake-ip is a proxy placeholder, not a real destination — the
        // connection goes through the local proxy which owns the hostname,
        // so the SSRF check doesn't apply to it.
        if !is_public_ip(&ip) && !is_fake_ip(&ip) {
            return Err(ToolError::Failed(format!(
                "refused: '{host}' resolves to private/reserved address {}",
                ip
            )));
        }
    }
    Ok(())
}

/// Guarded GET: validates the URL, follows redirects manually (re-validating
/// each hop), streams the body through `MAX_RESPONSE_BYTES`, and polls the
/// caller's cancel flag. Shared by every tool that reads the network.
pub async fn fetch(
    url_str: &str,
    accept: &str,
    cancel: Option<Arc<AtomicBool>>,
    user_agent: &str,
) -> Result<FetchResponse, ToolError> {
    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none()) // manual: re-validate every hop
        .user_agent(user_agent)
        .build()
        .map_err(|e| ToolError::Failed(format!("failed to build HTTP client: {e}")))?;

    let mut url = Url::parse(url_str.trim())
        .map_err(|e| ToolError::Args(format!("invalid URL '{url_str}': {e}")))?;

    for _hop in 0..MAX_REDIRECTS {
        if cancelled(&cancel) {
            return Err(ToolError::Failed("cancelled".into()));
        }
        validate_url(&url).await?;

        let resp = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, accept)
            .send()
            .await
            .map_err(|e| ToolError::Failed(format!("request to '{url}' failed: {e}")))?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| ToolError::Failed("redirect without Location header".into()))?;
            url = url
                .join(location)
                .map_err(|e| ToolError::Failed(format!("bad redirect target '{location}': {e}")))?;
            continue;
        }

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        // Byte cap while streaming — a hostile/huge body never lands whole.
        let mut body = Vec::new();
        let mut body_truncated = false;
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            if cancelled(&cancel) {
                return Err(ToolError::Failed("cancelled".into()));
            }
            let chunk = chunk
                .map_err(|e| ToolError::Failed(format!("failed to read response body: {e}")))?;
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                let room = MAX_RESPONSE_BYTES - body.len();
                body.extend_from_slice(&chunk[..room]);
                body_truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }

        return Ok(FetchResponse {
            url,
            status,
            content_type,
            body,
            body_truncated,
        });
    }

    Err(ToolError::Failed(format!(
        "too many redirects (max {MAX_REDIRECTS})"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rejects_private_and_reserved_ips() {
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata endpoint
            "0.0.0.0",
            "255.255.255.255",
            "100.64.1.1",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1", // v4-mapped v6 still hits the v4 rules
        ] {
            assert!(!is_public_ip(&ip(bad)), "{bad} should be refused");
        }
        for good in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(&ip(good)), "{good} should be allowed");
        }
    }

    #[test]
    fn fake_ip_segment_is_allowed() {
        // Clash/V2Ray fake-ip mode answers every A query with a 198.18.x.x
        // placeholder — refusing it bricks all fetches behind a local proxy.
        for fake in ["198.18.0.74", "198.18.0.1", "198.19.255.255"] {
            assert!(is_fake_ip(&ip(fake)), "{fake} should be a fake-ip");
            assert!(!is_public_ip(&ip(fake)), "{fake} is still non-public");
        }
        // Just outside the segment is still refused.
        assert!(!is_fake_ip(&ip("198.17.0.1")));
        assert!(!is_fake_ip(&ip("198.20.0.1")));
    }

    #[tokio::test]
    async fn validate_url_rejects_bad_schemes_and_private_targets() {
        for bad in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "gopher://x",
            "http://127.0.0.1:8080/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data",
            "http://192.168.0.1/",
            "http://localhost:3000/", // resolves to loopback without network
        ] {
            assert!(
                validate_url(&Url::parse(bad).unwrap()).await.is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn relative_redirect_targets_resolve_against_current_url() {
        let base = Url::parse("https://example.com/a/b").unwrap();
        assert_eq!(
            base.join("/login").unwrap().as_str(),
            "https://example.com/login"
        );
        assert_eq!(base.join("../c").unwrap().as_str(), "https://example.com/c");
    }
}
