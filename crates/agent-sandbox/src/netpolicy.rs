//! `netpolicy` — destination allow/deny rules for the sandbox proxy.
//!
//! Ported from `@anthropic-ai/sandbox-runtime` (`domain-pattern.ts`,
//! `resolved-address-guard.ts`): the allowlist matches by *name*
//! (`api.github.com`, `*.github.com`, `host:443`), then a resolved-address
//! guard re-checks where the name points so a permitted name cannot be
//! pointed at loopback, link-local, cloud-metadata or this host's own
//! addresses. Deny rules always win over allow rules.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One `allowedDomains`/`deniedDomains` entry, parsed.
///
/// Forms: `example.com`, `*.example.com` (strict subdomains), `*` (any),
/// literal IPs (`127.0.0.1`, `[::1]`) and an optional `:port` suffix on any
/// of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPattern {
    host: HostPattern,
    port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    Any,
    /// `*.base` — strict subdomains of `base` only (not `base` itself),
    /// never an IP literal (a zone-id'd IPv6 like `::ffff:1.2.3.4%x.com`
    /// can't ride a suffix match).
    Suffix(String),
    Exact(String),
    Literal(IpAddr),
}

impl DomainPattern {
    /// Parse a config entry. `Err` on malformed input — callers should
    /// surface it (a silently dropped rule is a silent hole).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty domain pattern".into());
        }
        let (host_part, port) = split_port(s)?;
        if host_part.is_empty() {
            return Err(format!("empty host in pattern {s:?}"));
        }
        let host = match host_part {
            "*" => HostPattern::Any,
            h if h.starts_with("*.") => {
                let base = h[2..].to_lowercase();
                if base.is_empty() || base.contains('*') {
                    return Err(format!("bad wildcard pattern {s:?}"));
                }
                HostPattern::Suffix(base)
            }
            h => {
                if let Ok(ip) = h.parse::<IpAddr>() {
                    HostPattern::Literal(ip)
                } else if let Some(inner) = h.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
                    let ip = inner
                        .parse::<Ipv6Addr>()
                        .map_err(|_| format!("bad bracketed IPv6 literal {s:?}"))?;
                    HostPattern::Literal(IpAddr::V6(ip))
                } else {
                    HostPattern::Exact(h.trim_end_matches('.').to_lowercase())
                }
            }
        };
        Ok(Self { host, port })
    }

    /// Does this pattern cover `hostname:port`? `hostname` is a DNS name or
    /// a literal IP spelling. Exact rules compare IP destinations by parsed
    /// form so `127.1`-style spellings can't diverge from the canonical
    /// form the resolver produced.
    pub fn matches(&self, hostname: &str, port: u16) -> bool {
        if let Some(p) = self.port {
            if p != port {
                return false;
            }
        }
        let h = hostname.trim().to_lowercase();
        let h = h.trim_end_matches('.');
        match &self.host {
            HostPattern::Any => true,
            HostPattern::Suffix(base) => {
                if h.parse::<IpAddr>().is_ok() || h.starts_with('[') {
                    return false;
                }
                h.ends_with(&format!(".{base}"))
            }
            HostPattern::Exact(e) => {
                if let Ok(ip) = h.parse::<IpAddr>() {
                    e.parse::<IpAddr>().map(|r| r == ip).unwrap_or(false)
                } else {
                    h == e.as_str()
                }
            }
            HostPattern::Literal(ip) => h
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .map(|d| d == *ip)
                .unwrap_or(false),
        }
    }

    /// The literal IP (v4/v6) this pattern names, if any — feeds the
    /// resolved-address rule set (an allowed literal is what a name may
    /// resolve to; a denied literal is refused however it is reached).
    pub fn literal_ip(&self) -> Option<IpAddr> {
        match &self.host {
            HostPattern::Literal(ip) => Some(*ip),
            HostPattern::Exact(e) => e.parse().ok(),
            _ => None,
        }
    }

    /// Port restriction carried by this pattern, if any.
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

/// Split `host[:port]`, bracket-aware for IPv6 (`[::1]:443`).
/// A bare multi-colon string is a bare IPv6 literal — never split (same
/// rule as srt: `::1:443` must not be mistaken for host+port).
fn split_port(s: &str) -> Result<(&str, Option<u16>), String> {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let inner = &rest[..close];
            let tail = &rest[close + 1..];
            return match tail.strip_prefix(':') {
                None if tail.is_empty() => Ok((inner, None)),
                Some(port_s) => Ok((inner, Some(parse_port_checked(port_s, s)?))),
                None => Err(format!("trailing junk after bracketed address {s:?}")),
            };
        }
        return Err(format!("unbalanced bracket in {s:?}"));
    }
    let colons = s.matches(':').count();
    if colons == 0 {
        return Ok((s, None));
    }
    if colons > 1 {
        // Unbracketed IPv6 — whole thing is the host.
        return Ok((s, None));
    }
    let (host, port_s) = s.rsplit_once(':').unwrap();
    Ok((host, Some(parse_port_checked(port_s, s)?)))
}

fn parse_port_checked(s: &str, whole: &str) -> Result<u16, String> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("bad port in pattern {whole:?}"));
    }
    s.parse::<u16>()
        .map_err(|_| format!("bad port in pattern {whole:?}"))
}

/// Parsed `a.b.c.d/n` or bare `a.b.c.d` (host bit) range.
#[derive(Debug, Clone)]
struct IpRange {
    net: IpAddr,
    /// Prefix length in bits (32/128 = host).
    bits: u8,
}

impl IpRange {
    fn parse(s: &str) -> Result<Self, String> {
        let (addr_s, bits_s) = match s.split_once('/') {
            Some((a, b)) => (a, b),
            None => (s, ""),
        };
        let net: IpAddr = addr_s
            .trim()
            .parse()
            .map_err(|_| format!("bad address in range {s:?}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = if bits_s.is_empty() {
            max
        } else {
            bits_s
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| format!("bad prefix in range {s:?}"))?
        };
        Ok(Self { net, bits })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        let (n, a, width) = match (self.net, addr) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                (u128::from(u32::from(n)), u128::from(u32::from(a)), 32u8)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => (u128::from(n), u128::from(a), 128u8),
            _ => return false,
        };
        if self.bits == 0 {
            return true;
        }
        (n >> (width - self.bits)) == (a >> (width - self.bits))
    }
}

/// The IPv4 address an IPv6 form carries (mapped `::ffff:a.b.c.d`,
/// NAT64 `64:ff9b::a.b.c.d`, 6to4 `2002:aabb:ccdd::`) — deny rules judge the
/// embedded address too; it adds denials, never an allow carve-out
/// (srt parity).
fn embedded_ipv4(addr: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = addr.to_ipv4_mapped() {
        return Some(v4);
    }
    let o = addr.octets();
    if addr.segments()[0] == 0x64 && addr.segments()[1] == 0xff9b {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    if addr.segments()[0] == 0x2002 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

/// Unicast addresses assigned to this host's interfaces — a service bound
/// to 0.0.0.0 answers on those exactly as on loopback (srt denies the set).
#[cfg(unix)]
pub fn local_interface_addresses() -> Vec<IpAddr> {
    let mut out = Vec::new();
    unsafe {
        let mut ifs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifs) != 0 {
            return out;
        }
        let mut cur = ifs;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() {
                match (*ifa.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifs);
    }
    out
}

#[cfg(not(unix))]
pub fn local_interface_addresses() -> Vec<IpAddr> {
    Vec::new()
}

/// The resolved-address guard. A name allowed by the domain list still may
/// not resolve *anywhere* — the denied set below minus what an IP-literal
/// allow entry explicitly names. Mirrors srt: private-use ranges are NOT
/// denied by default (intranet allowlist entries are legitimate); deny them
/// via `denied_addrs` when needed.
pub struct ResolvedGuard {
    /// IP literals / CIDRs that allowed names must never resolve to
    /// (`deniedResolvedAddresses` in srt).
    denied_ranges: Vec<IpRange>,
    denied_classes: Vec<(&'static str, Vec<IpRange>)>,
    /// IP literals from the allow/deny domain lists — a denied literal wins
    /// wherever it is reached; an allowed literal is the only way a name may
    /// land on an otherwise-denied class.
    denied_literals: Vec<(IpAddr, Option<u16>)>,
    allowed_literals: Vec<(IpAddr, Option<u16>)>,
}

fn denied_class_ranges() -> Vec<(&'static str, Vec<IpRange>)> {
    /// Cloud instance-metadata / platform endpoints outside link-local
    /// space (srt's `CLOUD_METADATA_ADDRESSES`).
    const CLOUD_METADATA: &[&str] = &[
        "100.100.100.200",    // Alibaba
        "168.63.129.16",      // Azure WireServer
        "192.0.0.192",        // Oracle Classic
        "fd00:ec2::/32",      // AWS IPv6 service block (IMDS ::254, EKS ::23)
        "fd20:ce::254",       // GCP IPv6-only
        "fd00:c1::a9fe:a9fe", // Oracle IPv6
        "fd00:42::42",        // Scaleway
        "fd00:a9fe:a9fe::1",  // Akamai/Linode
        "fd00:100::100:200",  // Alibaba IPv6
    ];
    fn parse_ranges(list: &[&str]) -> Vec<IpRange> {
        list.iter().filter_map(|s| IpRange::parse(s).ok()).collect()
    }
    vec![
        (
            "a loopback address",
            parse_ranges(&["127.0.0.0/8", "::1/128"]),
        ),
        (
            "an unspecified address",
            parse_ranges(&["0.0.0.0/8", "::/128"]),
        ),
        (
            "a link-local address",
            parse_ranges(&["169.254.0.0/16", "fe80::/10"]),
        ),
        (
            "a multicast address",
            parse_ranges(&["224.0.0.0/4", "ff00::/8"]),
        ),
        (
            "the broadcast address",
            vec![IpRange {
                net: IpAddr::V4(Ipv4Addr::BROADCAST),
                bits: 32,
            }],
        ),
        ("a cloud metadata address", parse_ranges(CLOUD_METADATA)),
    ]
}

impl ResolvedGuard {
    pub fn new(
        denied_domains: &[DomainPattern],
        allowed_domains: &[DomainPattern],
        denied_addrs: &[String],
    ) -> Self {
        Self {
            denied_ranges: denied_addrs
                .iter()
                .filter_map(|s| IpRange::parse(s).ok())
                .collect(),
            denied_classes: denied_class_ranges(),
            denied_literals: denied_domains
                .iter()
                .filter_map(|p| p.literal_ip().map(|ip| (ip, p.port())))
                .collect(),
            allowed_literals: allowed_domains
                .iter()
                .filter_map(|p| p.literal_ip().map(|ip| (ip, p.port())))
                .collect(),
        }
    }

    /// Why `hostname`'s resolved `address` may not be dialed on `port`, or
    /// `None` if it may. The reason names the *class* of address — never
    /// the address itself (the sandboxed client shouldn't learn the
    /// address from a refusal).
    pub fn denial(
        &self,
        hostname: &str,
        address: &IpAddr,
        port: u16,
        local_addrs: &[IpAddr],
    ) -> Option<&'static str> {
        // A literal destination is the caller's explicit choice — never
        // re-judged (srt: the list entry *is* the decision).
        if hostname.parse::<IpAddr>().is_ok() {
            return None;
        }
        let v4 = match address {
            IpAddr::V6(v6) => embedded_ipv4(v6).map(IpAddr::V4),
            IpAddr::V4(_) => None,
        };
        let lit_hit = |set: &[(IpAddr, Option<u16>)]| {
            set.iter().any(|(ip, p)| {
                (*ip == *address || Some(*ip) == v4) && p.map(|pp| pp == port).unwrap_or(true)
            })
        };
        if lit_hit(&self.denied_literals) {
            return Some("a deny-listed address");
        }
        if lit_hit(&self.allowed_literals) {
            return None;
        }
        // `localhost` / `*.localhost` resolve to loopback or a listed
        // literal and nothing else.
        let lower = hostname.to_lowercase();
        let lower = lower.trim_end_matches('.');
        if lower == "localhost" || lower.ends_with(".localhost") {
            let is_lo = matches!(address, IpAddr::V4(a) if a.is_loopback())
                || matches!(address, IpAddr::V6(a) if a.is_loopback());
            return if is_lo {
                None
            } else {
                Some("a non-loopback address")
            };
        }
        for (why, ranges) in &self.denied_classes {
            if ranges.iter().any(|r| r.contains(*address))
                || v4
                    .map(|v| ranges.iter().any(|r| r.contains(v)))
                    .unwrap_or(false)
            {
                return Some(why);
            }
        }
        if self
            .denied_ranges
            .iter()
            .any(|r| r.contains(*address) || v4.map(|v| r.contains(v)).unwrap_or(false))
        {
            return Some("a listed address");
        }
        if local_addrs.iter().any(|a| *a == *address || Some(*a) == v4) {
            return Some("one of this host's addresses");
        }
        None
    }
}

/// Where a connection attempt landed, in policy terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Human-readable reason (rule text) for the denial surface.
    Deny(String),
}

/// The whole egress policy: deny patterns first, then allow.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    pub allowed: Vec<DomainPattern>,
    pub denied: Vec<DomainPattern>,
    pub denied_addrs: Vec<String>,
}

impl EgressPolicy {
    pub fn from_strs(allowed: &[String], denied: &[String]) -> Result<Self, String> {
        let parse = |v: &[String]| -> Result<Vec<DomainPattern>, String> {
            v.iter().map(|s| DomainPattern::parse(s.as_str())).collect()
        };
        Ok(Self {
            allowed: parse(allowed)?,
            denied: parse(denied)?,
            denied_addrs: Vec::new(),
        })
    }

    pub fn guard(&self) -> ResolvedGuard {
        ResolvedGuard::new(&self.denied, &self.allowed, &self.denied_addrs)
    }

    /// Name-level decision. Deny rules win; empty allow list denies all.
    pub fn decide(&self, hostname: &str, port: u16) -> Decision {
        for p in &self.denied {
            if p.matches(hostname, port) {
                return Decision::Deny(format!("{hostname}:{port} matched deny rule"));
            }
        }
        for p in &self.allowed {
            if p.matches(hostname, port) {
                return Decision::Allow;
            }
        }
        Decision::Deny(format!("{hostname}:{port} not in allowed domains"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_is_strict_subdomain_only() {
        let p = DomainPattern::parse("*.example.com").unwrap();
        assert!(p.matches("api.example.com", 443));
        assert!(!p.matches("example.com", 443));
        assert!(!p.matches("notexample.com", 443));
        assert!(p.matches("a.b.example.com", 443));
    }

    #[test]
    fn port_suffix_narrows() {
        let p = DomainPattern::parse("api.example.com:443").unwrap();
        assert!(p.matches("api.example.com", 443));
        assert!(!p.matches("api.example.com", 80));
        assert!(DomainPattern::parse("*:22")
            .unwrap()
            .matches("any.host", 22));
    }

    #[test]
    fn trailing_dot_and_case_normalized() {
        let p = DomainPattern::parse("Example.COM").unwrap();
        assert!(p.matches("example.com.", 443));
    }

    #[test]
    fn deny_wins() {
        let pol = EgressPolicy::from_strs(
            &["*.github.com".to_string()],
            &["evil.github.com".to_string()],
        )
        .unwrap();
        assert_eq!(pol.decide("api.github.com", 443), Decision::Allow);
        assert!(matches!(
            pol.decide("evil.github.com", 443),
            Decision::Deny(_)
        ));
        assert!(matches!(pol.decide("other.com", 443), Decision::Deny(_)));
    }

    #[test]
    fn ipv6_bracket_and_port() {
        let p = DomainPattern::parse("[::1]:8080").unwrap();
        assert!(p.matches("::1", 8080));
        assert!(!p.matches("::1", 9090));
        // bare v6 with two colons is never split into host+port
        assert!(DomainPattern::parse("::1:443").is_ok());
    }

    #[test]
    fn guard_blocks_loopback_unless_listed() {
        let pol = EgressPolicy::from_strs(&["safe.example.com".to_string()], &[]).unwrap();
        let g = pol.guard();
        assert_eq!(
            g.denial(
                "safe.example.com",
                &IpAddr::V4(Ipv4Addr::LOCALHOST),
                443,
                &[]
            ),
            Some("a loopback address")
        );
        // name resolving to an allow-listed literal is the sanctioned path
        let pol2 = EgressPolicy::from_strs(
            &["safe.example.com".to_string(), "127.0.0.1:3000".to_string()],
            &[],
        )
        .unwrap();
        let g2 = pol2.guard();
        assert_eq!(
            g2.denial(
                "safe.example.com",
                &IpAddr::V4(Ipv4Addr::LOCALHOST),
                3000,
                &[]
            ),
            None
        );
        // cloud metadata
        assert_eq!(
            g2.denial(
                "safe.example.com",
                &"169.254.169.254".parse().unwrap(),
                443,
                &[]
            ),
            Some("a link-local address")
        );
        // normal public addr passes
        assert_eq!(
            g2.denial(
                "safe.example.com",
                &"93.184.216.34".parse().unwrap(),
                443,
                &[]
            ),
            None
        );
    }
}
