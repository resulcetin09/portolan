//! Parse target specifications into concrete IP addresses.
//!
//! Accepts, comma- or space-separated:
//!
//! * a single IPv4/IPv6 address — `192.168.1.10`, `::1`
//! * a hostname (resolved via DNS) — `example.com`
//! * an IPv4 CIDR block — `192.168.1.0/24`
//! * an IPv4 range — `192.168.1.10-192.168.1.20`, or `192.168.1.10-20`
//!   (last-octet shorthand)

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

/// Expand one target token into a list of (display-name, IpAddr) pairs.
/// The display name keeps the hostname for nicer output when one was given.
pub fn expand(token: &str) -> Result<Vec<(String, IpAddr)>, String> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(Vec::new());
    }

    if let Some((base, bits)) = token.split_once('/') {
        return expand_cidr(base, bits);
    }
    if let Some((a, b)) = token.split_once('-') {
        if let Some(range) = try_range(a, b)? {
            return Ok(range);
        }
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(vec![(token.to_string(), ip)]);
    }
    resolve_host(token)
}

/// Expand many tokens, flattening and de-duplicating by address.
pub fn expand_all(tokens: &[String]) -> Result<Vec<(String, IpAddr)>, String> {
    let mut out: Vec<(String, IpAddr)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for token in tokens {
        for part in token.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            for (name, ip) in expand(part)? {
                if seen.insert(ip) {
                    out.push((name, ip));
                }
            }
        }
    }
    Ok(out)
}

fn resolve_host(host: &str) -> Result<Vec<(String, IpAddr)>, String> {
    // ToSocketAddrs needs a port; 0 is fine, we only want the address.
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let mut seen = std::collections::HashSet::new();
            let ips: Vec<(String, IpAddr)> = addrs
                .map(|sa| sa.ip())
                .filter(|ip| seen.insert(*ip))
                .map(|ip| (host.to_string(), ip))
                .collect();
            if ips.is_empty() {
                Err(format!("could not resolve '{host}'"))
            } else {
                // One address is enough per hostname for a port scan.
                Ok(vec![ips.into_iter().next().unwrap()])
            }
        }
        Err(e) => Err(format!("could not resolve '{host}': {e}")),
    }
}

fn expand_cidr(base: &str, bits: &str) -> Result<Vec<(String, IpAddr)>, String> {
    let addr: Ipv4Addr = base
        .parse()
        .map_err(|_| format!("CIDR only supports IPv4 base addresses: '{base}'"))?;
    let prefix: u32 = bits
        .parse()
        .map_err(|_| format!("bad CIDR prefix '/{bits}'"))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix out of range '/{bits}'"));
    }
    let base_u32 = u32::from(addr);
    let host_bits = 32 - prefix;
    let count: u64 = 1u64 << host_bits;
    if count > 65_536 {
        return Err(format!(
            "/{prefix} expands to {count} hosts; refusing (use /16 or smaller)"
        ));
    }
    let mask = if host_bits == 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = base_u32 & mask;

    // For /31 and /32 every address is usable; otherwise skip network & broadcast.
    let (start, end) = if prefix >= 31 {
        (network, network + (count as u32) - 1)
    } else {
        (network + 1, network + (count as u32) - 2)
    };
    let mut out = Vec::new();
    for v in start..=end {
        let ip = Ipv4Addr::from(v);
        out.push((ip.to_string(), IpAddr::V4(ip)));
    }
    Ok(out)
}

fn try_range(a: &str, b: &str) -> Result<Option<Vec<(String, IpAddr)>>, String> {
    let start: Ipv4Addr = match a.parse() {
        Ok(ip) => ip,
        Err(_) => return Ok(None), // not an IPv4 range (maybe a hostname with a dash)
    };
    let end: Ipv4Addr = if let Ok(ip) = b.parse::<Ipv4Addr>() {
        ip
    } else if let Ok(last) = b.parse::<u8>() {
        // shorthand: 192.168.1.10-20 -> vary the last octet
        let o = start.octets();
        Ipv4Addr::new(o[0], o[1], o[2], last)
    } else {
        return Ok(None);
    };
    let (s, e) = (u32::from(start), u32::from(end));
    if e < s {
        return Err(format!("range end {end} is before start {start}"));
    }
    if e - s > 65_536 {
        return Err(format!("range {start}-{end} is too large (max 65536)"));
    }
    let out = (s..=e)
        .map(|v| {
            let ip = Ipv4Addr::from(v);
            (ip.to_string(), IpAddr::V4(ip))
        })
        .collect();
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ip() {
        let r = expand("127.0.0.1").unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].1, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn cidr_24_skips_network_and_broadcast() {
        let r = expand("192.168.1.0/24").unwrap();
        assert_eq!(r.len(), 254);
        assert_eq!(r[0].1.to_string(), "192.168.1.1");
        assert_eq!(r[253].1.to_string(), "192.168.1.254");
    }

    #[test]
    fn cidr_32_is_single_host() {
        assert_eq!(expand("10.0.0.5/32").unwrap().len(), 1);
    }

    #[test]
    fn cidr_too_large_rejected() {
        assert!(expand("10.0.0.0/8").is_err());
    }

    #[test]
    fn range_full_and_shorthand() {
        assert_eq!(expand("192.168.1.10-192.168.1.12").unwrap().len(), 3);
        assert_eq!(expand("192.168.1.10-12").unwrap().len(), 3);
    }

    #[test]
    fn range_reversed_errors() {
        assert!(expand("192.168.1.12-10").is_err());
    }

    #[test]
    fn dedup_across_tokens() {
        let r = expand_all(&["127.0.0.1,127.0.0.1".to_string()]).unwrap();
        assert_eq!(r.len(), 1);
    }
}
