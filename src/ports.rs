//! Port specifications and the service name lookup table.

/// Parse a port spec: `22`, `1-1024`, `22,80,443`, `80,8000-8100`.
pub fn parse_spec(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let start: u32 = a.trim().parse().map_err(|_| format!("bad port '{a}'"))?;
            let end: u32 = b.trim().parse().map_err(|_| format!("bad port '{b}'"))?;
            if start == 0 || end > 65_535 || end < start {
                return Err(format!("bad port range '{part}'"));
            }
            for p in start..=end {
                if seen.insert(p as u16) {
                    out.push(p as u16);
                }
            }
        } else {
            let p: u32 = part.parse().map_err(|_| format!("bad port '{part}'"))?;
            if p == 0 || p > 65_535 {
                return Err(format!("port out of range '{part}'"));
            }
            if seen.insert(p as u16) {
                out.push(p as u16);
            }
        }
    }
    if out.is_empty() {
        return Err("no ports to scan".into());
    }
    Ok(out)
}

/// The N most commonly open TCP ports (frequency order), truncated to `n`.
pub fn top_ports(n: usize) -> Vec<u16> {
    TOP_PORTS
        .iter()
        .take(n.min(TOP_PORTS.len()))
        .copied()
        .collect()
}

pub fn all_ports() -> Vec<u16> {
    (1u16..=65_535).collect()
}

/// IANA service name for a port, if well-known.
pub fn service_name(port: u16) -> &'static str {
    match SERVICES.binary_search_by_key(&port, |&(p, _)| p) {
        Ok(idx) => SERVICES[idx].1,
        Err(_) => "unknown",
    }
}

// The ~100 most frequently open TCP ports, roughly in nmap frequency order.
const TOP_PORTS: &[u16] = &[
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5985,
    9200, 11211, 27017, 6379, 5672, 9092, 2375,
];

// Sorted by port so service_name can binary-search.
const SERVICES: &[(u16, &str)] = &[
    (7, "echo"),
    (9, "discard"),
    (13, "daytime"),
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (37, "time"),
    (43, "whois"),
    (53, "dns"),
    (67, "dhcp"),
    (69, "tftp"),
    (79, "finger"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "rpcbind"),
    (113, "ident"),
    (119, "nntp"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios-ns"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (179, "bgp"),
    (389, "ldap"),
    (427, "svrloc"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (514, "syslog"),
    (515, "printer"),
    (543, "klogin"),
    (544, "kshell"),
    (548, "afp"),
    (554, "rtsp"),
    (587, "submission"),
    (631, "ipp"),
    (636, "ldaps"),
    (993, "imaps"),
    (995, "pop3s"),
    (1025, "nfs-or-iis"),
    (1080, "socks"),
    (1194, "openvpn"),
    (1433, "mssql"),
    (1521, "oracle"),
    (1720, "h323"),
    (1723, "pptp"),
    (1883, "mqtt"),
    (1900, "upnp"),
    (2049, "nfs"),
    (2082, "cpanel"),
    (2181, "zookeeper"),
    (2375, "docker"),
    (2376, "docker-tls"),
    (3000, "dev-http"),
    (3128, "squid-proxy"),
    (3306, "mysql"),
    (3389, "rdp"),
    (4369, "epmd"),
    (5000, "upnp-or-flask"),
    (5060, "sip"),
    (5432, "postgresql"),
    (5601, "kibana"),
    (5672, "amqp"),
    (5900, "vnc"),
    (5985, "winrm"),
    (6000, "x11"),
    (6379, "redis"),
    (7070, "realserver"),
    (8000, "http-alt"),
    (8008, "http-alt"),
    (8009, "ajp13"),
    (8080, "http-proxy"),
    (8081, "http-alt"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9000, "php-fpm-or-sonar"),
    (9092, "kafka"),
    (9100, "jetdirect"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (9999, "http-alt"),
    (11211, "memcached"),
    (15672, "rabbitmq-mgmt"),
    (27017, "mongodb"),
    (27018, "mongodb"),
    (50070, "hadoop"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_and_range() {
        assert_eq!(parse_spec("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_spec("20-22").unwrap(), vec![20, 21, 22]);
    }

    #[test]
    fn parse_dedups() {
        assert_eq!(parse_spec("80,80,80").unwrap(), vec![80]);
    }

    #[test]
    fn parse_rejects_bad() {
        assert!(parse_spec("0").is_err());
        assert!(parse_spec("70000").is_err());
        assert!(parse_spec("100-50").is_err());
        assert!(parse_spec("abc").is_err());
    }

    #[test]
    fn services_table_is_sorted() {
        for w in SERVICES.windows(2) {
            assert!(w[0].0 < w[1].0, "SERVICES must stay sorted by port");
        }
    }

    #[test]
    fn service_lookup() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(65000), "unknown");
    }

    #[test]
    fn top_ports_truncates() {
        assert_eq!(top_ports(5).len(), 5);
        assert!(top_ports(10_000).len() <= TOP_PORTS.len());
    }
}
