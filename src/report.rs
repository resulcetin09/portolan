//! Output formats for scan results.

use crate::scan::Open;
use std::collections::BTreeMap;
use std::time::Duration;

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn color(on: bool, code: &str, text: &str) -> String {
    if on {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn render_table(
    open: &[Open],
    hosts_scanned: usize,
    ports_per_host: usize,
    elapsed: Duration,
    show_banner: bool,
    use_color: bool,
) -> String {
    let c = |code: &str, t: &str| color(use_color, code, t);
    let mut out = String::new();

    // group by host/ip
    let mut by_host: BTreeMap<(String, String), Vec<&Open>> = BTreeMap::new();
    for o in open {
        by_host
            .entry((o.ip.to_string(), o.host.clone()))
            .or_default()
            .push(o);
    }

    if open.is_empty() {
        out.push_str(&c(
            "2",
            &format!(
                "No open ports found across {hosts_scanned} host(s), {ports_per_host} port(s) each, in {:.2}s.\n",
                elapsed.as_secs_f64()
            ),
        ));
        return out;
    }

    for ((ip, host), ports) in &by_host {
        let title = if host == ip {
            ip.clone()
        } else {
            format!("{host} ({ip})")
        };
        out.push_str(&format!(
            "\n{}  {}\n",
            c("1;4", &title),
            c("2", &format!("{} open", ports.len()))
        ));
        out.push_str(&c("2", "  PORT      SERVICE          "));
        if show_banner {
            out.push_str(&c("2", "BANNER"));
        }
        out.push('\n');
        for o in ports {
            let port_col = format!("{}/tcp", o.port);
            out.push_str(&c("1;32", &format!("  {port_col:<9}")));
            out.push_str(&format!(" {:<16} ", o.service));
            if show_banner {
                match &o.banner {
                    Some(b) => out.push_str(&c("36", b)),
                    None => out.push_str(&c("2", "-")),
                }
            }
            out.push('\n');
        }
    }

    out.push('\n');
    out.push_str(&c(
        "1",
        &format!(
            "{} open port(s) on {} host(s) · {} host(s) × {} port(s) scanned in {:.2}s\n",
            open.len(),
            by_host.len(),
            hosts_scanned,
            ports_per_host,
            elapsed.as_secs_f64(),
        ),
    ));
    out
}

pub fn render_json(
    open: &[Open],
    hosts_scanned: usize,
    ports_per_host: usize,
    elapsed: Duration,
) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!(
        "  \"tool\": \"portolan\",\n  \"version\": \"{}\",\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!("  \"hosts_scanned\": {hosts_scanned},\n"));
    out.push_str(&format!("  \"ports_per_host\": {ports_per_host},\n"));
    out.push_str(&format!(
        "  \"elapsed_seconds\": {:.3},\n",
        elapsed.as_secs_f64()
    ));
    out.push_str(&format!("  \"open_count\": {},\n", open.len()));
    out.push_str("  \"open\": [\n");
    for (i, o) in open.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"ip\": \"{}\",\n", o.ip));
        out.push_str(&format!("      \"host\": \"{}\",\n", json_escape(&o.host)));
        out.push_str(&format!("      \"port\": {},\n", o.port));
        out.push_str(&format!("      \"service\": \"{}\",\n", o.service));
        out.push_str(&format!("      \"rtt_ms\": {}", o.rtt_ms));
        match &o.banner {
            Some(b) => out.push_str(&format!(",\n      \"banner\": \"{}\"\n", json_escape(b))),
            None => out.push_str(",\n      \"banner\": null\n"),
        }
        out.push_str("    }");
        out.push_str(if i + 1 < open.len() { ",\n" } else { "\n" });
    }
    out.push_str("  ]\n}\n");
    out
}

/// One line per open port: `ip port service banner` — easy to pipe into awk/grep.
pub fn render_grepable(open: &[Open]) -> String {
    let mut out = String::new();
    for o in open {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            o.ip,
            o.port,
            o.service,
            o.banner.as_deref().unwrap_or("")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_chars() {
        assert_eq!(json_escape("a\tb"), "a\\tb");
    }

    #[test]
    fn empty_table_is_informative() {
        let s = render_table(&[], 1, 10, Duration::from_secs(1), false, false);
        assert!(s.contains("No open ports"));
    }

    #[test]
    fn json_empty_valid_shape() {
        let s = render_json(&[], 1, 10, Duration::from_secs(1));
        assert!(s.contains("\"open_count\": 0"));
        assert!(s.trim_end().ends_with('}'));
    }
}
