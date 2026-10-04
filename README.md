<p align="center">
  <img src="assets/logo.svg" alt="portolan" width="440">
</p>

<p align="center">
  <b>Chart the open ports on your network.</b><br>
  A fast, single-binary TCP port scanner and service mapper — no dependencies,
  no raw sockets, no root required.
</p>

<p align="center">
  <a href="#authorization">Authorization</a> ·
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#features">Features</a> ·
  <a href="#how-it-works">How it works</a>
</p>

---

A *portolan* is a medieval nautical chart: coastlines, harbours, and a web of
rhumb lines radiating from compass roses. This one charts a different coast —
the open TCP ports on the hosts you run — so you can see your attack surface the
way an outsider would, and close what shouldn't be open.

```
$ portolan 127.0.0.1 -p 22,80,443,5432,9077 -b

127.0.0.1  2 open
  PORT      SERVICE          BANNER
  80/tcp    http             Server: nginx/1.25
  9077/tcp  unknown          DEMO-SERVICE 1.0 ready

2 open port(s) on 1 host(s) · 1 host(s) × 5 port(s) scanned in 0.21s
```

## Authorization

**Scan only hosts you own or are explicitly authorized to test.** Port scanning
systems without permission may violate computer-misuse laws and acceptable-use
policies in your jurisdiction. Portolan is built for sysadmins auditing their
own machines, for home-lab mapping, and for authorized security testing — use it
that way. Every run prints a reminder, and the tool offers no evasion features
by design.

## Why portolan

* **Nothing to install but the binary.** Pure Rust standard library — no crates,
  no OpenSSL, no libpcap. `cargo build` and copy one file.
* **No privileges needed.** It does a TCP *connect* scan, completing the normal
  handshake, so it runs as any user on Linux, macOS, and Windows alike.
* **Fast.** A configurable worker pool (default 512) scans thousands of ports in
  seconds, with a live progress bar.
* **Useful output.** Service names from a built-in table, optional banner
  grabbing, and text / JSON / grepable formats that pipe cleanly into other
  tools.

## Install

```bash
git clone https://github.com/resulcetin09/portolan
cd portolan
cargo build --release
install -m 0755 target/release/portolan /usr/local/bin/
```

Or:

```bash
cargo install --path .
```

## Quick start

```bash
# Scan one host's top-100 ports
portolan 192.168.1.10

# Specific ports, with banner grabbing
portolan 192.168.1.10 -p 22,80,443,3306 -b

# A whole /24, top 20 ports, fast
portolan 192.168.1.0/24 --top 20

# An address range
portolan 10.0.0.10-10.0.0.40 -p 1-1024

# Full sweep of a host you own, as JSON
portolan 10.0.0.5 --all -f json -o scan.json

# Pipe the grepable format into awk
portolan 192.168.1.0/24 -p 22 -f grepable | awk '{print $1}'
```

## Features

| | |
|---|---|
| **Targets** | single IP, hostname (DNS-resolved), IPv4 CIDR (`/16`–`/32`), ranges (`.10-.40`), comma lists |
| **Ports** | lists & ranges (`22,80,1-1024`), `--top N` common ports, `--all` for everything |
| **Service names** | built-in table of ~90 well-known ports (ssh, http, postgresql, redis, docker, …) |
| **Banners** | `-b` grabs a service banner; sends a minimal, well-formed HTTP `HEAD` to quiet web ports, reads otherwise |
| **Concurrency** | `-c N` worker pool (default 512); `-t MS` per-port timeout (default 500 ms) |
| **Output** | `text` (grouped table + progress bar), `json`, `grepable` (tab-separated) |
| **Exit code** | `0` if any port is open, `1` if none, `2` on error — scriptable |

## How it works

```
 targets ─▶ expand ─▶ (host × port) jobs ─▶ worker pool ─▶ connect() ─▶ open ports ─▶ report
 (CIDR,     to IPs     queued once           N threads      + optional    sorted,       text/json/
  ranges,                                    pull work       banner        by host       grepable
  DNS)                                        from a queue    grab)
```

1. **Targets** are expanded to concrete addresses (CIDR math, range expansion,
   one DNS lookup per hostname), de-duplicated.
2. Every `(host, port)` pair becomes a job in a shared queue. A pool of worker
   threads pulls jobs and runs `TcpStream::connect_timeout`. A successful
   handshake means the port is open; a refused connection or timeout means it
   isn't.
3. Optionally, each open port gets a **banner grab**: for quiet web ports a
   minimal `HEAD / HTTP/1.0` request is sent; for talkative services the first
   line the server offers is read. Only well-formed, read-only requests are
   ever sent.
4. Results are sorted by host and port and rendered.

### Why connect scan, not SYN scan?

A half-open (SYN) scan is stealthier and marginally faster, but it needs raw
sockets and therefore root, plus platform-specific packet code. Portolan
deliberately chooses the portable, unprivileged path: it is slightly more
visible to the target, which is exactly the right trade-off for a tool meant to
be run against your *own* infrastructure.

## Options

```
-p, --ports <SPEC>       22,80,443 or 1-1024 (default: top 100)
    --top <N>            scan the N most common ports
    --all                scan all 65535 ports
-t, --timeout <MS>       connect timeout per port (default: 500)
-c, --concurrency <N>    parallel workers (default: 512)
-b, --banner             grab service banners
-f, --format <text|json|grepable>
-o, --output <FILE>
    --no-color / --no-progress
```

## Development

```bash
cargo test            # target parsing, port specs, scanner (uses real loopback sockets)
cargo clippy --all-targets
cargo build --release
```

The scanner tests bind ephemeral loopback ports, so they verify a real
open/closed result without any external host.

## Scope & honesty

Portolan maps **TCP** ports via connect scan. It does not do UDP, OS
fingerprinting, deep version detection, or scripted vuln checks — for those,
reach for a full-featured scanner. Banner grabbing is best-effort and reads only
the first response. A host behind a firewall that drops packets will show ports
as closed (filtered looks the same as closed to a connect scan). Treat results
as a map to investigate, and — again — point it only at systems you are
authorized to scan.

## License

MIT © Resul Çetin. See [LICENSE](LICENSE).
