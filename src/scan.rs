//! TCP connect scanning with a fixed-size worker pool.
//!
//! A connect scan completes the TCP handshake, so it needs no raw sockets and
//! no elevated privileges — it works the same for any user on any platform.
//! That is a deliberate trade-off: it is a little more visible to the target
//! than a half-open scan, in exchange for being portable and requiring no root.

use crate::ports;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Open {
    pub ip: IpAddr,
    pub host: String,
    pub port: u16,
    pub service: &'static str,
    pub banner: Option<String>,
    pub rtt_ms: u128,
}

pub struct Config {
    pub timeout: Duration,
    pub workers: usize,
    pub grab_banner: bool,
    pub banner_timeout: Duration,
}

pub struct Progress {
    pub done: AtomicUsize,
    pub open: AtomicUsize,
    pub total: usize,
}

struct Job {
    host: String,
    ip: IpAddr,
    port: u16,
}

/// Scan every (target, port) pair. `on_tick` is called (from the main thread)
/// as results arrive, so a caller can render a progress bar.
pub fn run(
    targets: &[(String, IpAddr)],
    ports: &[u16],
    cfg: &Config,
    progress: &Arc<Progress>,
) -> Vec<Open> {
    let jobs: Vec<Job> = targets
        .iter()
        .flat_map(|(host, ip)| {
            ports.iter().map(move |&port| Job {
                host: host.clone(),
                ip: *ip,
                port,
            })
        })
        .collect();

    let queue = Arc::new(Mutex::new(jobs.into_iter()));
    let (tx, rx) = mpsc::channel::<Open>();
    let workers = cfg.workers.max(1);
    let timeout = cfg.timeout;
    let grab = cfg.grab_banner;
    let banner_timeout = cfg.banner_timeout;

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let progress = Arc::clone(progress);
        handles.push(thread::spawn(move || loop {
            let job = {
                let mut guard = queue.lock().unwrap();
                guard.next()
            };
            let job = match job {
                Some(j) => j,
                None => break,
            };
            if let Some(open) = probe(&job, timeout, grab, banner_timeout) {
                progress.open.fetch_add(1, Ordering::Relaxed);
                let _ = tx.send(open);
            }
            progress.done.fetch_add(1, Ordering::Relaxed);
        }));
    }
    drop(tx); // so rx closes once all workers finish

    let mut results: Vec<Open> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    results.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));
    results
}

fn probe(job: &Job, timeout: Duration, grab: bool, banner_timeout: Duration) -> Option<Open> {
    let addr = SocketAddr::new(job.ip, job.port);
    let start = Instant::now();
    let stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let rtt_ms = start.elapsed().as_millis();
    let banner = if grab {
        grab_banner(&stream, job.port, banner_timeout)
    } else {
        None
    };
    let _ = stream.shutdown(Shutdown::Both);
    Some(Open {
        ip: job.ip,
        host: job.host.clone(),
        port: job.port,
        service: ports::service_name(job.port),
        banner,
        rtt_ms,
    })
}

/// Read a service banner. For quiet protocols that expect the client to speak
/// first (HTTP), send a minimal, benign request. Never sends anything that
/// isn't a well-formed, read-only request.
fn grab_banner(stream: &TcpStream, port: u16, timeout: Duration) -> Option<String> {
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut s = stream.try_clone().ok()?;

    if matches!(
        port,
        80 | 8080 | 8000 | 8888 | 8008 | 3000 | 5000 | 9200 | 9999
    ) {
        let host = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "host".into());
        let req = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: portolan\r\n\r\n");
        s.write_all(req.as_bytes()).ok()?;
    }

    let mut buf = [0u8; 512];
    let n = s.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(clean_banner(&buf[..n], port))
}

fn clean_banner(bytes: &[u8], port: u16) -> String {
    let text = String::from_utf8_lossy(bytes);
    // For HTTP, the Server header is the useful part.
    if matches!(port, 80 | 8080 | 8000 | 8888 | 8008 | 3000 | 5000 | 9999) {
        for line in text.lines() {
            if let Some(server) = line
                .strip_prefix("Server:")
                .or_else(|| line.strip_prefix("server:"))
            {
                return format!("Server:{}", server.trim_end());
            }
        }
        // fall back to the status line
        if let Some(first) = text.lines().next() {
            return first.trim().chars().take(80).collect();
        }
    }
    let first_line: String = text
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    first_line.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn finds_an_open_local_port() {
        // Bind an ephemeral port, then scan it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let targets = vec![("127.0.0.1".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let cfg = Config {
            timeout: Duration::from_millis(300),
            workers: 4,
            grab_banner: false,
            banner_timeout: Duration::from_millis(200),
        };
        let progress = Arc::new(Progress {
            done: AtomicUsize::new(0),
            open: AtomicUsize::new(0),
            total: 1,
        });
        let open = run(&targets, &[port], &cfg, &progress);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].port, port);
        assert_eq!(progress.done.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn closed_port_is_not_reported() {
        // Bind then drop to get a port that is almost certainly closed.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let targets = vec![("127.0.0.1".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let cfg = Config {
            timeout: Duration::from_millis(200),
            workers: 2,
            grab_banner: false,
            banner_timeout: Duration::from_millis(100),
        };
        let progress = Arc::new(Progress {
            done: AtomicUsize::new(0),
            open: AtomicUsize::new(0),
            total: 1,
        });
        let open = run(&targets, &[port], &cfg, &progress);
        assert!(open.is_empty());
    }

    #[test]
    fn http_banner_extracts_server_header() {
        let b = clean_banner(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n", 80);
        assert_eq!(b, "Server: nginx/1.25");
    }
}
