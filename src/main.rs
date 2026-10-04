//! portolan — a fast, dependency-free TCP port scanner and service mapper.
//!
//! Scan only hosts you own or are explicitly authorized to test. Port scanning
//! systems without permission may be illegal in your jurisdiction.

mod ports;
mod report;
mod scan;
mod targets;

use scan::{Config, Progress};
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const USAGE: &str = "\
portolan — a fast TCP port scanner and service mapper

USAGE:
    portolan <TARGETS> [OPTIONS]

TARGETS (comma- or space-separated):
    192.168.1.10              a single host
    example.com              a hostname (resolved via DNS)
    192.168.1.0/24           a CIDR block (IPv4, /16 or smaller)
    192.168.1.10-20          an address range

OPTIONS:
    -p, --ports <SPEC>       ports: 22,80,443 or 1-1024 (default: top 100)
        --top <N>            scan the N most common ports (default: 100)
        --all                scan all 65535 ports
    -t, --timeout <MS>       connect timeout per port (default: 500)
    -c, --concurrency <N>    parallel workers (default: 512)
    -b, --banner             grab service banners from open ports
    -f, --format <text|json|grepable>   output format (default: text)
    -o, --output <FILE>      write report to FILE
        --open-only          (default) only show open ports
        --no-color           disable colours
        --no-progress        don't print the progress line
    -h, --help               show this help
    -V, --version            print version

EXAMPLES:
    portolan 127.0.0.1
    portolan 192.168.1.0/24 -p 22,80,443 -b
    portolan example.com --top 1000 -f json -o scan.json

AUTHORIZATION:
    Only scan hosts you own or are explicitly authorized to test. Unauthorized
    scanning may violate computer-misuse laws and acceptable-use policies.
";

struct Args {
    targets: Vec<String>,
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
    banner: bool,
    format: String,
    output: Option<String>,
    no_color: bool,
    no_progress: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut targets = Vec::new();
    let mut port_spec: Option<String> = None;
    let mut top: Option<usize> = None;
    let mut all = false;
    let mut timeout_ms = 500u64;
    let mut concurrency = 512usize;
    let mut banner = false;
    let mut format = "text".to_string();
    let mut output = None;
    let mut no_color = std::env::var_os("NO_COLOR").is_some();
    let mut no_progress = false;

    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        let mut next = || {
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "-p" | "--ports" => port_spec = Some(next()?),
            "--top" => {
                top = Some(
                    next()?
                        .parse()
                        .map_err(|_| "--top needs a number".to_string())?,
                )
            }
            "--all" => all = true,
            "-t" | "--timeout" => {
                timeout_ms = next()?
                    .parse()
                    .map_err(|_| "--timeout needs a number".to_string())?
            }
            "-c" | "--concurrency" => {
                concurrency = next()?
                    .parse()
                    .map_err(|_| "--concurrency needs a number".to_string())?
            }
            "-b" | "--banner" => banner = true,
            "-f" | "--format" => format = next()?,
            "-o" | "--output" => output = Some(next()?),
            "--open-only" => {}
            "--no-color" => no_color = true,
            "--no-progress" => no_progress = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("portolan {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other if other.starts_with('-') => return Err(format!("unknown option '{other}'")),
            other => targets.push(other.to_string()),
        }
        i += 1;
    }

    if targets.is_empty() {
        return Err("no targets given (try `portolan --help`)".into());
    }
    if !["text", "json", "grepable"].contains(&format.as_str()) {
        return Err(format!("unknown format '{format}'"));
    }
    if concurrency == 0 {
        return Err("--concurrency must be at least 1".into());
    }

    let ports = if all {
        ports::all_ports()
    } else if let Some(spec) = port_spec {
        ports::parse_spec(&spec)?
    } else {
        ports::top_ports(top.unwrap_or(100))
    };

    Ok(Args {
        targets,
        ports,
        timeout: Duration::from_millis(timeout_ms),
        concurrency,
        banner,
        format,
        output,
        no_color,
        no_progress,
    })
}

fn draw_progress(progress: &Arc<Progress>, stop: &Arc<std::sync::atomic::AtomicBool>) {
    let bar_width = 28;
    while !stop.load(Ordering::Relaxed) {
        let done = progress.done.load(Ordering::Relaxed);
        let open = progress.open.load(Ordering::Relaxed);
        let total = progress.total.max(1);
        let frac = (done as f64 / total as f64).min(1.0);
        let filled = (frac * bar_width as f64) as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
        eprint!("\r  [{bar}] {done}/{total}  {open} open");
        let _ = std::io::stderr().flush();
        if done >= total {
            break;
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    eprint!("\r{}\r", " ".repeat(60));
    let _ = std::io::stderr().flush();
}

fn run() -> Result<i32, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv)?;

    let targets = targets::expand_all(&args.targets)?;
    if targets.is_empty() {
        return Err("targets expanded to nothing".into());
    }
    let total = targets.len() * args.ports.len();

    let use_color = !args.no_color && args.output.is_none();
    if !args.no_progress && args.format == "text" && args.output.is_none() {
        eprintln!(
            "portolan: scanning {} host(s) × {} port(s) = {} probes (authorized targets only)",
            targets.len(),
            args.ports.len(),
            total
        );
    }

    let cfg = Config {
        timeout: args.timeout,
        workers: args.concurrency,
        grab_banner: args.banner,
        banner_timeout: Duration::from_millis(1200),
    };
    let progress = Arc::new(Progress {
        done: AtomicUsize::new(0),
        open: AtomicUsize::new(0),
        total,
    });

    // Progress bar on a side thread (text mode, interactive stderr only).
    let show_progress = !args.no_progress
        && args.format == "text"
        && args.output.is_none()
        && std::io::stderr().is_terminal();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bar_handle = if show_progress {
        let p = Arc::clone(&progress);
        let s = Arc::clone(&stop);
        Some(std::thread::spawn(move || draw_progress(&p, &s)))
    } else {
        None
    };

    let start = Instant::now();
    let open = scan::run(&targets, &args.ports, &cfg, &progress);
    let elapsed = start.elapsed();

    stop.store(true, Ordering::Relaxed);
    if let Some(h) = bar_handle {
        let _ = h.join();
    }

    let out = match args.format.as_str() {
        "json" => report::render_json(&open, targets.len(), args.ports.len(), elapsed),
        "grepable" => report::render_grepable(&open),
        _ => report::render_table(
            &open,
            targets.len(),
            args.ports.len(),
            elapsed,
            args.banner,
            use_color,
        ),
    };

    match &args.output {
        Some(path) => {
            std::fs::write(path, &out).map_err(|e| format!("cannot write {path}: {e}"))?;
            eprintln!("portolan: report written to {path}");
        }
        None => print!("{out}"),
    }

    Ok(if open.is_empty() { 1 } else { 0 })
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("portolan: {e}");
            std::process::exit(2);
        }
    }
}
