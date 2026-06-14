mod display;
mod inspect;
mod types;

use clap::Parser;
use serde::Serialize;
use types::Finding;

/// Inspect what process is using a port, or list all listening ports.
#[derive(Parser)]
#[command(name = "portspy", version, about)]
struct Cli {
    /// Port number to inspect (omit to list all listening ports)
    port: Option<u16>,

    /// Output as JSON for piping to jq or other tools
    #[arg(short, long)]
    json: bool,

    /// Kill the process(es) using the port — requires PORT
    #[arg(short, long)]
    kill: bool,

    /// Use SIGKILL instead of SIGTERM (with --kill)
    #[arg(short, long)]
    force: bool,

    /// Show extra process details: exe path, CWD (inspect mode only)
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.kill && cli.port.is_none() {
        eprintln!("error: --kill requires a port argument");
        std::process::exit(1);
    }

    match cli.port {
        Some(port) => {
            let findings = inspect::find_port_users(port)?;
            if findings.is_empty() {
                if cli.json {
                    println!("[]");
                } else {
                    println!(
                        "\n  No processes found using port {}.\n  (Try running with sudo for system processes.)",
                        port
                    );
                }
                return Ok(());
            }

            if cli.kill {
                let results = kill_processes(&findings, cli.force);
                if cli.json {
                    display::emit_json(&results);
                } else {
                    for r in &results {
                        if r.ok {
                            println!("  Sent {} to {} (PID {})", r.signal, r.name, r.pid);
                        } else {
                            eprintln!(
                                "  Failed to kill {} (PID {}): {}",
                                r.name,
                                r.pid,
                                r.error.as_deref().unwrap_or("unknown error")
                            );
                        }
                    }
                }
            } else if cli.json {
                display::emit_json(&findings);
            } else {
                display::render(&findings, cli.verbose);
            }
        }
        None => {
            let entries = inspect::list_all_ports()?;
            if cli.json {
                display::emit_json(&entries);
            } else {
                display::render_list(&entries);
            }
        }
    }

    Ok(())
}

// ── Kill ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct KillResult {
    pub pid: u32,
    pub name: String,
    pub signal: &'static str,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn kill_processes(findings: &[Finding], force: bool) -> Vec<KillResult> {
    use std::collections::HashSet;
    let signal_name = if force { "SIGKILL" } else { "SIGTERM" };
    let signum = if force { libc::SIGKILL } else { libc::SIGTERM };

    let mut seen: HashSet<u32> = HashSet::new();
    let mut results = Vec::new();

    for f in findings {
        let pid = f.process.pid;
        if !seen.insert(pid) {
            continue; // same PID appeared on multiple sockets (e.g. TCP + TCP6)
        }

        let name = if f.process.name.is_empty() {
            "<unknown>".to_string()
        } else {
            f.process.name.clone()
        };

        let rc = unsafe { libc::kill(pid as libc::pid_t, signum) };
        if rc == 0 {
            results.push(KillResult { pid, name, signal: signal_name, ok: true, error: None });
        } else {
            let err = std::io::Error::last_os_error().to_string();
            results.push(KillResult { pid, name, signal: signal_name, ok: false, error: Some(err) });
        }
    }

    results
}
