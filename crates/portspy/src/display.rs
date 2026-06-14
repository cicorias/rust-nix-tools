use crate::types::{Finding, ListEntry, Protocol, TcpState};
use colored::Colorize;
use std::time::{Duration, SystemTime};

pub fn render(findings: &[Finding], verbose: bool) {
    let count = findings.len();
    let port = findings.first().map(|f| f.socket.local_port).unwrap_or(0);

    println!(
        "\n{}",
        format!("  portspy — port {}", port).bold().white()
    );
    println!("  {}", "─".repeat(56).dimmed());
    println!(
        "  {} socket(s) found\n",
        count.to_string().bold().yellow()
    );

    for finding in findings {
        render_finding(finding, verbose);
    }
}

pub fn render_list(entries: &[ListEntry]) {
    if entries.is_empty() {
        println!("\n  No listening ports found.\n  (Try running with sudo for system processes.)");
        return;
    }

    // Build the ADDR column as "local_addr:port"
    let addr_strs: Vec<String> = entries
        .iter()
        .map(|e| format!("{}:{}", e.local_addr, e.port))
        .collect();

    let addr_width = addr_strs.iter().map(|s| s.len()).max().unwrap_or(4).max(4);
    let name_width = entries.iter().map(|e| e.process_name.len()).max().unwrap_or(7).max(7);
    let user_width = entries.iter().map(|e| e.user.len()).max().unwrap_or(4).max(4);

    // sep width = addr + 2 + proto(5) + 2 + state(11) + 2 + name + 2 + user + 2 + pid(7)
    let sep = "─".repeat(addr_width + 2 + 5 + 2 + 11 + 2 + name_width + 2 + user_width + 2 + 7);

    println!("\n  {}", "portspy — listening ports".bold().white());
    println!("  {}", sep.dimmed());
    println!(
        "  {:<addr_width$}  {:<5}  {:<11}  {:<name_width$}  {:<user_width$}  {:>7}",
        "ADDR".bold().dimmed(),
        "PROTO".bold().dimmed(),
        "STATE".bold().dimmed(),
        "PROCESS".bold().dimmed(),
        "USER".bold().dimmed(),
        "PID".bold().dimmed(),
        addr_width = addr_width,
        name_width = name_width,
        user_width = user_width,
    );
    println!("  {}", sep.dimmed());

    for (e, addr_str) in entries.iter().zip(addr_strs.iter()) {
        let proto_str = e.protocol.to_string();
        let proto_col = match e.protocol {
            Protocol::Tcp | Protocol::Tcp6 => proto_str.cyan().to_string(),
            Protocol::Udp | Protocol::Udp6 => proto_str.magenta().to_string(),
            Protocol::Unknown(_) => proto_str.dimmed().to_string(),
        };

        let state_col = match &e.state {
            Some(s) => {
                let t = s.to_string();
                match s {
                    TcpState::Listen => t.green().to_string(),
                    TcpState::Established => t.bright_green().to_string(),
                    TcpState::TimeWait | TcpState::FinWait1 | TcpState::FinWait2 => {
                        t.yellow().to_string()
                    }
                    _ => t.dimmed().to_string(),
                }
            }
            None => "—".dimmed().to_string(),
        };

        let name_col = if e.process_name.is_empty() {
            "<unknown>".dimmed().to_string()
        } else {
            e.process_name.white().to_string()
        };

        println!(
            "  {:<addr_width$}  {:<5}  {:<11}  {:<name_width$}  {:<user_width$}  {:>7}",
            addr_str.yellow().to_string(),
            proto_col,
            state_col,
            name_col,
            e.user.dimmed().to_string(),
            e.pid.to_string().dimmed(),
            addr_width = addr_width,
            name_width = name_width,
            user_width = user_width,
        );
    }

    println!("  {}", sep.dimmed());

    let unique_ports: std::collections::HashSet<u16> = entries.iter().map(|e| e.port).collect();
    let unique_procs: std::collections::HashSet<u32> = entries.iter().map(|e| e.pid).collect();
    println!(
        "  {} ports  ·  {} processes\n",
        unique_ports.len().to_string().bold(),
        unique_procs.len().to_string().bold(),
    );
}

fn render_finding(f: &Finding, verbose: bool) {
    let sock = &f.socket;
    let proc = &f.process;

    // ── Socket line ──────────────────────────────────────────────────────────
    let proto_str = format!("{}", sock.protocol);
    let proto_colored = match sock.protocol {
        Protocol::Tcp | Protocol::Tcp6 => proto_str.cyan().bold(),
        Protocol::Udp | Protocol::Udp6 => proto_str.magenta().bold(),
        Protocol::Unknown(_) => proto_str.dimmed(),
    };

    let addr_str = match (&sock.remote_addr, sock.remote_port) {
        (Some(ra), Some(rp)) => format!("{}:{} → {}:{}", sock.local_addr, sock.local_port, ra, rp),
        _ => format!("{}:{}", sock.local_addr, sock.local_port),
    };

    let state_str = match &sock.state {
        Some(s) => {
            let s_fmt = format!("[{}]", s);
            match s {
                TcpState::Listen => s_fmt.green().bold().to_string(),
                TcpState::Established => s_fmt.bright_green().to_string(),
                TcpState::TimeWait | TcpState::FinWait1 | TcpState::FinWait2 => {
                    s_fmt.yellow().to_string()
                }
                TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => {
                    s_fmt.red().to_string()
                }
                _ => s_fmt.dimmed().to_string(),
            }
        }
        None => String::new(),
    };

    println!(
        "  {} {}  {}",
        proto_colored,
        addr_str.white().bold(),
        state_str
    );

    // ── Process tree ─────────────────────────────────────────────────────────
    field("Process", &format!(
        "{} {}",
        if proc.name.is_empty() { "<unknown>".to_string() } else { proc.name.clone() }.bold().white().to_string(),
        format!("(PID {})", proc.pid).dimmed().to_string()
    ));

    if !proc.user.is_empty() {
        field("User", &proc.user.bright_white().to_string());
    }

    if !proc.cmdline.is_empty() && proc.cmdline != proc.name {
        field("Command", &proc.cmdline.dimmed().to_string());
    }

    if let Some(ref exe) = proc.exe {
        if verbose {
            field("Exe", &exe.dimmed().to_string());
        }
    }

    if let Some(ppid) = proc.parent_pid {
        let parent_label = match &proc.parent_name {
            Some(name) => format!("{} (PID {})", name.bold(), ppid),
            None => format!("PID {}", ppid),
        };
        field("Parent", &parent_label);
    }

    if let Some(ref cwd) = proc.cwd {
        if verbose {
            field("CWD", &cwd.dimmed().to_string());
        }
    }

    // ── Memory ───────────────────────────────────────────────────────────────
    if proc.memory_bytes > 0 {
        field(
            "Memory",
            &format!(
                "{}  (virt {})",
                fmt_bytes(proc.memory_bytes).green().to_string(),
                fmt_bytes(proc.virtual_memory_bytes).dimmed().to_string()
            ),
        );
    }

    // ── Uptime ───────────────────────────────────────────────────────────────
    if proc.run_time_secs > 0 || proc.start_time_secs > 0 {
        let started = if proc.start_time_secs > 0 {
            fmt_unix_time(proc.start_time_secs)
        } else {
            String::new()
        };
        let uptime = fmt_duration(proc.run_time_secs);
        field(
            "Started",
            &format!(
                "{} {} ago",
                started.dimmed(),
                uptime.yellow()
            ),
        );
    }

    println!();
}

fn field(label: &str, value: &str) {
    println!(
        "    {:<12}  {}",
        format!("{}:", label).dimmed(),
        value
    );
}

fn fmt_bytes(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const KB: u64 = 1024;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn fmt_duration(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    } else if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

fn fmt_unix_time(unix_secs: u64) -> String {
    use std::time::UNIX_EPOCH;
    let dt = UNIX_EPOCH + Duration::from_secs(unix_secs);
    // Simple ISO-ish format without pulling in chrono
    match SystemTime::now().duration_since(dt) {
        Ok(_) => {
            // Convert to local-ish display using the offset trick
            // We just show UTC here for portability without chrono
            let secs_since_epoch = unix_secs;
            let (y, mo, d, h, mi, s) = secs_to_ymd(secs_since_epoch);
            format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, mi, s)
        }
        Err(_) => "unknown".to_string(),
    }
}

// Minimal UTC calendar conversion without external deps
fn secs_to_ymd(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let mins = secs / 60;
    let mi = mins % 60;
    let hours = mins / 60;
    let h = hours % 24;
    let mut days = hours / 24;

    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = [31u64, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0u64;
    for (i, &dm) in months.iter().enumerate() {
        if days < dm {
            month = i as u64 + 1;
            break;
        }
        days -= dm;
    }
    (year, month, days + 1, h, mi, s)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
