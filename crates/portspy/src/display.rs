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

    // Fixed-width columns
    const PORT_W: usize = 5;
    const BIND_W: usize = 16; // normalized bind addr, truncated
    const PROTO_W: usize = 5;
    const STATE_W: usize = 12;
    const PID_W: usize = 7;

    // Dynamic columns — derive from data
    let name_w = entries.iter().map(|e| e.process_name.len()).max().unwrap_or(7).max(7);
    let user_w = entries.iter().map(|e| e.user.len()).max().unwrap_or(4).max(4);

    let total = PORT_W + 2 + BIND_W + 2 + PROTO_W + 2 + STATE_W + 2 + name_w + 2 + user_w + 2 + PID_W;
    let sep = "─".repeat(total);

    println!("\n  {}", "portspy — listening ports".bold().white());
    println!("  {}", sep.dimmed());

    // Header: pre-pad plain strings, then color — avoids ANSI-byte padding bug
    println!(
        "  {}  {}  {}  {}  {}  {}  {}",
        col_r(PORT_W, "PORT").bold().dimmed(),
        col_l(BIND_W, "BIND").bold().dimmed(),
        col_l(PROTO_W, "PROTO").bold().dimmed(),
        col_l(STATE_W, "STATE").bold().dimmed(),
        col_l(name_w, "PROCESS").bold().dimmed(),
        col_l(user_w, "USER").bold().dimmed(),
        col_r(PID_W, "PID").bold().dimmed(),
    );
    println!("  {}", sep.dimmed());

    for e in entries {
        let bind = normalize_addr(&e.local_addr);
        let bind = trunc(&bind, BIND_W);
        let state_plain = e.state.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "—".into());
        let name = trunc(&e.process_name, name_w);

        // Pre-pad to column width as plain text, then apply color
        let port_col  = col_r(PORT_W,  &e.port.to_string()).yellow().bold().to_string();
        let bind_col  = col_l(BIND_W,  &bind).dimmed().to_string();
        let proto_col = color_proto(col_l(PROTO_W, &e.protocol.to_string()), &e.protocol);
        let state_col = color_state(col_l(STATE_W, &state_plain), &e.state);
        let name_col  = col_l(name_w,  &name).white().to_string();
        let user_col  = col_l(user_w,  &e.user).dimmed().to_string();
        let pid_col   = col_r(PID_W,   &e.pid.to_string()).dimmed().to_string();

        println!("  {}  {}  {}  {}  {}  {}  {}",
            port_col, bind_col, proto_col, state_col, name_col, user_col, pid_col);
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

// ── Formatting helpers ────────────────────────────────────────────────────────

/// Left-pad a plain string to `w` chars — do this BEFORE applying color.
fn col_l(w: usize, s: &str) -> String {
    format!("{:<w$}", s, w = w)
}

/// Right-pad a plain string to `w` chars — do this BEFORE applying color.
fn col_r(w: usize, s: &str) -> String {
    format!("{:>w$}", s, w = w)
}

/// Truncate to `max` visible chars, appending `~` if cut.
fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}~", &s[..max.saturating_sub(1)])
    }
}

/// Normalize wildcard/loopback addresses for compact display.
fn normalize_addr(addr: &str) -> String {
    match addr {
        "0.0.0.0" | "::" | "[::]" => "*".to_string(),
        "127.0.0.1" => "localhost".to_string(),
        "::1" | "[::1]" => "localhost6".to_string(),
        other => other.to_string(),
    }
}

fn color_proto(padded: String, proto: &Protocol) -> String {
    match proto {
        Protocol::Tcp | Protocol::Tcp6 => padded.cyan().to_string(),
        Protocol::Udp | Protocol::Udp6 => padded.magenta().to_string(),
        Protocol::Unknown(_) => padded.dimmed().to_string(),
    }
}

fn color_state(padded: String, state: &Option<TcpState>) -> String {
    match state {
        Some(TcpState::Listen) => padded.green().to_string(),
        Some(TcpState::Established) => padded.bright_green().to_string(),
        Some(TcpState::TimeWait) | Some(TcpState::FinWait1) | Some(TcpState::FinWait2) => {
            padded.yellow().to_string()
        }
        Some(TcpState::CloseWait) | Some(TcpState::LastAck) | Some(TcpState::Closing) => {
            padded.red().to_string()
        }
        _ => padded.dimmed().to_string(),
    }
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
