use crate::types::*;
use anyhow::Result;

pub fn find_port_users(port: u16) -> Result<Vec<Finding>> {
    platform::find_port_users(port)
}

pub fn list_all_ports() -> Result<Vec<ListEntry>> {
    platform::list_all_ports()
}

// ── macOS implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use sysinfo::{Pid, System, Users};
    use std::process::Command;

    // Raw parsed row from lsof output
    struct LsofRow {
        pid: u32,
        user: String,
        command: String,
        socket: SocketInfo,
    }

    pub fn find_port_users(port: u16) -> Result<Vec<Finding>> {
        let output = Command::new("lsof")
            .args([
                "-i", &format!("TCP:{}", port),
                "-i", &format!("UDP:{}", port),
                "-n", "-P",
            ])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rows = parse_lsof(&stdout, Some(port));

        let mut sys = System::new_all();
        sys.refresh_all();
        let users = Users::new_with_refreshed_list();

        let findings = rows
            .into_iter()
            .map(|row| {
                let process = enrich_process(row.pid, &row.user, &sys, &users);
                Finding { socket: row.socket, process }
            })
            .collect();

        Ok(findings)
    }

    pub fn list_all_ports() -> Result<Vec<ListEntry>> {
        // -sTCP:LISTEN keeps only TCP listeners; UDP has no states
        let output = Command::new("lsof")
            .args(["-iTCP", "-iUDP", "-n", "-P", "-sTCP:LISTEN"])
            .output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut entries: Vec<ListEntry> = parse_lsof(&stdout, None)
            .into_iter()
            .filter(|row| row.socket.local_port != 0) // skip unbound sockets
            .map(|row| ListEntry {
                port: row.socket.local_port,
                protocol: row.socket.protocol,
                local_addr: row.socket.local_addr,
                state: row.socket.state,
                process_name: row.command,
                pid: row.pid,
                user: row.user,
            })
            .collect();

        entries.sort_by_key(|e| (e.port, e.protocol.sort_key(), e.pid));
        Ok(entries)
    }

    /// Parse lsof output. When `port_filter` is Some, only rows on that port
    /// are returned; when None, all rows are returned.
    fn parse_lsof(output: &str, port_filter: Option<u16>) -> Vec<LsofRow> {
        let mut rows = Vec::new();
        let mut lines = output.lines();

        let header = match lines.next() {
            Some(h) => h,
            None => return rows,
        };
        let name_offset = header.find("NAME").unwrap_or(0);

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let command = parts[0].to_string();
            let pid: u32 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let user = parts[2].to_string();
            let fd = parts[3].to_string();
            let ip_type = parts[4];  // IPv4, IPv6
            let node_proto = parts[7]; // TCP, UDP

            let name = if name_offset < line.len() {
                line[name_offset..].trim()
            } else {
                parts[8..].join(" ").leak()
            };

            let protocol = match node_proto {
                "TCP" if ip_type.contains('6') => Protocol::Tcp6,
                "TCP" => Protocol::Tcp,
                "UDP" if ip_type.contains('6') => Protocol::Udp6,
                "UDP" => Protocol::Udp,
                other => Protocol::Unknown(other.to_string()),
            };

            let (local, remote, state) = parse_name(name);
            let (local_addr, local_port) = split_addr(&local);

            if let Some(filter_port) = port_filter {
                if local_port != filter_port {
                    let ok = remote.as_ref().map(|r| split_addr(r).1 == filter_port).unwrap_or(false);
                    if !ok {
                        continue;
                    }
                }
            }

            let (remote_addr, remote_port) = match remote {
                Some(r) => {
                    let (ra, rp) = split_addr(&r);
                    (Some(ra), Some(rp))
                }
                None => (None, None),
            };

            rows.push(LsofRow {
                pid,
                user,
                command,
                socket: SocketInfo {
                    protocol,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    state,
                    fd,
                },
            });
        }
        rows
    }

    /// Parses the lsof NAME field: `local[->remote] [(STATE)]`
    fn parse_name(name: &str) -> (String, Option<String>, Option<TcpState>) {
        let (addr_part, state) =
            if let (Some(start), Some(end)) = (name.rfind('('), name.rfind(')')) {
                if start < end {
                    let state_str = &name[start + 1..end];
                    (name[..start].trim(), Some(TcpState::from_lsof(state_str)))
                } else {
                    (name, None)
                }
            } else {
                (name, None)
            };

        if let Some(arrow) = addr_part.find("->") {
            let local = addr_part[..arrow].trim().to_string();
            let remote = addr_part[arrow + 2..].trim().to_string();
            (local, Some(remote), state)
        } else {
            (addr_part.trim().to_string(), None, state)
        }
    }

    /// Splits `host:port`, `*:port`, or `[::1]:port`
    fn split_addr(addr: &str) -> (String, u16) {
        if addr.starts_with('[') {
            if let Some(end) = addr.find(']') {
                let host = addr[..=end].to_string();
                let port = addr.get(end + 2..).and_then(|s| s.parse().ok()).unwrap_or(0);
                return (host, port);
            }
        }
        if let Some(colon) = addr.rfind(':') {
            let host = addr[..colon].to_string();
            let port: u16 = addr[colon + 1..].parse().unwrap_or(0);
            (host, port)
        } else {
            (addr.to_string(), 0)
        }
    }

    fn enrich_process(pid: u32, lsof_user: &str, sys: &System, users: &Users) -> ProcessInfo {
        let sysinfo_pid = Pid::from(pid as usize);

        if let Some(proc) = sys.process(sysinfo_pid) {
            let user = proc
                .user_id()
                .and_then(|uid| users.get_user_by_id(uid))
                .map(|u| u.name().to_string())
                .unwrap_or_else(|| lsof_user.to_string());

            let parent_pid = proc.parent().map(|p| p.as_u32());
            let parent_name = parent_pid
                .and_then(|ppid| sys.process(Pid::from(ppid as usize)))
                .map(|p| p.name().to_string_lossy().to_string());

            let cmdline = if proc.cmd().is_empty() {
                proc.name().to_string_lossy().to_string()
            } else {
                proc.cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            };

            ProcessInfo {
                pid,
                name: proc.name().to_string_lossy().to_string(),
                cmdline,
                user,
                parent_pid,
                parent_name,
                memory_bytes: proc.memory(),
                virtual_memory_bytes: proc.virtual_memory(),
                run_time_secs: proc.run_time(),
                start_time_secs: proc.start_time(),
                cwd: proc.cwd().map(|p| p.to_string_lossy().to_string()),
                exe: proc.exe().map(|p| p.to_string_lossy().to_string()),
            }
        } else {
            ProcessInfo {
                pid,
                name: String::new(),
                cmdline: String::new(),
                user: lsof_user.to_string(),
                parent_pid: None,
                parent_name: None,
                memory_bytes: 0,
                virtual_memory_bytes: 0,
                run_time_secs: 0,
                start_time_secs: 0,
                cwd: None,
                exe: None,
            }
        }
    }
}

// ── Linux implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use sysinfo::{Pid, System, Users};
    use std::collections::HashMap;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub fn find_port_users(port: u16) -> Result<Vec<Finding>> {
        let inode_map = collect_sockets(Some(port))?;
        if inode_map.is_empty() {
            return Ok(vec![]);
        }
        let inode_to_pid = find_pids_for_inodes(&inode_map.keys().cloned().collect::<Vec<_>>());

        let mut sys = System::new_all();
        sys.refresh_all();
        let users = Users::new_with_refreshed_list();

        let findings = inode_map
            .into_iter()
            .filter_map(|(inode, socket)| {
                let pid = *inode_to_pid.get(&inode)?;
                let process = enrich_process(pid, &sys, &users);
                Some(Finding { socket, process })
            })
            .collect();

        Ok(findings)
    }

    pub fn list_all_ports() -> Result<Vec<ListEntry>> {
        let inode_map = collect_sockets(None)?;
        if inode_map.is_empty() {
            return Ok(vec![]);
        }

        // Only keep LISTEN (TCP) and all UDP sockets
        let filtered: HashMap<u64, SocketInfo> = inode_map
            .into_iter()
            .filter(|(_, sock)| {
                matches!(
                    sock.state,
                    None | Some(TcpState::Listen)
                )
            })
            .collect();

        let inode_to_pid = find_pids_for_inodes(&filtered.keys().cloned().collect::<Vec<_>>());

        let mut sys = System::new_all();
        sys.refresh_all();
        let users = Users::new_with_refreshed_list();

        let mut entries: Vec<ListEntry> = filtered
            .into_iter()
            .filter_map(|(inode, socket)| {
                let pid = *inode_to_pid.get(&inode)?;
                let proc = sys.process(Pid::from(pid as usize))?;
                let user = proc
                    .user_id()
                    .and_then(|uid| users.get_user_by_id(uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_default();
                Some(ListEntry {
                    port: socket.local_port,
                    protocol: socket.protocol,
                    local_addr: socket.local_addr,
                    state: socket.state,
                    process_name: proc.name().to_string_lossy().to_string(),
                    pid,
                    user,
                })
            })
            .collect();

        entries.sort_by_key(|e| (e.port, e.protocol.sort_key(), e.pid));
        Ok(entries)
    }

    fn collect_sockets(port_filter: Option<u16>) -> Result<HashMap<u64, SocketInfo>> {
        let mut map = HashMap::new();
        for (path, proto) in &[
            ("/proc/net/tcp", Protocol::Tcp),
            ("/proc/net/tcp6", Protocol::Tcp6),
            ("/proc/net/udp", Protocol::Udp),
            ("/proc/net/udp6", Protocol::Udp6),
        ] {
            if let Ok(entries) = read_proc_net(path, proto.clone(), port_filter) {
                map.extend(entries);
            }
        }
        Ok(map)
    }

    fn read_proc_net(
        path: &str,
        proto: Protocol,
        port_filter: Option<u16>,
    ) -> Result<Vec<(u64, SocketInfo)>> {
        let content = fs::read_to_string(path)?;
        let is_v6 = matches!(proto, Protocol::Tcp6 | Protocol::Udp6);
        let is_udp = matches!(proto, Protocol::Udp | Protocol::Udp6);
        let mut results = Vec::new();

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let local_raw = fields[1];
            let remote_raw = fields[2];
            let state_hex = fields[3];
            let inode: u64 = fields[9].parse().unwrap_or(0);

            let (local_addr, local_port) =
                if is_v6 { parse_hex_addr_v6(local_raw) } else { parse_hex_addr_v4(local_raw) };
            let (remote_addr, remote_port) =
                if is_v6 { parse_hex_addr_v6(remote_raw) } else { parse_hex_addr_v4(remote_raw) };

            if let Some(p) = port_filter {
                if local_port != p && remote_port != p {
                    continue;
                }
            }

            let state = if is_udp { None } else { Some(TcpState::from_hex(state_hex)) };

            results.push((
                inode,
                SocketInfo {
                    protocol: proto.clone(),
                    local_addr,
                    local_port,
                    remote_addr: if remote_port == 0 { None } else { Some(remote_addr) },
                    remote_port: if remote_port == 0 { None } else { Some(remote_port) },
                    state,
                    fd: String::new(),
                },
            ));
        }
        Ok(results)
    }

    fn parse_hex_addr_v4(raw: &str) -> (String, u16) {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 2 {
            return ("?".to_string(), 0);
        }
        let ip_num = u32::from_str_radix(parts[0], 16).unwrap_or(0);
        let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
        let ip = Ipv4Addr::from(ip_num.to_ne_bytes());
        (ip.to_string(), port)
    }

    fn parse_hex_addr_v6(raw: &str) -> (String, u16) {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 2 {
            return ("?".to_string(), 0);
        }
        let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
        let hex = parts[0];
        if hex.len() != 32 {
            return ("?".to_string(), port);
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
            let word_hex = std::str::from_utf8(chunk).unwrap_or("00000000");
            let word = u32::from_str_radix(word_hex, 16).unwrap_or(0);
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        (Ipv6Addr::from(bytes).to_string(), port)
    }

    fn find_pids_for_inodes(inodes: &[u64]) -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        let targets: std::collections::HashSet<u64> = inodes.iter().cloned().collect();

        let Ok(proc_dir) = fs::read_dir("/proc") else { return map; };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };

            let Ok(fds) = fs::read_dir(format!("/proc/{}/fd", pid)) else { continue; };

            for fd in fds.flatten() {
                if let Ok(link) = fs::read_link(fd.path()) {
                    let s = link.to_string_lossy();
                    if let Some(inode_str) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            if targets.contains(&inode) {
                                map.insert(inode, pid);
                            }
                        }
                    }
                }
            }
        }
        map
    }

    fn enrich_process(pid: u32, sys: &System, users: &Users) -> ProcessInfo {
        if let Some(proc) = sys.process(Pid::from(pid as usize)) {
            let user = proc
                .user_id()
                .and_then(|uid| users.get_user_by_id(uid))
                .map(|u| u.name().to_string())
                .unwrap_or_default();

            let parent_pid = proc.parent().map(|p| p.as_u32());
            let parent_name = parent_pid
                .and_then(|ppid| sys.process(Pid::from(ppid as usize)))
                .map(|p| p.name().to_string_lossy().to_string());

            let cmdline = if proc.cmd().is_empty() {
                proc.name().to_string_lossy().to_string()
            } else {
                proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")
            };

            ProcessInfo {
                pid,
                name: proc.name().to_string_lossy().to_string(),
                cmdline,
                user,
                parent_pid,
                parent_name,
                memory_bytes: proc.memory(),
                virtual_memory_bytes: proc.virtual_memory(),
                run_time_secs: proc.run_time(),
                start_time_secs: proc.start_time(),
                cwd: proc.cwd().map(|p| p.to_string_lossy().to_string()),
                exe: proc.exe().map(|p| p.to_string_lossy().to_string()),
            }
        } else {
            ProcessInfo {
                pid,
                name: String::new(),
                cmdline: String::new(),
                user: String::new(),
                parent_pid: None,
                parent_name: None,
                memory_bytes: 0,
                virtual_memory_bytes: 0,
                run_time_secs: 0,
                start_time_secs: 0,
                cwd: None,
                exe: None,
            }
        }
    }
}
