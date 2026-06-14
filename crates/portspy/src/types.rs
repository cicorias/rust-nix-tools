use std::fmt;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Tcp6,
    Udp6,
    Unknown(String),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Tcp6 => write!(f, "TCP6"),
            Protocol::Udp6 => write!(f, "UDP6"),
            Protocol::Unknown(s) => write!(f, "{}", s),
        }
    }
}

impl Serialize for Protocol {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpState {
    Listen,
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Closing,
    Unknown(String),
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECEIVED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT2"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::Unknown(s) => write!(f, "{}", s),
        }
    }
}

impl Serialize for TcpState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl TcpState {
    pub fn from_lsof(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "LISTEN" => TcpState::Listen,
            "ESTABLISHED" => TcpState::Established,
            "SYN_SENT" => TcpState::SynSent,
            "SYN_RECEIVED" | "SYN_RECV" => TcpState::SynReceived,
            "FIN_WAIT1" | "FIN_WAIT_1" => TcpState::FinWait1,
            "FIN_WAIT2" | "FIN_WAIT_2" => TcpState::FinWait2,
            "TIME_WAIT" => TcpState::TimeWait,
            "CLOSED" => TcpState::Closed,
            "CLOSE_WAIT" => TcpState::CloseWait,
            "LAST_ACK" => TcpState::LastAck,
            "CLOSING" => TcpState::Closing,
            other => TcpState::Unknown(other.to_string()),
        }
    }

    /// Linux `/proc/net/tcp` hex state codes
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn from_hex(hex: &str) -> Self {
        match hex {
            "01" => TcpState::Established,
            "02" => TcpState::SynSent,
            "03" => TcpState::SynReceived,
            "04" => TcpState::FinWait1,
            "05" => TcpState::FinWait2,
            "06" => TcpState::TimeWait,
            "07" => TcpState::Closed,
            "08" => TcpState::CloseWait,
            "09" => TcpState::LastAck,
            "0A" | "0a" => TcpState::Listen,
            "0B" | "0b" => TcpState::Closing,
            other => TcpState::Unknown(format!("0x{}", other)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketInfo {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: Option<TcpState>,
    #[serde(skip)]
    #[allow(dead_code)]
    pub fd: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub run_time_secs: u64,
    pub start_time_secs: u64,
    pub cwd: Option<String>,
    pub exe: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub socket: SocketInfo,
    pub process: ProcessInfo,
}

/// Lightweight entry used by the list view — populated directly from lsof/proc
/// without the full sysinfo enrichment pass.
#[derive(Debug, Clone, Serialize)]
pub struct ListEntry {
    pub port: u16,
    pub protocol: Protocol,
    pub local_addr: String,
    pub state: Option<TcpState>,
    pub process_name: String,
    pub pid: u32,
    pub user: String,
}

impl Protocol {
    /// Stable sort order: TCP < TCP6 < UDP < UDP6 < unknown
    pub fn sort_key(&self) -> u8 {
        match self {
            Protocol::Tcp => 0,
            Protocol::Tcp6 => 1,
            Protocol::Udp => 2,
            Protocol::Udp6 => 3,
            Protocol::Unknown(_) => 4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_state_from_lsof_case_insensitive() {
        assert_eq!(TcpState::from_lsof("listen"), TcpState::Listen);
        assert_eq!(TcpState::from_lsof("LISTEN"), TcpState::Listen);
        assert_eq!(TcpState::from_lsof("ESTABLISHED"), TcpState::Established);
        assert_eq!(TcpState::from_lsof("TIME_WAIT"), TcpState::TimeWait);
    }

    #[test]
    fn tcp_state_from_hex() {
        assert_eq!(TcpState::from_hex("0A"), TcpState::Listen);
        assert_eq!(TcpState::from_hex("0a"), TcpState::Listen);
        assert_eq!(TcpState::from_hex("01"), TcpState::Established);
        assert_eq!(TcpState::from_hex("06"), TcpState::TimeWait);
    }

    #[test]
    fn tcp_state_display() {
        assert_eq!(TcpState::Listen.to_string(), "LISTEN");
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::Unknown("FOO".into()).to_string(), "FOO");
    }

    #[test]
    fn protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp6.to_string(), "UDP6");
        assert_eq!(Protocol::Unknown("RAW".into()).to_string(), "RAW");
    }
}
