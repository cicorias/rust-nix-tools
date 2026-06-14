/// Integration tests for portspy.
///
/// These tests exercise the binary against live system state so they need
/// a real OS environment and may need elevated privileges for certain ports.
use std::net::TcpListener;
use std::process::Command;
use serde_json;

fn portspy_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_portspy"))
}

/// Bind a random port so we can ask portspy about it
fn bind_ephemeral() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

#[test]
fn exits_cleanly_for_free_port() {
    // Port 1 is almost certainly unused and unlistenable without root
    let output = portspy_bin()
        .arg("1")
        .output()
        .expect("failed to run portspy");

    // Should exit 0 (we handle "nothing found" gracefully)
    assert!(output.status.success(), "portspy exited non-zero: {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No processes found"),
        "unexpected output: {stdout}"
    );
}

#[test]
fn finds_self_listener() {
    let (_listener, port) = bind_ephemeral();

    let output = portspy_bin()
        .arg(port.to_string())
        .output()
        .expect("failed to run portspy");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should report the port and at least one socket
    assert!(
        stdout.contains(&port.to_string()),
        "port not in output:\n{stdout}"
    );
    assert!(
        stdout.contains("LISTEN"),
        "expected LISTEN state in output:\n{stdout}"
    );
}

#[test]
fn verbose_flag_shows_extra_fields() {
    let (_listener, port) = bind_ephemeral();

    let output = portspy_bin()
        .args([&port.to_string(), "--verbose"])
        .output()
        .expect("failed to run portspy");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verbose should show at least one of exe/CWD
    assert!(
        stdout.contains("Exe:") || stdout.contains("CWD:"),
        "verbose output missing exe/cwd:\n{stdout}"
    );
}

#[test]
fn version_flag_works() {
    let output = portspy_bin()
        .arg("--version")
        .output()
        .expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("portspy"), "version output: {stdout}");
}

#[test]
fn list_mode_runs_without_args() {
    let output = portspy_bin().output().expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show the list header
    assert!(
        stdout.contains("listening ports") || stdout.contains("No listening ports"),
        "unexpected list output:\n{stdout}"
    );
}

#[test]
fn list_mode_shows_headers() {
    let output = portspy_bin().output().expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // If there are any ports (very likely), check column headers appear
    if !stdout.contains("No listening ports") {
        assert!(stdout.contains("PORT"), "missing PORT header:\n{stdout}");
        assert!(stdout.contains("BIND"), "missing BIND header:\n{stdout}");
        assert!(stdout.contains("PROTO"), "missing PROTO header:\n{stdout}");
        assert!(stdout.contains("PROCESS"), "missing PROCESS header:\n{stdout}");
    }
}

#[test]
fn list_mode_includes_self_bound_port() {
    let (_listener, port) = bind_ephemeral();

    let output = portspy_bin().output().expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains(&port.to_string()),
        "ephemeral port {port} not found in list:\n{stdout}"
    );
}

#[test]
fn json_flag_list_mode_is_valid_json() {
    let output = portspy_bin().arg("--json").output().expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json output is not valid JSON");
    assert!(parsed.is_array(), "expected JSON array, got: {parsed}");
}

#[test]
fn json_flag_list_mode_has_expected_fields() {
    let output = portspy_bin().arg("--json").output().expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let arr: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    if let Some(first) = arr.as_array().and_then(|a| a.first()) {
        assert!(first.get("port").is_some(), "missing 'port' field");
        assert!(first.get("protocol").is_some(), "missing 'protocol' field");
        assert!(first.get("pid").is_some(), "missing 'pid' field");
        assert!(first.get("process_name").is_some(), "missing 'process_name' field");
    }
}

#[test]
fn json_flag_inspect_mode_is_valid_json() {
    let (_listener, port) = bind_ephemeral();
    let output = portspy_bin()
        .args([&port.to_string(), "--json"])
        .output()
        .expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("--json output is not valid JSON");
    assert!(parsed.is_array());
    let first = &parsed.as_array().unwrap()[0];
    assert!(first.get("socket").is_some(), "missing 'socket' field");
    assert!(first.get("process").is_some(), "missing 'process' field");
    assert_eq!(
        first["socket"]["local_port"].as_u64().unwrap(),
        u64::from(port)
    );
}

#[test]
fn json_inspect_has_process_fields() {
    let (_listener, port) = bind_ephemeral();
    let output = portspy_bin()
        .args([&port.to_string(), "--json"])
        .output()
        .expect("failed to run portspy");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let arr: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let proc = &arr[0]["process"];
    assert!(proc.get("pid").is_some());
    assert!(proc.get("name").is_some());
    assert!(proc.get("cmdline").is_some());
    assert!(proc.get("user").is_some());
    assert!(proc.get("memory_bytes").is_some());
}

#[test]
fn kill_flag_requires_port() {
    let output = portspy_bin().arg("--kill").output().expect("failed to run portspy");
    assert!(!output.status.success(), "should exit non-zero without a port");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--kill requires"), "unexpected stderr: {stderr}");
}

#[test]
fn list_is_sorted_numerically() {
    let output = portspy_bin().output().expect("failed to run portspy");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Extract port numbers from lines that start with whitespace + digits + colon
    // (the ADDR column is "addr:port")
    let ports: Vec<u16> = stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Skip header/separator/summary lines
            if trimmed.starts_with("PORT")
                || trimmed.starts_with("ADDR")
                || trimmed.starts_with('─')
                || trimmed.is_empty()
                || trimmed.starts_with("portspy")
                || !trimmed.contains(':')
            {
                return None;
            }
            // Addr column is "something:portnum  PROTO ..."
            let addr_col = trimmed.split_whitespace().next()?;
            let port_str = addr_col.rsplit(':').next()?;
            port_str.parse().ok()
        })
        .collect();

    let mut sorted = ports.clone();
    sorted.sort_unstable();
    assert_eq!(ports, sorted, "port list is not sorted numerically");
}
