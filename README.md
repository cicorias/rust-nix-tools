# rust-nix-tools

A collection of Unix/macOS command-line tools built in Rust. Each tool is a standalone binary focused on doing one thing well.

## Tools

### `portspy` — port inspector

Deep inspection of what process is using a network port.

```
# List all listening ports, sorted numerically
portspy

# Deep-inspect a specific port
portspy 8080

# Show extra detail (exe path, CWD)
portspy 8080 --verbose
```

**List mode** (`portspy` with no args) shows a sorted table of all listening/bound ports:

```
  portspy — listening ports
  ─────────────────────────────────────────────────────────────
  ADDR              PROTO  STATE    PROCESS      USER      PID
  ─────────────────────────────────────────────────────────────
  *:5000            TCP    LISTEN   ControlCe    cicorias   670
  *:5000            TCP6   LISTEN   ControlCe    cicorias   670
  127.0.0.1:8080    TCP    LISTEN   node         cicorias  1234
  *:53271           TCP    LISTEN   rapportd     cicorias   673
  ─────────────────────────────────────────────────────────────
  4 ports  ·  3 processes
```

**Inspect mode** (`portspy <port>`) shows full process details:

```
  portspy — port 8080
  ────────────────────────────────────────────────────────
  2 socket(s) found

  TCP *:8080  [LISTEN]
    Process:      node (PID 1234)
    User:         cicorias
    Command:      node server.js --port 8080
    Parent:       bash (PID 5678)
    Memory:       45.2 MB  (virt 512.0 MB)
    Started:      2026-06-14 10:00:00 2h 30m ago
```

#### Platform support

| Platform | Backend |
|----------|---------|
| macOS    | `lsof` |
| Linux    | `/proc/net/tcp`, `/proc/*/fd/` |

## Installation

Requires [Rust](https://rustup.rs/) 1.70+. Toolchain version is managed via [mise](https://mise.jdx.dev/).

```bash
# Install mise (if not already)
brew install mise  # macOS

# Build all tools
mise run build-release

# Or build a specific tool
cargo build -p portspy --release
```

The release binary lands at `target/release/portspy`. Copy it to somewhere on your `$PATH`:

```bash
cp target/release/portspy ~/.local/bin/
```

## Development

```bash
mise run test    # run all tests
mise run lint    # clippy
mise run fmt     # rustfmt
```

Each tool lives under `crates/<name>/` as an independent binary crate. Shared utilities will live in `crates/nix-tools-core/` as the collection grows.

## License

MIT — see [LICENSE](LICENSE).
