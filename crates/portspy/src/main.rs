mod display;
mod inspect;
mod types;

use clap::Parser;

/// Inspect what process is using a port, or list all listening ports
#[derive(Parser)]
#[command(name = "portspy", version, about)]
struct Cli {
    /// Port number to inspect (omit to list all listening ports)
    port: Option<u16>,

    /// Show extra process details (exe path, CWD) — inspect mode only
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.port {
        Some(port) => {
            let findings = inspect::find_port_users(port)?;
            if findings.is_empty() {
                println!(
                    "\n  No processes found using port {}.\n  (Try running with sudo for system processes.)",
                    port
                );
            } else {
                display::render(&findings, cli.verbose);
            }
        }
        None => {
            let entries = inspect::list_all_ports()?;
            display::render_list(&entries);
        }
    }

    Ok(())
}
