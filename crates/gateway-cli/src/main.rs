mod canary;
mod demo;
mod doctor;
mod verify;

use clap::{Parser, Subcommand};

/// Gateway CLI -- health checks and interactive demo for the privacy gateway.
#[derive(Parser)]
#[command(name = "gateway", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check system health: Ollama, model, database, upstream, disk space.
    Doctor {
        /// Output results as JSON instead of colored terminal output.
        #[arg(long)]
        json: bool,
    },
    /// Interactive split-terminal anonymization demo (no Ollama required).
    Demo,
    /// Verify a receipt JSON file (offline). Confirms the entry hash
    /// recomputes correctly, the chain link references the prior hash,
    /// and (optionally) the HMAC key id matches the operator's expectation.
    /// Does NOT contact Rekor — point `rekor-cli` at the rekor_uuid in
    /// the receipt for that.
    Verify(verify::VerifyArgs),
    /// Manage canary fingerprint baselines. `bootstrap` captures a
    /// fresh baseline from the upstream; `show` pretty-prints an
    /// existing one.
    Canary(canary::CanaryArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { json } => {
            let report = doctor::run_checks().await;
            if json {
                doctor::print_report_json(&report);
            } else {
                doctor::print_report(&report);
            }

            // Exit with non-zero status if any check failed
            if report.passed < report.total {
                std::process::exit(1);
            }
        }
        Commands::Demo => {
            if let Err(e) = demo::run().await {
                eprintln!("Demo error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Verify(args) => {
            if let Err(e) = verify::run(args) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Commands::Canary(args) => {
            if let Err(e) = canary::run(args) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parses_doctor() {
        let cli = Cli::try_parse_from(["gateway", "doctor"]).unwrap();
        match cli.command {
            Commands::Doctor { json } => assert!(!json),
            _ => panic!("expected Doctor command"),
        }
    }

    #[test]
    fn cli_parses_doctor_json() {
        let cli = Cli::try_parse_from(["gateway", "doctor", "--json"]).unwrap();
        match cli.command {
            Commands::Doctor { json } => assert!(json),
            _ => panic!("expected Doctor command"),
        }
    }

    #[test]
    fn cli_parses_demo() {
        let cli = Cli::try_parse_from(["gateway", "demo"]).unwrap();
        assert!(matches!(cli.command, Commands::Demo));
    }

    #[test]
    fn cli_rejects_unknown_subcommand() {
        let result = Cli::try_parse_from(["gateway", "unknown"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_requires_subcommand() {
        let result = Cli::try_parse_from(["gateway"]);
        assert!(result.is_err());
    }
}
