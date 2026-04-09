mod demo;
mod doctor;

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
