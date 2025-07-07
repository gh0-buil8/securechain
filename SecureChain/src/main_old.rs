//! BugForgeX - Universal Web3 Smart Contract Security Auditor
//! 
//! A comprehensive Rust-based CLI tool for Web3 smart contract security auditing
//! with AI-powered vulnerability detection across multiple blockchain platforms.

use std::env;

/// Initialize the application environment
fn init_app() -> Result<()> {
    // Initialize logging
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "bugforgex=info");
    }
    env_logger::init();

    // Display banner
    print_banner();

    Ok(())
}

/// Print the application banner
fn print_banner() {
    println!("{}", "
╔══════════════════════════════════════════════════════════════╗
║                         BugForgeX                            ║
║           Universal Web3 Smart Contract Auditor             ║
║                                                              ║
║  🔍 Multi-chain Security Analysis                           ║
║  🧠 AI-Powered Vulnerability Detection                      ║
║  ⚡ Creative Exploit Discovery                              ║
╚══════════════════════════════════════════════════════════════╝
    ".bright_cyan());
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize application
    if let Err(e) = init_app() {
        eprintln!("{} Failed to initialize application: {}", "ERROR".red(), e);
        std::process::exit(1);
    }

    // Parse command line arguments
    let cli = Cli::parse();

    // Load configuration
    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            Config::default()
        }
    };

    debug!("Configuration loaded successfully");
    info!("Starting BugForgeX v{}", env!("CARGO_PKG_VERSION"));

    // Execute the command
    match cli::commands::execute_command(cli, config).await {
        Ok(_) => {
            info!("Command executed successfully");
            println!("{}", "\n✅ Analysis completed successfully!".green());
        }
        Err(e) => {
            error!("Command execution failed: {}", e);
            eprintln!("{} {}", "ERROR".red(), e);
            std::process::exit(1);
        }
    }

    Ok(())
}
