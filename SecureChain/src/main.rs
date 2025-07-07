
//! SecureChain - Universal Web3 Smart Contract Security Auditor
//! 
//! A comprehensive security auditing tool with AI-powered vulnerability detection,
//! fuzzing, static analysis, and automatic PoC generation.

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

mod cli;
mod core;
mod plugins;
mod report;
mod utils;

use cli::commands::{execute_command, Cli};
use utils::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Display banner
    display_banner();

    // Check if this is first run and setup if needed
    if !is_setup_complete() {
        println!("🔧 First-time setup detected. Running automatic setup...");
        run_auto_setup().await?;
    }

    // Parse CLI arguments
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load_or_default()?;

    // Execute the command
    match execute_command(cli, config).await {
        Ok(_) => {
            println!("\n{} Operation completed successfully!", "✅".green());
        }
        Err(e) => {
            eprintln!("\n{} Error: {}", "❌".red(), e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Display SecureChain banner
fn display_banner() {
    println!("{}", r#"
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗          ║
    ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝          ║
    ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗            ║
    ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝            ║
    ║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗          ║
    ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝          ║
    ║                                                               ║
    ║        ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗                  ║
    ║       ██╔════╝██║  ██║██╔══██╗██║████╗  ██║                  ║
    ║       ██║     ███████║███████║██║██╔██╗ ██║                  ║
    ║       ██║     ██╔══██║██╔══██║██║██║╚██╗██║                  ║
    ║       ╚██████╗██║  ██║██║  ██║██║██║ ╚████║                  ║
    ║        ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝                  ║
    ║                                                               ║
    ║              Universal Web3 Security Auditor                 ║
    ║               AI-Powered • Multi-Platform                    ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    "#.bright_cyan());
    
    println!("{} v{} - {}", 
             "SecureChain".bright_white().bold(),
             env!("CARGO_PKG_VERSION"),
             "Perfect Smart Contract Security Auditing".dimmed());
    println!();
}

/// Check if setup is complete
fn is_setup_complete() -> bool {
    // Check for required tools
    let tools = ["slither", "myth", "echidna-test", "forge"];
    
    for tool in &tools {
        if std::process::Command::new(tool)
            .arg("--version")
            .output()
            .is_err()
        {
            return false;
        }
    }
    
    true
}

/// Run automatic setup
async fn run_auto_setup() -> Result<()> {
    println!("🔧 Setting up SecureChain with all required tools...");
    
    // Run setup script
    let output = std::process::Command::new("bash")
        .arg("setup.sh")
        .current_dir(std::env::current_dir()?)
        .output()?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Setup failed: {}", stderr));
    }
    
    println!("✅ Setup completed successfully!");
    Ok(())
}
