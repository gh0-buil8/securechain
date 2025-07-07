//! SecureChain - Universal Web3 Smart Contract Security Auditor
//! 
//! A comprehensive security auditing tool with AI-powered vulnerability detection,
//! fuzzing, static analysis, and automatic PoC generation.

use anyhow::Result;
use clap::Parser;
use colored::Colorize;


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
    let config = Config::load().unwrap_or_else(|_| Config::default());

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

/// Check if this is first run and setup if needed
async fn run_auto_setup() -> Result<()> {
    println!("🔧 Setting up SecureChain with all required tools...");

    // Find the setup script in the SecureChain directory
    let current_dir = std::env::current_dir()?;
    let setup_script = if current_dir.file_name().and_then(|n| n.to_str()) == Some("SecureChain") {
        current_dir.join("setup.sh")
    } else {
        current_dir.join("SecureChain").join("setup.sh")
    };

    if !setup_script.exists() {
        println!("⚠️  Setup script not found. Creating minimal setup...");
        create_minimal_setup().await?;
        return Ok(());
    }

    let output = tokio::process::Command::new("bash")
        .arg(&setup_script)
        .current_dir(setup_script.parent().unwrap())
        .output()
        .await?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        println!("⚠️  Full setup failed: {}", error);
        println!("🔄 Running minimal setup instead...");
        create_minimal_setup().await?;
        return Ok(());
    }

    println!("✅ Setup completed successfully!");

    // Create setup marker
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not find config directory"))?
        .join("securechain");

    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(config_dir.join(".setup_complete"), "")?;

    Ok(())
}

/// Create minimal setup when full setup fails
async fn create_minimal_setup() -> Result<()> {
    println!("📦 Creating minimal SecureChain setup...");

    // Create config directory
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow!("Could not find config directory"))?
        .join("securechain");

    std::fs::create_dir_all(&config_dir)?;

    // Create default config
    let default_config = r#"
[analysis]
default_depth = "standard"
enable_ai = false
output_format = "markdown"

[tools]
slither_enabled = false
mythril_enabled = false
echidna_enabled = false

[ai]
backend = "local"
openai_api_key = ""
anthropic_api_key = ""

[output]
colored = true
verbose = false
"#;

    std::fs::write(config_dir.join("config.toml"), default_config)?;
    std::fs::write(config_dir.join(".setup_complete"), "minimal")?;

    println!("✅ Minimal setup completed!");
    println!("💡 For full functionality, install tools manually:");
    println!("   - pip install slither-analyzer mythril");
    println!("   - npm install -g solhint");

    Ok(())
}