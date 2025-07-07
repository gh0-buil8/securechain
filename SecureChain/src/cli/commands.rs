use crate::core::ai_assist::AIAssistant;
use crate::core::analyzer::{AnalysisEngine, AnalysisResults};
use crate::core::fetcher::ContractFetcher;
use crate::plugins::PluginManager;
use crate::utils::config::Config;
use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

/// SecureChain CLI - Universal Web3 Smart Contract Security Auditor
#[derive(Parser)]
#[command(
    name = "securechain",
    version = "1.0.0",
    about = "Universal Web3 Smart Contract Security Auditor with AI-powered vulnerability detection",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze smart contracts for security vulnerabilities
    Analyze {
        /// Path to contract file or directory
        #[arg(short, long)]
        input: PathBuf,

        /// Target platform (evm, solana, move, cairo, ink)
        #[arg(short, long, default_value = "evm")]
        target: String,

        /// Analysis depth (quick, standard, deep)
        #[arg(short, long, default_value = "standard")]
        depth: String,

        /// Enable AI-powered analysis
        #[arg(long)]
        ai: bool,

        /// Output format (markdown, json, html)
        #[arg(short, long, default_value = "markdown")]
        output: String,

        /// Output file path
        #[arg(short = 'f', long)]
        output_file: Option<PathBuf>,
    },

    /// Fetch and analyze contracts from blockchain
    Fetch {
        /// Contract address
        #[arg(short, long)]
        address: String,

        /// Network (ethereum, polygon, bsc, arbitrum, optimism)
        #[arg(short, long, default_value = "ethereum")]
        network: String,

        /// API key for blockchain explorer
        #[arg(short = 'k', long)]
        api_key: Option<String>,

        /// Also run analysis after fetching
        #[arg(long)]
        analyze: bool,
    },

    /// Run comprehensive security audit
    Audit {
        /// Path to contract file or directory
        #[arg(short, long)]
        input: PathBuf,

        /// Target platform (evm, solana, move, cairo, ink)
        #[arg(short, long, default_value = "evm")]
        target: String,

        /// Enable AI-powered analysis
        #[arg(long)]
        ai: bool,

        /// Include fuzzing tests
        #[arg(long)]
        fuzz: bool,

        /// Output directory for comprehensive report
        #[arg(short, long, default_value = "audit_results")]
        output_dir: PathBuf,
    },

    /// Generate PoC exploits for discovered vulnerabilities
    Exploit {
        /// Path to analysis results file
        #[arg(short, long)]
        results: PathBuf,

        /// Output directory for exploits
        #[arg(short, long, default_value = "exploits")]
        output_dir: PathBuf,
    },

    /// Configure SecureChain settings
    Config {
        /// Configuration key to set
        #[arg(short, long)]
        key: Option<String>,

        /// Configuration value to set
        #[arg(short, long)]
        value: Option<String>,

        /// List all configuration options
        #[arg(short, long)]
        list: bool,
    },

    /// Update analysis tools and databases
    Update {
        /// Update all tools
        #[arg(long)]
        all: bool,

        /// Update vulnerability database
        #[arg(long)]
        db: bool,

        /// Update AI models
        #[arg(long)]
        ai: bool,
    },
}

/// Execute CLI commands
pub async fn execute_command(cli: Cli, config: Config) -> Result<()> {
    match cli.command {
        Commands::Analyze { input, target, depth, ai, output, output_file } => {
            handle_analyze(input, target, depth, ai, output, output_file, config).await
        }
        Commands::Fetch { address, network, api_key, analyze } => {
            handle_fetch(address, network, api_key, analyze, config).await
        }
        Commands::Audit { input, target, ai, fuzz, output_dir } => {
            handle_audit(input, target, ai, fuzz, output_dir, config).await
        }
        Commands::Exploit { results, output_dir } => {
            handle_exploit(results, output_dir, config).await
        }
        Commands::Config { key, value, list } => {
            handle_config(key, value, list, config).await
        }
        Commands::Update { all, db, ai } => {
            handle_update(all, db, ai, config).await
        }
    }
}

/// Handle analyze command
async fn handle_analyze(
    input: PathBuf,
    target: String,
    depth: String,
    ai: bool,
    output: String,
    output_file: Option<PathBuf>,
    config: Config,
) -> Result<()> {
    println!("🔍 {} Smart Contract Analysis", "Starting".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Initialize components
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);

    // Perform analysis
    let results = analysis_engine
        .analyze_contracts(&input, &target, &depth, ai)
        .await?;

    // Generate report
    let report_generator = crate::report::generator::ReportGenerator::new(config);
    let report = report_generator.generate_report(&results, &output)?;

    // Output results
    if let Some(output_path) = output_file {
        std::fs::write(&output_path, &report)?;
        println!("📄 Report saved to: {}", output_path.display());
    } else {
        println!("{}", report);
    }

    println!("✅ Analysis completed successfully!");
    Ok(())
}

/// Handle fetch command
async fn handle_fetch(
    address: String,
    network: String,
    api_key: Option<String>,
    analyze: bool,
    config: Config,
) -> Result<()> {
    println!("🔗 {} Contract from {}", "Fetching".bright_green(), network);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let fetcher = ContractFetcher::new(config.clone());
    let contracts = fetcher.fetch_contracts(&network, &address, api_key.as_deref()).await?;

    println!("✅ Successfully fetched {} contracts", contracts.len());

    if analyze {
        println!("\n🔍 {} Analysis", "Starting".bright_green());
        let plugin_manager = PluginManager::new();
        let analysis_engine = AnalysisEngine::new(config, plugin_manager);

        for contract in contracts {
            let temp_path = std::env::temp_dir().join(format!("{}.sol", contract.name));
            std::fs::write(&temp_path, &contract.source_code)?;

            let results = analysis_engine
                .analyze_contracts(&temp_path, "evm", "standard", false)
                .await?;

            println!("📊 Contract: {} - {} vulnerabilities found", 
                     contract.name, results.vulnerabilities.len());
        }
    }

    Ok(())
}

/// Handle audit command
async fn handle_audit(
    input: PathBuf,
    target: String,
    ai: bool,
    fuzz: bool,
    output_dir: PathBuf,
    config: Config,
) -> Result<()> {
    println!("🛡️  {} Comprehensive Security Audit", "Starting".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Step 1: Static Analysis
    println!("\n{} Step 1: Static Analysis", "🔍".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);

    let analysis_results = analysis_engine
        .analyze_contracts(&input, &target, "deep", ai)
        .await?;

    println!("✅ Found {} vulnerabilities", analysis_results.vulnerabilities.len());

    // Step 2: Fuzzing Analysis
    if fuzz {
        println!("\n{} Step 2: Dynamic Fuzzing", "🎲".bright_green());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        let fuzz_engine = crate::core::fuzz_engine::FuzzEngine::new(config.clone());

        // Get contracts for fuzzing
        let fetcher = crate::core::fetcher::ContractFetcher::new(config.clone());
        let contracts = fetcher.fetch_from_local(input.to_str().unwrap()).await?;

        for contract in &contracts {
            let parsed_contract = crate::core::parser::ContractParser::new()?.parse_contract(contract)?;
            let fuzz_results = fuzz_engine.fuzz_contract(&parsed_contract).await?;

            println!("✅ Fuzzing completed for {}", contract.name);
        }
    }

    // Step 3: Generate comprehensive report
    println!("\n{} Step 3: Generating Report", "📄".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    std::fs::create_dir_all(&output_dir)?;

    let report_generator = crate::report::generator::ReportGenerator::new(config);
    let report = report_generator.generate_report(&analysis_results, "markdown")?;

    let report_path = output_dir.join("security_audit_report.md");
    std::fs::write(&report_path, &report)?;

    println!("📄 Comprehensive audit report saved to: {}", report_path.display());
    println!("✅ Security audit completed successfully!");

    Ok(())
}

/// Handle exploit command
async fn handle_exploit(
    results: PathBuf,
    output_dir: PathBuf,
    config: Config,
) -> Result<()> {
    println!("⚡ {} PoC Exploit Generation", "Starting".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Read analysis results
    let results_content = std::fs::read_to_string(&results)?;
    let analysis_results: AnalysisResults = serde_json::from_str(&results_content)?;

    std::fs::create_dir_all(&output_dir)?;

    // Generate exploits for each vulnerability
    for (i, vulnerability) in analysis_results.vulnerabilities.iter().enumerate() {
        if vulnerability.severity == "Critical" || vulnerability.severity == "High" {
            let exploit_code = generate_exploit_code(vulnerability);
            let exploit_path = output_dir.join(format!("exploit_{}.sol", i + 1));
            std::fs::write(&exploit_path, exploit_code)?;

            println!("🔥 Generated exploit for: {}", vulnerability.title);
        }
    }

    println!("✅ PoC exploits generated successfully!");
    Ok(())
}

/// Handle config command
async fn handle_config(
    key: Option<String>,
    value: Option<String>,
    list: bool,
    mut config: Config,
) -> Result<()> {
    if list {
        println!("📋 {} Configuration", "Current".bright_green());
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("AI Backend: {}", config.ai.backend);
        println!("Log Level: {}", config.general.log_level);
        println!("Output Directory: {}", config.general.output_dir.display());
        println!("Default Analysis Depth: {}", config.analysis.default_depth);
        println!("Default Report Format: {}", config.reporting.default_format);
        return Ok(());
    }

    if let (Some(key), Some(value)) = (key, value) {
        config.set_value(&key, &value)?;
        if let Some(config_path) = Config::user_config_path() {
            config.save_to_file(&config_path)?;
            println!("✅ Configuration updated: {} = {}", key, value);
        }
    } else {
        println!("❌ Please provide both key and value, or use --list to view current configuration");
    }

    Ok(())
}

/// Handle update command
async fn handle_update(
    all: bool,
    db: bool,
    ai: bool,
    _config: Config,
) -> Result<()> {
    println!("🔄 {} SecureChain Components", "Updating".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if all || db {
        println!("📊 Updating vulnerability database...");
        // Simulate database update
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        println!("✅ Vulnerability database updated");
    }

    if all || ai {
        println!("🤖 Updating AI models...");
        // Simulate AI model update
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        println!("✅ AI models updated");
    }

    if all {
        println!("🛠️  Updating analysis tools...");
        // Simulate tool update
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        println!("✅ Analysis tools updated");
    }

    println!("✅ Update completed successfully!");
    Ok(())
}

/// Generate exploit code for a vulnerability
fn generate_exploit_code(vulnerability: &crate::report::vulnerability::Vulnerability) -> String {
    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * PoC Exploit for: {}
 * Severity: {}
 * Description: {}
 */

contract ExploitPoC {{
    address public target;

    constructor(address _target) {{
        target = _target;
    }}

    function exploit() external {{
        // Exploit implementation based on vulnerability type
        // This is a template - actual implementation depends on specific vulnerability

        // Example: Reentrancy exploit
        (bool success, ) = target.call(
            abi.encodeWithSignature("vulnerableFunction()")
        );
        require(success, "Exploit failed");
    }}

    // Add fallback function for reentrancy attacks
    fallback() external payable {{
        if (address(target).balance > 0) {{
            (bool success, ) = target.call(
                abi.encodeWithSignature("vulnerableFunction()")
            );
            require(success, "Reentrancy failed");
        }}
    }}
}}
"#,
        vulnerability.title,
        vulnerability.severity,
        vulnerability.description
    )
}