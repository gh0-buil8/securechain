//! Command-line interface commands and handlers

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

use crate::core::{analyzer::AnalysisEngine, fetcher::ContractFetcher};
use crate::plugins::PluginManager;
use crate::report::generator::ReportGenerator;
use crate::utils::config::Config;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Fetch contracts from various sources
    Fetch {
        /// Source type (etherscan, github, local)
        #[arg(short, long, default_value = "etherscan")]
        source: String,
        
        /// Contract address or search query
        #[arg(short, long)]
        query: String,
        
        /// Output directory
        #[arg(short, long, default_value = "./contracts")]
        output: PathBuf,
        
        /// Network/chain to fetch from
        #[arg(short, long, default_value = "ethereum")]
        network: String,
    },
    
    /// Analyze smart contracts for vulnerabilities
    Analyze {
        /// Path to contract file or directory
        #[arg(short, long)]
        input: PathBuf,
        
        /// Target blockchain/language (evm, move, cairo, ink)
        #[arg(short, long, default_value = "evm")]
        target: String,
        
        /// Analysis depth (basic, standard, deep)
        #[arg(short, long, default_value = "standard")]
        depth: String,
        
        /// Enable AI-powered analysis
        #[arg(long)]
        ai: bool,
        
        /// Output format (json, markdown, console)
        #[arg(short, long, default_value = "console")]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Generate creative exploit probes
    Probe {
        /// Path to contract file
        #[arg(short, long)]
        input: PathBuf,
        
        /// Creativity level (low, medium, high)
        #[arg(short, long, default_value = "medium")]
        creativity: String,
        
        /// LLM backend (local, openai, anthropic)
        #[arg(long, default_value = "local")]
        llm: String,
        
        /// Generate proof-of-concept exploit
        #[arg(long)]
        poc: bool,
    },
    
    /// Generate comprehensive audit report
    Report {
        /// Path to analysis results
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output format (markdown, pdf, html)
        #[arg(short, long, default_value = "markdown")]
        format: String,
        
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
        
        /// Include executive summary
        #[arg(long)]
        summary: bool,
    },
    
    /// Configure BugForgeX settings
    Config {
        /// Show current configuration
        #[arg(long)]
        show: bool,
        
        /// Set configuration value
        #[arg(long)]
        set: Option<String>,
        
        /// Configuration key-value pair
        #[arg(long)]
        value: Option<String>,
    },
    
    /// Install or update analysis tools
    Install {
        /// Tool to install (slither, echidna, mythril, all)
        #[arg(short, long, default_value = "all")]
        tool: String,
        
        /// Force reinstallation
        #[arg(long)]
        force: bool,
    },
}

/// Execute the parsed command
pub async fn execute_command(cli: Cli, config: Config) -> Result<()> {
    match cli.command {
        Commands::Fetch { source, query, output, network } => {
            execute_fetch_command(source, query, output, network, config).await
        }
        Commands::Analyze { input, target, depth, ai, format, output } => {
            execute_analyze_command(input, target, depth, ai, format, output, config).await
        }
        Commands::Probe { input, creativity, llm, poc } => {
            execute_probe_command(input, creativity, llm, poc, config).await
        }
        Commands::Report { input, format, output, summary } => {
            execute_report_command(input, format, output, summary, config).await
        }
        Commands::Config { show, set, value } => {
            execute_config_command(show, set, value, config).await
        }
        Commands::Install { tool, force } => {
            execute_install_command(tool, force, config).await
        }
    }
}

/// Execute fetch command
async fn execute_fetch_command(
    source: String,
    query: String,
    output: PathBuf,
    network: String,
    config: Config,
) -> Result<()> {
    println!("{} contracts from {} on {}", "Fetching".cyan(), source, network);
    
    let fetcher = ContractFetcher::new(config.clone());
    let contracts = fetcher.fetch_contracts(&source, &query, &network).await?;
    
    println!("{} {} contracts found", "✓".green(), contracts.len());
    
    // Save contracts to output directory
    std::fs::create_dir_all(&output)?;
    
    for contract in contracts {
        let file_path = output.join(format!("{}.sol", contract.name));
        std::fs::write(&file_path, &contract.source_code)?;
        println!("  {} {}", "Saved".green(), file_path.display());
    }
    
    Ok(())
}

/// Execute analyze command
async fn execute_analyze_command(
    input: PathBuf,
    target: String,
    depth: String,
    ai: bool,
    format: String,
    output: Option<PathBuf>,
    config: Config,
) -> Result<()> {
    println!("{} {} contracts for {} platform", "Analyzing".cyan(), input.display(), target);
    
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);
    
    let results = analysis_engine.analyze_contracts(&input, &target, &depth, ai).await?;
    
    println!("{} {} vulnerabilities found", "✓".green(), results.vulnerabilities.len());
    
    // Display results based on format
    match format.as_str() {
        "console" => {
            display_console_results(&results)?;
        }
        "json" => {
            let json_output = serde_json::to_string_pretty(&results)?;
            if let Some(output_path) = output {
                std::fs::write(&output_path, json_output)?;
                println!("Results saved to {}", output_path.display());
            } else {
                println!("{}", json_output);
            }
        }
        "markdown" => {
            let report_gen = ReportGenerator::new(config);
            let markdown_output = report_gen.generate_markdown_report(&results)?;
            if let Some(output_path) = output {
                std::fs::write(&output_path, markdown_output)?;
                println!("Report saved to {}", output_path.display());
            } else {
                println!("{}", markdown_output);
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported output format: {}", format));
        }
    }
    
    Ok(())
}

/// Execute probe command
async fn execute_probe_command(
    input: PathBuf,
    creativity: String,
    llm: String,
    poc: bool,
    config: Config,
) -> Result<()> {
    println!("{} creative vulnerabilities in {}", "Probing".cyan(), input.display());
    
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);
    
    let probes = analysis_engine.generate_creative_probes(&input, &creativity, &llm, poc).await?;
    
    println!("{} {} creative probes generated", "✓".green(), probes.len());
    
    for (i, probe) in probes.iter().enumerate() {
        println!("\n{} {}", format!("Probe #{}", i + 1).bright_yellow(), probe.title);
        println!("  {}: {}", "Severity".red(), probe.severity);
        println!("  {}: {}", "Description".blue(), probe.description);
        
        if let Some(poc_code) = &probe.proof_of_concept {
            println!("  {}: ", "Proof of Concept".green());
            println!("    {}", poc_code);
        }
    }
    
    Ok(())
}

/// Execute report command
async fn execute_report_command(
    input: PathBuf,
    format: String,
    output: PathBuf,
    summary: bool,
    config: Config,
) -> Result<()> {
    println!("{} comprehensive report", "Generating".cyan());
    
    let report_gen = ReportGenerator::new(config);
    let report = report_gen.generate_comprehensive_report(&input, &format, summary).await?;
    
    std::fs::write(&output, report)?;
    println!("{} Report saved to {}", "✓".green(), output.display());
    
    Ok(())
}

/// Execute config command
async fn execute_config_command(
    show: bool,
    set: Option<String>,
    value: Option<String>,
    config: Config,
) -> Result<()> {
    if show {
        println!("{}", "Current Configuration:".bright_cyan());
        println!("{}", toml::to_string_pretty(&config)?);
    }
    
    if let (Some(key), Some(val)) = (set, value) {
        println!("{} configuration: {} = {}", "Setting".cyan(), key, val);
        // Implementation for setting configuration values
        // This would modify the config file
    }
    
    Ok(())
}

/// Execute install command
async fn execute_install_command(
    tool: String,
    force: bool,
    _config: Config,
) -> Result<()> {
    println!("{} analysis tools: {}", "Installing".cyan(), tool);
    
    match tool.as_str() {
        "slither" => install_slither(force).await?,
        "echidna" => install_echidna(force).await?,
        "mythril" => install_mythril(force).await?,
        "all" => {
            install_slither(force).await?;
            install_echidna(force).await?;
            install_mythril(force).await?;
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown tool: {}", tool));
        }
    }
    
    println!("{} Installation completed", "✓".green());
    Ok(())
}

/// Install Slither
async fn install_slither(force: bool) -> Result<()> {
    println!("  {} Slither static analyzer", "Installing".yellow());
    
    // Check if already installed
    if !force {
        if let Ok(output) = std::process::Command::new("slither").arg("--version").output() {
            if output.status.success() {
                println!("    {} Slither already installed", "✓".green());
                return Ok(());
            }
        }
    }
    
    // Install via pip
    let output = std::process::Command::new("pip3")
        .args(&["install", "slither-analyzer"])
        .output()?;
    
    if output.status.success() {
        println!("    {} Slither installed successfully", "✓".green());
    } else {
        return Err(anyhow::anyhow!("Failed to install Slither: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }
    
    Ok(())
}

/// Install Echidna
async fn install_echidna(force: bool) -> Result<()> {
    println!("  {} Echidna fuzzer", "Installing".yellow());
    
    // Check if already installed
    if !force {
        if let Ok(output) = std::process::Command::new("echidna-test").arg("--version").output() {
            if output.status.success() {
                println!("    {} Echidna already installed", "✓".green());
                return Ok(());
            }
        }
    }
    
    // For now, just show installation instructions
    println!("    {} Please install Echidna manually from: https://github.com/crytic/echidna", "ℹ".blue());
    
    Ok(())
}

/// Install Mythril
async fn install_mythril(force: bool) -> Result<()> {
    println!("  {} Mythril symbolic execution", "Installing".yellow());
    
    // Check if already installed
    if !force {
        if let Ok(output) = std::process::Command::new("myth").arg("version").output() {
            if output.status.success() {
                println!("    {} Mythril already installed", "✓".green());
                return Ok(());
            }
        }
    }
    
    // Install via pip
    let output = std::process::Command::new("pip3")
        .args(&["install", "mythril"])
        .output()?;
    
    if output.status.success() {
        println!("    {} Mythril installed successfully", "✓".green());
    } else {
        return Err(anyhow::anyhow!("Failed to install Mythril: {}", 
            String::from_utf8_lossy(&output.stderr)));
    }
    
    Ok(())
}

/// Display analysis results in console format
fn display_console_results(results: &crate::core::analyzer::AnalysisResults) -> Result<()> {
    println!("\n{}", "═══ ANALYSIS RESULTS ═══".bright_cyan());
    
    if results.vulnerabilities.is_empty() {
        println!("{} No vulnerabilities found", "✓".green());
        return Ok(());
    }
    
    // Group vulnerabilities by severity
    let mut critical = Vec::new();
    let mut high = Vec::new();
    let mut medium = Vec::new();
    let mut low = Vec::new();
    let mut info = Vec::new();
    
    for vuln in &results.vulnerabilities {
        match vuln.severity.as_str() {
            "Critical" => critical.push(vuln),
            "High" => high.push(vuln),
            "Medium" => medium.push(vuln),
            "Low" => low.push(vuln),
            _ => info.push(vuln),
        }
    }
    
    // Display vulnerabilities by severity
    display_vulnerability_group("Critical", &critical, "🔴")?;
    display_vulnerability_group("High", &high, "🟠")?;
    display_vulnerability_group("Medium", &medium, "🟡")?;
    display_vulnerability_group("Low", &low, "🟢")?;
    display_vulnerability_group("Info", &info, "🔵")?;
    
    println!("\n{} Total: {} vulnerabilities", "📊".bright_blue(), results.vulnerabilities.len());
    
    Ok(())
}

/// Display a group of vulnerabilities
fn display_vulnerability_group(
    severity: &str,
    vulnerabilities: &[&crate::report::vulnerability::Vulnerability],
    icon: &str,
) -> Result<()> {
    if vulnerabilities.is_empty() {
        return Ok(());
    }
    
    println!("\n{} {} {} ({})", icon, severity.bright_white(), "Vulnerabilities".bright_white(), vulnerabilities.len());
    
    for (i, vuln) in vulnerabilities.iter().enumerate() {
        println!("  {}. {}", i + 1, vuln.title.bright_yellow());
        println!("     {}: {}", "File".blue(), vuln.file_path);
        println!("     {}: {}", "Line".blue(), vuln.line_number.unwrap_or(0));
        println!("     {}: {}", "Description".blue(), vuln.description);
        
        if let Some(recommendation) = &vuln.recommendation {
            println!("     {}: {}", "Fix".green(), recommendation);
        }
        
        println!();
    }
    
    Ok(())
}
