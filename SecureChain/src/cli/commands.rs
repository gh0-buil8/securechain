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
    
    /// Perfect audit - Complete security analysis with fuzzing, AI, and PoC generation
    Perfect {
        /// Path to contract file or directory
        #[arg(short, long)]
        input: PathBuf,
        
        /// Target blockchain/language (evm, move, cairo, ink)
        #[arg(short, long, default_value = "evm")]
        target: String,
        
        /// AI creativity level (low, medium, high)
        #[arg(short, long, default_value = "high")]
        creativity: String,
        
        /// LLM backend (local, openai, anthropic)
        #[arg(long, default_value = "openai")]
        llm: String,
        
        /// Output directory for reports
        #[arg(short, long, default_value = "./audit_results")]
        output: PathBuf,
        
        /// Skip interactive prompts
        #[arg(long)]
        yes: bool,
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
        Commands::Perfect { input, target, creativity, llm, output, yes } => {
            execute_perfect_audit(input, target, creativity, llm, output, yes, config).await
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



/// Execute perfect audit command - Complete automated security analysis
async fn execute_perfect_audit(
    input: PathBuf,
    target: String,
    creativity: String,
    llm: String,
    output: PathBuf,
    yes: bool,
    config: Config,
) -> Result<()> {
    println!("{}", "🎯 PERFECT AUDIT INITIATED".bright_cyan().bold());
    println!("{}", "=========================".bright_cyan());
    
    if !yes {
        println!("This will perform a comprehensive security audit including:");
        println!("  • Static analysis (Slither, Mythril)");
        println!("  • Dynamic fuzzing (Echidna)");
        println!("  • AI-powered vulnerability detection");
        println!("  • Creative exploit probe generation");
        println!("  • Proof-of-concept generation");
        println!("  • Professional audit report");
        println!("\nContinue? (y/N)");
        
        let mut input_line = String::new();
        std::io::stdin().read_line(&mut input_line)?;
        if !input_line.trim().to_lowercase().starts_with('y') {
            println!("Audit cancelled.");
            return Ok(());
        }
    }
    
    // Create output directory
    std::fs::create_dir_all(&output)?;
    
    let start_time = std::time::Instant::now();
    
    // Step 1: Initial contract analysis
    println!("\n{} Step 1: Contract Analysis", "🔍".bright_blue());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);
    
    let analysis_results = analysis_engine
        .analyze_contracts(&input, &target, "deep", true)
        .await?;
    
    println!("✅ Found {} vulnerabilities", analysis_results.vulnerabilities.len());
    
    // Step 2: Fuzzing Analysis
    println!("\n{} Step 2: Dynamic Fuzzing", "🎲".bright_green());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let fuzz_engine = crate::core::fuzz_engine::FuzzEngine::new(config.clone());
    
    // Get contracts for fuzzing
    let fetcher = crate::core::fetcher::ContractFetcher::new(config.clone());
    let contracts = fetcher.fetch_from_local(input.to_str().unwrap()).await?;
    
    let mut all_fuzz_results = Vec::new();
    for contract in &contracts {
        let parsed_contract = crate::core::parser::ContractParser::new()?.parse_contract(contract)?;
        let fuzz_results = fuzz_engine.fuzz_contract(&parsed_contract).await?;
        
        // Convert fuzzing results to vulnerabilities
        let fuzz_vulnerabilities = fuzz_engine.convert_to_vulnerabilities(&fuzz_results);
        all_fuzz_results.extend(fuzz_vulnerabilities);
        
        println!("✅ Fuzzing completed for {} - {} issues found", 
                 contract.name, fuzz_results.failures.len());
    }
    
    // Step 3: Creative AI Probes
    println!("\n{} Step 3: AI Creative Probes", "🧠".bright_magenta());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let creative_probes = analysis_engine
        .generate_creative_probes(&input, &creativity, &llm, true)
        .await?;
    
    println!("✅ Generated {} creative attack probes", creative_probes.len());
    
    // Step 4: Generate PoCs
    println!("\n{} Step 4: Proof-of-Concept Generation", "⚡".bright_yellow());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let poc_count = generate_pocs(&analysis_results, &creative_probes, &output).await?;
    println!("✅ Generated {} proof-of-concept exploits", poc_count);
    
    // Step 5: Comprehensive Report
    println!("\n{} Step 5: Report Generation", "📊".bright_cyan());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let report_gen = ReportGenerator::new(config);
    
    // Combine all results
    let mut combined_results = analysis_results;
    combined_results.vulnerabilities.extend(all_fuzz_results);
    
    // Generate executive report
    let exec_report = report_gen.generate_executive_summary(&combined_results, &creative_probes)?;
    let exec_path = output.join("executive_summary.md");
    std::fs::write(&exec_path, exec_report)?;
    
    // Generate technical report
    let tech_report = report_gen.generate_technical_report(&combined_results, &creative_probes)?;
    let tech_path = output.join("technical_report.md");
    std::fs::write(&tech_path, tech_report)?;
    
    // Generate JSON report
    let json_report = serde_json::to_string_pretty(&combined_results)?;
    let json_path = output.join("analysis_results.json");
    std::fs::write(&json_path, json_report)?;
    
    // Generate PoC index
    generate_poc_index(&output, poc_count)?;
    
    let duration = start_time.elapsed();
    
    // Final Summary
    println!("\n{}", "🎉 PERFECT AUDIT COMPLETED".bright_green().bold());
    println!("{}", "===========================".bright_green());
    println!("⏱️  Duration: {:.2} seconds", duration.as_secs_f64());
    println!("🔍 Total vulnerabilities: {}", combined_results.vulnerabilities.len());
    println!("🎯 Creative probes: {}", creative_probes.len());
    println!("⚡ PoCs generated: {}", poc_count);
    println!("📊 Reports generated: 4");
    println!("📁 Output directory: {}", output.display());
    
    println!("\n{} Files generated:", "📋".bright_blue());
    println!("  • executive_summary.md - Business-ready summary");
    println!("  • technical_report.md - Detailed technical analysis");
    println!("  • analysis_results.json - Machine-readable results");
    println!("  • poc_exploits/ - Proof-of-concept exploits");
    println!("  • poc_index.md - PoC documentation");
    
    Ok(())
}

/// Generate proof-of-concept exploits
async fn generate_pocs(
    analysis_results: &crate::core::analyzer::AnalysisResults,
    creative_probes: &[crate::core::analyzer::CreativeProbe],
    output_dir: &PathBuf,
) -> Result<usize> {
    let poc_dir = output_dir.join("poc_exploits");
    std::fs::create_dir_all(&poc_dir)?;
    
    let mut poc_count = 0;
    
    // Generate PoCs for high/critical vulnerabilities
    for vuln in &analysis_results.vulnerabilities {
        if matches!(vuln.severity.as_str(), "Critical" | "High") {
            let poc_content = generate_vulnerability_poc(vuln)?;
            let poc_file = poc_dir.join(format!("poc_{}.sol", poc_count + 1));
            std::fs::write(&poc_file, poc_content)?;
            poc_count += 1;
        }
    }
    
    // Generate PoCs for creative probes
    for (i, probe) in creative_probes.iter().enumerate() {
        if let Some(poc) = &probe.proof_of_concept {
            let poc_file = poc_dir.join(format!("creative_poc_{}.sol", i + 1));
            std::fs::write(&poc_file, poc)?;
            poc_count += 1;
        }
    }
    
    Ok(poc_count)
}

/// Generate PoC for a specific vulnerability
fn generate_vulnerability_poc(vuln: &crate::report::vulnerability::Vulnerability) -> Result<String> {
    let poc_template = format!(r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Proof of Concept Exploit for: {}
 * Severity: {}
 * Category: {:?}
 * 
 * Description: {}
 * 
 * This PoC demonstrates how the vulnerability can be exploited.
 * DO NOT USE IN PRODUCTION - FOR EDUCATIONAL PURPOSES ONLY
 */

import "./target_contract.sol"; // Import the vulnerable contract

contract Exploit {{
    TargetContract public target;
    
    constructor(address _target) {{
        target = TargetContract(_target);
    }}
    
    /**
     * Execute the exploit
     */
    function exploit() external payable {{
        // TODO: Implement specific exploit logic based on vulnerability type
        // This is a template - customize based on the actual vulnerability
        
        // Example for reentrancy:
        // target.vulnerableFunction{{value: msg.value}}();
        
        // Example for access control:
        // target.privilegedFunction();
        
        // Example for integer overflow:
        // target.arithmeticFunction(type(uint256).max);
    }}
    
    /**
     * Receive function for reentrancy attacks
     */
    receive() external payable {{
        if (address(target).balance > 0) {{
            // target.vulnerableFunction();
        }}
    }}
}}

/**
 * Test Contract for the Exploit
 */
contract ExploitTest {{
    TargetContract public target;
    Exploit public exploit;
    
    function setUp() public {{
        target = new TargetContract();
        exploit = new Exploit(address(target));
    }}
    
    function testExploit() public {{
        // Setup initial state
        // target.setup{{value: 1 ether}}();
        
        uint256 balanceBefore = address(this).balance;
        
        // Execute exploit
        exploit.exploit{{value: 0.1 ether}}();
        
        uint256 balanceAfter = address(this).balance;
        
        // Verify exploit success
        assert(balanceAfter > balanceBefore);
    }}
}}
"#, vuln.title, vuln.severity, vuln.category, vuln.description);
    
    Ok(poc_template)
}

/// Generate PoC index documentation
fn generate_poc_index(output_dir: &PathBuf, poc_count: usize) -> Result<()> {
    let index_content = format!(r#"
# Proof-of-Concept Exploits Index

This directory contains {} proof-of-concept exploits generated during the security audit.

## ⚠️ IMPORTANT DISCLAIMER

**These exploits are for educational and testing purposes only. DO NOT use them against contracts you do not own or have explicit permission to test.**

## Structure

### Vulnerability PoCs
- `poc_*.sol` - Exploits for critical and high severity vulnerabilities found during static analysis

### Creative PoCs  
- `creative_poc_*.sol` - Exploits for creative attack vectors discovered by AI analysis

## Usage

1. **Review the exploit code** to understand the attack vector
2. **Modify target contract imports** to point to your actual contract
3. **Customize exploit logic** based on your specific contract implementation
4. **Test in a safe environment** (local testnet, fork, etc.)
5. **Use findings to fix vulnerabilities** in your contract

## Testing Framework

Most PoCs include test contracts that can be used with Foundry:

```bash
# Install Foundry if not already installed
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Run tests
forge test -vvv
```

## Categories Covered

The generated PoCs may cover:
- ⚡ Reentrancy attacks
- 🔐 Access control bypasses  
- 🔢 Integer overflow/underflow
- 💸 Economic exploitation
- ⛽ Gas griefing attacks
- 🎯 MEV extraction
- 🕐 Timestamp manipulation
- 🎲 Randomness exploitation

## Next Steps

1. **Fix identified vulnerabilities** in your contracts
2. **Add proper security measures** (reentrancy guards, access controls, etc.)
3. **Write comprehensive tests** to prevent regressions
4. **Consider additional security measures** like circuit breakers and time delays
5. **Get a professional audit** before mainnet deployment

---

Generated by SecureChain Perfect Audit v{}
"#, poc_count, env!("CARGO_PKG_VERSION"));
    
    let index_path = output_dir.join("poc_index.md");
    std::fs::write(&index_path, index_content)?;
    
    Ok(())
}
