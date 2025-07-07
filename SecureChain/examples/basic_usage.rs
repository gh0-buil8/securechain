//! Basic usage examples for BugForgeX
//! 
//! This example demonstrates how to use BugForgeX programmatically
//! for integrating smart contract security analysis into your own tools.

use anyhow::Result;
use bugforgex::{
    core::{analyzer::AnalysisEngine, fetcher::ContractFetcher},
    plugins::PluginManager,
    report::generator::ReportGenerator,
    utils::config::{Config, ConfigBuilder},
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    println!("🔍 BugForgeX Basic Usage Examples");
    println!("=================================\n");

    // Example 1: Basic contract analysis
    basic_contract_analysis().await?;

    // Example 2: Fetch and analyze from blockchain
    fetch_and_analyze().await?;

    // Example 3: AI-powered creative analysis
    ai_powered_analysis().await?;

    // Example 4: Custom configuration
    custom_configuration().await?;

    // Example 5: Batch analysis
    batch_analysis().await?;

    // Example 6: Generate comprehensive report
    generate_comprehensive_report().await?;

    println!("✅ All examples completed successfully!");
    Ok(())
}

/// Example 1: Basic contract analysis
async fn basic_contract_analysis() -> Result<()> {
    println!("📋 Example 1: Basic Contract Analysis");
    println!("------------------------------------");

    // Create default configuration
    let config = Config::default();

    // Initialize plugin manager and analysis engine
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config, plugin_manager);

    // Sample Solidity contract with vulnerabilities
    let contract_code = r#"
        pragma solidity ^0.8.0;

        contract VulnerableContract {
            mapping(address => uint256) public balances;
            
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                
                // Vulnerability: External call before state update (reentrancy)
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                
                balances[msg.sender] -= amount;
            }
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
        }
    "#;

    // Create temporary file for analysis
    let temp_dir = tempfile::tempdir()?;
    let contract_path = temp_dir.path().join("VulnerableContract.sol");
    std::fs::write(&contract_path, contract_code)?;

    // Analyze the contract
    let results = analysis_engine
        .analyze_contracts(&contract_path, "evm", "standard", false)
        .await?;

    println!("Analysis Results:");
    println!("- Total vulnerabilities found: {}", results.vulnerabilities.len());
    println!("- Security score: {:.2}/100", results.metrics.security_score);
    println!("- Analysis duration: {:.2} seconds", results.analysis_summary.analysis_duration);

    // Display vulnerabilities
    for (i, vuln) in results.vulnerabilities.iter().enumerate() {
        println!("\n{}. {} ({})", i + 1, vuln.title, vuln.severity);
        println!("   Description: {}", vuln.description);
        if let Some(recommendation) = &vuln.recommendation {
            println!("   Fix: {}", recommendation);
        }
    }

    println!("\n✅ Basic analysis completed\n");
    Ok(())
}

/// Example 2: Fetch and analyze from blockchain
async fn fetch_and_analyze() -> Result<()> {
    println!("📋 Example 2: Fetch and Analyze from Blockchain");
    println!("----------------------------------------------");

    let config = Config::default();
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);
    let fetcher = ContractFetcher::new(config);

    // Note: This would require a valid Etherscan API key
    // For this example, we'll simulate the process
    println!("🔗 Fetching contract from Etherscan...");
    
    // In a real scenario, you would fetch like this:
    // let contracts = fetcher.fetch_contracts(
    //     "etherscan",
    //     "0x1234567890123456789012345678901234567890",
    //     "ethereum"
    // ).await?;

    // For demo purposes, we'll use a local contract
    let contract_code = r#"
        pragma solidity ^0.8.0;

        contract SimpleToken {
            mapping(address => uint256) public balances;
            uint256 public totalSupply;
            address public owner;
            
            constructor(uint256 _totalSupply) {
                totalSupply = _totalSupply;
                balances[msg.sender] = _totalSupply;
                owner = msg.sender;
            }
            
            function transfer(address to, uint256 amount) public returns (bool) {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                
                // Potential integer overflow (in older Solidity versions)
                balances[msg.sender] -= amount;
                balances[to] += amount;
                
                return true;
            }
            
            // Vulnerability: Missing access control
            function mint(address to, uint256 amount) public {
                balances[to] += amount;
                totalSupply += amount;
            }
        }
    "#;

    let temp_dir = tempfile::tempdir()?;
    let contract_path = temp_dir.path().join("SimpleToken.sol");
    std::fs::write(&contract_path, contract_code)?;

    println!("🔍 Analyzing fetched contract...");
    let results = analysis_engine
        .analyze_contracts(&contract_path, "evm", "standard", false)
        .await?;

    println!("✅ Fetch and analysis completed");
    println!("- Vulnerabilities found: {}", results.vulnerabilities.len());
    
    for vuln in &results.vulnerabilities {
        println!("  • {} ({})", vuln.title, vuln.severity);
    }

    println!();
    Ok(())
}

/// Example 3: AI-powered creative analysis
async fn ai_powered_analysis() -> Result<()> {
    println!("📋 Example 3: AI-Powered Creative Analysis");
    println!("-----------------------------------------");

    // Create configuration with AI enabled
    let config = ConfigBuilder::new()
        .ai_backend("local") // Use local LLM
        .build()?;

    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config, plugin_manager);

    // Complex DeFi contract for AI analysis
    let defi_contract = r#"
        pragma solidity ^0.8.0;

        interface IERC20 {
            function transfer(address to, uint256 amount) external returns (bool);
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }

        contract LiquidityPool {
            IERC20 public tokenA;
            IERC20 public tokenB;
            
            mapping(address => uint256) public liquidityProviders;
            uint256 public totalLiquidity;
            
            uint256 public reserveA;
            uint256 public reserveB;
            
            constructor(address _tokenA, address _tokenB) {
                tokenA = IERC20(_tokenA);
                tokenB = IERC20(_tokenB);
            }
            
            function addLiquidity(uint256 amountA, uint256 amountB) external {
                require(amountA > 0 && amountB > 0, "Invalid amounts");
                
                tokenA.transferFrom(msg.sender, address(this), amountA);
                tokenB.transferFrom(msg.sender, address(this), amountB);
                
                uint256 liquidity;
                if (totalLiquidity == 0) {
                    liquidity = sqrt(amountA * amountB);
                } else {
                    liquidity = min(
                        (amountA * totalLiquidity) / reserveA,
                        (amountB * totalLiquidity) / reserveB
                    );
                }
                
                liquidityProviders[msg.sender] += liquidity;
                totalLiquidity += liquidity;
                
                reserveA += amountA;
                reserveB += amountB;
            }
            
            function swap(uint256 amountAIn, uint256 minAmountBOut) external {
                require(amountAIn > 0, "Invalid input amount");
                
                uint256 amountBOut = getAmountOut(amountAIn, reserveA, reserveB);
                require(amountBOut >= minAmountBOut, "Insufficient output amount");
                
                tokenA.transferFrom(msg.sender, address(this), amountAIn);
                tokenB.transfer(msg.sender, amountBOut);
                
                reserveA += amountAIn;
                reserveB -= amountBOut;
            }
            
            function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) 
                public pure returns (uint256) {
                require(amountIn > 0 && reserveIn > 0 && reserveOut > 0, "Invalid reserves");
                
                uint256 amountInWithFee = amountIn * 997;
                uint256 numerator = amountInWithFee * reserveOut;
                uint256 denominator = (reserveIn * 1000) + amountInWithFee;
                
                return numerator / denominator;
            }
            
            function sqrt(uint256 x) internal pure returns (uint256) {
                if (x == 0) return 0;
                uint256 z = (x + 1) / 2;
                uint256 y = x;
                while (z < y) {
                    y = z;
                    z = (x / z + z) / 2;
                }
                return y;
            }
            
            function min(uint256 a, uint256 b) internal pure returns (uint256) {
                return a < b ? a : b;
            }
        }
    "#;

    let temp_dir = tempfile::tempdir()?;
    let contract_path = temp_dir.path().join("LiquidityPool.sol");
    std::fs::write(&contract_path, defi_contract)?;

    println!("🧠 Running AI-powered analysis...");
    println!("Note: This requires a local LLM (like Ollama) or API keys");

    // Run analysis with AI enabled
    let results = analysis_engine
        .analyze_contracts(&contract_path, "evm", "deep", true)
        .await?;

    println!("🎯 Generating creative vulnerability probes...");
    let probes = analysis_engine
        .generate_creative_probes(&contract_path, "high", "local", true)
        .await?;

    println!("✅ AI analysis completed");
    println!("- Standard vulnerabilities: {}", results.vulnerabilities.len());
    println!("- Creative probes: {}", probes.len());

    // Display creative probes
    for (i, probe) in probes.iter().enumerate() {
        println!("\n🔍 Creative Probe #{}: {}", i + 1, probe.title);
        println!("   Severity: {}", probe.severity);
        println!("   Attack Vector: {}", probe.attack_vector);
        if let Some(poc) = &probe.proof_of_concept {
            println!("   PoC Available: Yes ({} chars)", poc.len());
        }
    }

    println!();
    Ok(())
}

/// Example 4: Custom configuration
async fn custom_configuration() -> Result<()> {
    println!("📋 Example 4: Custom Configuration");
    println!("----------------------------------");

    // Build custom configuration
    let config = ConfigBuilder::new()
        .log_level("debug")
        .ai_backend("local")
        .output_dir("./custom_output")
        .colored_output(true)
        .analysis_depth("deep")
        .build()?;

    println!("📝 Custom configuration created:");
    println!("- Log level: {}", config.general.log_level);
    println!("- AI backend: {}", config.ai.backend);
    println!("- Output directory: {}", config.general.output_dir.display());
    println!("- Analysis depth: {}", config.analysis.default_depth);

    // You can also load configuration from file
    // let config = Config::load_from_file("custom_config.toml")?;

    // Or save configuration to file
    let config_path = PathBuf::from("./example_config.toml");
    config.save_to_file(&config_path)?;
    println!("📁 Configuration saved to: {}", config_path.display());

    println!("✅ Custom configuration example completed\n");
    Ok(())
}

/// Example 5: Batch analysis of multiple contracts
async fn batch_analysis() -> Result<()> {
    println!("📋 Example 5: Batch Analysis");
    println!("----------------------------");

    let config = Config::default();
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config, plugin_manager);

    // Create multiple contracts for batch analysis
    let contracts = vec![
        ("SafeContract.sol", r#"
            pragma solidity ^0.8.0;
            contract SafeContract {
                mapping(address => uint256) public balances;
                
                function deposit() public payable {
                    balances[msg.sender] += msg.value;
                }
                
                function withdraw(uint256 amount) public {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }
            }
        "#),
        ("VulnerableContract.sol", r#"
            pragma solidity ^0.8.0;
            contract VulnerableContract {
                mapping(address => uint256) public balances;
                
                function withdraw(uint256 amount) public {
                    require(balances[msg.sender] >= amount);
                    msg.sender.call{value: amount}("");
                    balances[msg.sender] -= amount;
                }
            }
        "#),
        ("TokenContract.sol", r#"
            pragma solidity ^0.8.0;
            contract TokenContract {
                mapping(address => uint256) public balances;
                address public owner;
                
                function mint(address to, uint256 amount) public {
                    // Missing access control
                    balances[to] += amount;
                }
                
                function transfer(address to, uint256 amount) public {
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }
            }
        "#),
    ];

    let temp_dir = tempfile::tempdir()?;
    
    // Write contracts to files
    for (filename, code) in &contracts {
        let contract_path = temp_dir.path().join(filename);
        std::fs::write(&contract_path, code)?;
    }

    println!("🔄 Analyzing {} contracts...", contracts.len());

    // Analyze the directory containing all contracts
    let results = analysis_engine
        .analyze_contracts(temp_dir.path(), "evm", "standard", false)
        .await?;

    println!("✅ Batch analysis completed");
    println!("- Contracts analyzed: {}", contracts.len());
    println!("- Total vulnerabilities: {}", results.vulnerabilities.len());
    println!("- Security score: {:.2}/100", results.metrics.security_score);

    // Group vulnerabilities by severity
    let mut severity_count = std::collections::HashMap::new();
    for vuln in &results.vulnerabilities {
        *severity_count.entry(vuln.severity.clone()).or_insert(0) += 1;
    }

    println!("\n📊 Vulnerability distribution:");
    for (severity, count) in severity_count {
        println!("  • {}: {}", severity, count);
    }

    println!();
    Ok(())
}

/// Example 6: Generate comprehensive report
async fn generate_comprehensive_report() -> Result<()> {
    println!("📋 Example 6: Comprehensive Report Generation");
    println!("---------------------------------------------");

    let config = Config::default();
    let plugin_manager = PluginManager::new();
    let analysis_engine = AnalysisEngine::new(config.clone(), plugin_manager);
    let report_generator = ReportGenerator::new(config);

    // Create a contract with various types of vulnerabilities
    let complex_contract = r#"
        pragma solidity ^0.8.0;

        contract ComplexContract {
            mapping(address => uint256) public balances;
            mapping(address => bool) public authorized;
            address public owner;
            uint256 public totalSupply;
            
            modifier onlyOwner() {
                require(msg.sender == owner, "Not owner");
                _;
            }
            
            modifier onlyAuthorized() {
                require(authorized[msg.sender], "Not authorized");
                _;
            }
            
            constructor() {
                owner = msg.sender;
                authorized[msg.sender] = true;
            }
            
            // Vulnerability: Reentrancy
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] -= amount;
            }
            
            // Vulnerability: Missing access control
            function mint(address to, uint256 amount) public {
                balances[to] += amount;
                totalSupply += amount;
            }
            
            // Vulnerability: tx.origin usage
            function authorize(address user) public {
                require(tx.origin == owner, "Only owner");
                authorized[user] = true;
            }
            
            // Vulnerability: Timestamp dependence
            function timeBasedReward() public view returns (uint256) {
                if (block.timestamp % 2 == 0) {
                    return 100;
                } else {
                    return 50;
                }
            }
            
            // Good: Proper access control
            function setOwner(address newOwner) public onlyOwner {
                owner = newOwner;
            }
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
        }
    "#;

    let temp_dir = tempfile::tempdir()?;
    let contract_path = temp_dir.path().join("ComplexContract.sol");
    std::fs::write(&contract_path, complex_contract)?;

    println!("🔍 Analyzing complex contract...");
    let results = analysis_engine
        .analyze_contracts(&contract_path, "evm", "deep", false)
        .await?;

    println!("📄 Generating reports in multiple formats...");

    // Generate Markdown report
    let markdown_report = report_generator.generate_markdown_report(&results)?;
    let markdown_path = temp_dir.path().join("audit_report.md");
    std::fs::write(&markdown_path, &markdown_report)?;
    println!("✅ Markdown report: {}", markdown_path.display());

    // Save analysis results as JSON for comprehensive report
    let json_results = serde_json::to_string_pretty(&results)?;
    let json_path = temp_dir.path().join("analysis_results.json");
    std::fs::write(&json_path, &json_results)?;

    // Generate comprehensive HTML report
    let html_report = report_generator
        .generate_comprehensive_report(&json_path, "html", true)
        .await?;
    let html_path = temp_dir.path().join("comprehensive_report.html");
    std::fs::write(&html_path, &html_report)?;
    println!("✅ HTML report: {}", html_path.display());

    // Generate JSON report for programmatic consumption
    let json_report = report_generator
        .generate_comprehensive_report(&json_path, "json", true)
        .await?;
    let structured_json_path = temp_dir.path().join("structured_report.json");
    std::fs::write(&structured_json_path, &json_report)?;
    println!("✅ Structured JSON: {}", structured_json_path.display());

    println!("\n📊 Report Summary:");
    println!("- Total vulnerabilities: {}", results.vulnerabilities.len());
    println!("- Analysis duration: {:.2}s", results.analysis_summary.analysis_duration);
    println!("- Security score: {:.2}/100", results.metrics.security_score);
    println!("- Lines analyzed: {}", results.metrics.lines_of_code);

    // Display first few vulnerabilities
    println!("\n🚨 Top vulnerabilities:");
    for (i, vuln) in results.vulnerabilities.iter().take(3).enumerate() {
        println!("{}. {} ({})", i + 1, vuln.title, vuln.severity);
        println!("   {}", vuln.description);
    }

    println!("\n✅ Comprehensive report generation completed\n");
    Ok(())
}

/// Helper function for demonstration
fn _show_available_plugins() {
    println!("🔌 Available Analysis Plugins:");
    let plugin_manager = PluginManager::new();
    let plugins = plugin_manager.get_available_plugins();
    
    for plugin in plugins {
        println!("- {}: {}", plugin.name, plugin.description);
        println!("  Languages: {}", plugin.supported_languages.join(", "));
        println!("  Tools: {}", plugin.available_tools.join(", "));
        println!();
    }
}

/// Helper function to demonstrate configuration options
fn _show_configuration_options() {
    println!("⚙️  Configuration Options:");
    println!("- AI backends: local (Ollama), openai, anthropic");
    println!("- Analysis depths: basic, standard, deep");
    println!("- Output formats: console, markdown, html, json, pdf");
    println!("- Supported networks: ethereum, polygon, arbitrum, optimism, bsc");
    println!("- Log levels: trace, debug, info, warn, error");
}
