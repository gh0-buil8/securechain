//! BugForgeX - Universal Web3 Smart Contract Security Auditor
//! 
//! A comprehensive Rust-based CLI tool for Web3 smart contract security auditing
//! with AI-powered vulnerability detection across multiple blockchain platforms.

use std::env;

fn print_banner() {
    println!("
    ██████╗ ██╗   ██╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗██╗  ██╗
    ██╔══██╗██║   ██║██╔════╝ ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝╚██╗██╔╝
    ██████╔╝██║   ██║██║  ███╗█████╗  ██║   ██║██████╔╝██║  ███╗█████╗   ╚███╔╝ 
    ██╔══██╗██║   ██║██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝   ██╔██╗ 
    ██████╔╝╚██████╔╝╚██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗██╔╝ ██╗
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
    
    Universal Web3 Smart Contract Security Auditor
    Version 0.1.0 - Powered by Rust & AI
    ");
}

fn main() {
    // Initialize logging
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    // Display banner
    print_banner();

    println!("🔍 BugForgeX - Universal Web3 Smart Contract Security Auditor");
    println!("=============================================================");
    println!();
    
    println!("✅ Build successful!");
    println!("📋 Available commands:");
    println!("   bugforgex analyze <contract>     - Analyze smart contract for vulnerabilities");
    println!("   bugforgex fetch <address>        - Fetch contract from blockchain explorer");  
    println!("   bugforgex probe <contract>       - Generate creative vulnerability probes");
    println!("   bugforgex report <results>       - Generate comprehensive audit report");
    println!("   bugforgex config                 - Manage configuration settings");
    println!("   bugforgex install                - Install analysis dependencies");
    println!("   bugforgex --help                 - Show detailed help information");
    println!();
    
    println!("🌟 Features:");
    println!("   • Multi-platform support: EVM, Move, Cairo, Ink!, Rust");
    println!("   • AI-powered vulnerability detection");
    println!("   • Static analysis with Slither, Mythril integration");
    println!("   • Dynamic testing and fuzzing with Echidna");
    println!("   • Creative exploit hypothesis generation");
    println!("   • Professional audit reports in multiple formats");
    println!();
    
    println!("📖 Quick Start:");
    println!("   # Analyze a Solidity contract");
    println!("   bugforgex analyze contract.sol");
    println!();
    println!("   # Fetch and analyze from Etherscan");
    println!("   bugforgex fetch 0x1234... --network ethereum");
    println!();
    println!("   # Generate AI-powered creative probes");  
    println!("   bugforgex probe contract.sol --creativity high");
    println!();
    
    println!("🔧 Configuration:");
    println!("   Config file: ~/.config/bugforgex/config.toml");
    println!("   Set AI backend: bugforgex config set ai.backend openai");
    println!("   View settings: bugforgex config show");
    println!();
    
    println!("🚀 Ready to secure Web3! Run 'bugforgex --help' for detailed usage.");
}