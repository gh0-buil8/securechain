# BugForgeX

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-audit-green.svg)](https://github.com/bugforgex/bugforgex)

**Universal Web3 Smart Contract Security Auditor**

BugForgeX is a comprehensive, Rust-based CLI tool for Web3 smart contract security auditing with AI-powered vulnerability detection across multiple blockchain platforms. It combines static analysis, dynamic testing, fuzzing, and creative exploit discovery to identify security vulnerabilities in smart contracts.

## 🌟 Features

### 🔍 Multi-Platform Support
- **EVM Chains**: Ethereum, Polygon, Arbitrum, Optimism, BSC
- **Solidity Contracts**: Full static and dynamic analysis
- **Move Language**: Aptos, Sui smart contracts
- **Cairo**: StarkNet contracts
- **Ink!**: Polkadot/Substrate contracts
- **Rust**: Solana, NEAR, CosmWasm

### 🧠 AI-Powered Analysis
- **Creative Vulnerability Discovery**: Beyond traditional static analysis
- **Multiple AI Backends**: OpenAI GPT-4, Anthropic Claude, Local LLMs
- **Exploit Hypothesis Generation**: AI-generated proof-of-concept exploits
- **Edge Case Detection**: Discover complex attack vectors

### ⚡ Comprehensive Analysis Tools
- **Static Analysis**: Slither, Mythril integration
- **Dynamic Testing**: Echidna fuzzing, property testing
- **Symbolic Execution**: Deep path analysis
- **Custom Plugins**: Extensible architecture for new tools

### 📊 Professional Reporting
- **Multiple Formats**: Markdown, HTML, JSON, PDF
- **Executive Summaries**: Business-ready audit reports
- **Vulnerability Classification**: OWASP, CWE mappings
- **Remediation Guidance**: Actionable fix recommendations

## 🚀 Quick Start

### Prerequisites

- **Rust 1.70+**: [Install Rust](https://rustup.rs/)
- **Python 3.8+**: For Slither and Mythril
- **Node.js 16+**: For some analysis tools (optional)

### Installation

#### Option 1: Install from GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/bugforgex/bugforgex.git
cd bugforgex

# Build the project
cargo build --release

# Install globally
cargo install --path .
