# Contributing to BugForgeX

We're excited that you're interested in contributing to BugForgeX! This guide will help you get started with contributing to our universal Web3 smart contract security auditor.

## 🌟 Ways to Contribute

### 🐛 Bug Reports
- Report security vulnerabilities responsibly
- Submit detailed bug reports with reproduction steps
- Provide feedback on usability and documentation

### 💡 Feature Requests
- Suggest new blockchain platform support
- Propose new analysis techniques
- Request integration with additional tools

### 🔧 Code Contributions
- Fix bugs and improve existing features
- Add support for new blockchain platforms
- Implement new security analysis techniques
- Improve AI-powered vulnerability detection

### 📚 Documentation
- Improve user guides and tutorials
- Add code comments and documentation
- Create examples and use cases
- Translate documentation

## 🚀 Getting Started

### Prerequisites

Before contributing, make sure you have:

- **Rust 1.70+**: [Install Rust](https://rustup.rs/)
- **Git**: Version control system
- **Python 3.8+**: For security tools integration
- Basic knowledge of smart contracts and security

### Development Setup

1. **Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/yourusername/bugforgex.git
   cd bugforgex
   ```

2. **Set Up Development Environment**
   ```bash
   # Install dependencies
   cargo build
   
   # Run tests to ensure everything works
   cargo test
   
   # Install development tools
   cargo install cargo-watch cargo-audit
   ```

3. **Create a Development Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/bug-description
   ```

4. **Install Analysis Tools (Optional)**
   ```bash
   # Install external security tools for testing
   pip install slither-analyzer mythril
   ```

## 🏗️ Project Structure

Understanding the codebase structure will help you contribute effectively:

