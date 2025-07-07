
#!/bin/bash

set -e

echo "🔧 Setting up SecureChain - Universal Web3 Security Auditor"
echo "=========================================================="

# Check if running on supported OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "❌ Unsupported OS. Please use Linux or macOS."
    exit 1
fi

# Install system dependencies
echo "📦 Installing system dependencies..."

if [[ "$OS" == "linux" ]]; then
    # Update package manager
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip nodejs npm git curl build-essential
    elif command -v yum &> /dev/null; then
        sudo yum update -y
        sudo yum install -y python3 python3-pip nodejs npm git curl gcc gcc-c++ make
    fi
elif [[ "$OS" == "macos" ]]; then
    # Install Homebrew if not present
    if ! command -v brew &> /dev/null; then
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python3 node git curl
fi

# Install Rust if not present
if ! command -v cargo &> /dev/null; then
    echo "🦀 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Install Python analysis tools
echo "🐍 Installing Python security tools..."
pip3 install --user slither-analyzer mythril crytic-compile

# Install Echidna fuzzer
echo "🎲 Installing Echidna fuzzer..."
if [[ "$OS" == "linux" ]]; then
    curl -L https://github.com/crytic/echidna/releases/latest/download/echidna-test-2.2.1-Ubuntu-22.04.tar.gz | tar -xz
    sudo mv echidna-test /usr/local/bin/
elif [[ "$OS" == "macos" ]]; then
    curl -L https://github.com/crytic/echidna/releases/latest/download/echidna-test-2.2.1-macOS.tar.gz | tar -xz
    sudo mv echidna-test /usr/local/bin/
fi

# Install Foundry for advanced testing
echo "⚒️  Installing Foundry..."
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Install additional tools
echo "🔍 Installing additional analysis tools..."
npm install -g solhint @openzeppelin/contracts

# Build SecureChain
echo "🏗️  Building SecureChain..."
cargo build --release

# Create symlink for global access
sudo ln -sf $(pwd)/target/release/securechain /usr/local/bin/securechain

echo "✅ Setup completed successfully!"
echo "🚀 You can now run: securechain --help"
