
#!/bin/bash

echo "🚀 SecureChain Quick Start"
echo "========================"

# Build the project if not already built
if [ ! -f "./target/release/securechain" ]; then
    echo "🏗️  Building SecureChain..."
    cargo build --release
fi

# Check if we have test contracts
if [ ! -d "test_contracts" ]; then
    echo "📁 Creating test contracts directory..."
    mkdir -p test_contracts
fi

# Create a simple vulnerable contract for testing if it doesn't exist
if [ ! -f "test_contracts/vulnerable_sample.sol" ]; then
    echo "📝 Creating sample vulnerable contract..."
    cat > test_contracts/vulnerable_sample.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    
    // Vulnerable: Reentrancy attack possible
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable: External call before state change
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    // Vulnerable: Integer overflow (if using older Solidity)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Vulnerable: Unchecked return value
    function unsafeTransfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
EOF
fi

echo "✅ Quick start setup complete!"
echo "🔍 Running sample analysis..."

# Run analysis on the sample contract
./target/release/securechain analyze \
    -i test_contracts/vulnerable_sample.sol \
    -t evm \
    -d standard \
    -o markdown

echo ""
echo "🎉 Analysis complete! Try these commands:"
echo "  ./target/release/securechain --help"
echo "  ./target/release/securechain analyze -i your_contract.sol"
echo "  ./target/release/securechain config --list"
