
#!/bin/bash

echo "🔧 Building SecureChain..."
cargo build --release

echo "🧪 Testing SecureChain with sample contract..."
./target/release/securechain analyze -i test_contract.sol -t evm -d standard -o markdown

echo "📋 Testing configuration..."
./target/release/securechain config --list

echo "✅ Test completed!"
