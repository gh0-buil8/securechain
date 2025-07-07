
#!/bin/bash

# Quick Fuzzing Script
# Usage: ./quick_fuzz.sh <contract_file>

set -e

echo "🎲 SecureChain Quick Fuzzer"
echo "============================"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <contract_file>"
    echo "Example: $0 mycontract.sol"
    exit 1
fi

INPUT=$1

# Build if needed
if [ ! -f "./target/release/securechain" ]; then
    echo "🏗️  Building SecureChain..."
    cargo build --release
fi

echo "🎯 Fuzzing: $INPUT"
echo ""

# Run fuzzing-focused audit
./target/release/securechain audit -i "$INPUT" -t evm --fuzz -o "fuzz_$(date +%Y%m%d_%H%M%S)"

echo ""
echo "✅ Fuzzing complete!"
