
#!/bin/bash

# Quick SecureChain Scanner
# Usage: ./quick_scan.sh <contract_file_or_dir> [target_platform]

set -e

echo "🚀 SecureChain Quick Scanner"
echo "=============================="

# Check arguments
if [ $# -eq 0 ]; then
    echo "Usage: $0 <contract_file_or_directory> [target_platform]"
    echo "Example: $0 mycontract.sol evm"
    echo "Example: $0 contracts/ evm"
    exit 1
fi

INPUT=$1
TARGET=${2:-evm}

# Build if needed
if [ ! -f "./target/release/securechain" ]; then
    echo "🏗️  Building SecureChain (first time only)..."
    cargo build --release
fi

echo "🔍 Scanning: $INPUT"
echo "🎯 Platform: $TARGET"
echo ""

# Run the scan
./target/release/securechain scan -i "$INPUT" -t "$TARGET"

echo ""
echo "✅ Scan complete! Check the scan_results_* directory for detailed reports."
