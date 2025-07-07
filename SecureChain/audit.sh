
#!/bin/bash

# SecureChain Perfect Audit Launcher
# Usage: ./audit.sh <contract_path> [output_dir]

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONTRACT_PATH="$1"
OUTPUT_DIR="${2:-./audit_results}"

if [ -z "$CONTRACT_PATH" ]; then
    echo "Usage: $0 <contract_path> [output_dir]"
    echo "Example: $0 ./contracts/MyToken.sol ./my_audit_results"
    exit 1
fi

echo "🚀 SecureChain Perfect Audit"
echo "=========================="
echo "Contract: $CONTRACT_PATH"
echo "Output: $OUTPUT_DIR"
echo ""

# Build if needed
if [ ! -f "$SCRIPT_DIR/target/release/securechain" ]; then
    echo "🏗️  Building SecureChain..."
    cd "$SCRIPT_DIR"
    cargo build --release
fi

# Set up environment variables if not set
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"

if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "⚠️  Warning: No AI API keys found. AI analysis will be skipped."
    echo "   Set OPENAI_API_KEY or ANTHROPIC_API_KEY for full AI capabilities."
    LLM_BACKEND="local"
else
    LLM_BACKEND="openai"
fi

# Run perfect audit
"$SCRIPT_DIR/target/release/securechain" perfect \
    --input "$CONTRACT_PATH" \
    --output "$OUTPUT_DIR" \
    --creativity high \
    --llm "$LLM_BACKEND" \
    --yes

echo ""
echo "🎉 Perfect audit completed!"
echo "📁 Results available in: $OUTPUT_DIR"
echo ""
echo "Quick access:"
echo "  📋 Executive Summary: $OUTPUT_DIR/executive_summary.md"
echo "  🔍 Technical Report: $OUTPUT_DIR/technical_report.md"
echo "  ⚡ PoC Exploits: $OUTPUT_DIR/poc_exploits/"
