
# 🚀 SecureChain Quick Usage

## One-Command Solutions

### 🎯 Quick Comprehensive Scan (Recommended)
```bash
# Scan a single contract
./target/release/securechain scan -i mycontract.sol

# Scan a directory
./target/release/securechain scan -i contracts/

# Scan without fuzzing (faster)
./target/release/securechain scan -i mycontract.sol --no-fuzz

# Scan without AI (faster)
./target/release/securechain scan -i mycontract.sol --no-ai
```

### 🎲 Quick Fuzzing Only
```bash
./target/release/securechain audit -i mycontract.sol --fuzz
```

### 🔍 Quick Static Analysis Only
```bash
./target/release/securechain analyze -i mycontract.sol
```

## Shell Scripts (Even Easier!)

```bash
# One-command scan (builds automatically if needed)
./quick_scan.sh mycontract.sol

# One-command fuzzing
./quick_fuzz.sh mycontract.sol
```

## What Each Command Does

- **`scan`**: Static analysis + AI analysis + fuzzing + exploit generation + comprehensive reports
- **`audit`**: Deep static analysis + optional fuzzing + detailed reports  
- **`analyze`**: Basic static analysis + simple report

## Output

All commands create timestamped result directories with:
- 📄 Markdown and JSON reports
- 🔥 PoC exploits for critical vulnerabilities  
- 📊 Security scores and recommendations

## Examples

```bash
# Quick scan of a DeFi contract
./quick_scan.sh defi_pool.sol evm

# Full audit with all features
./target/release/securechain scan -i my_nft.sol

# Fast scan without fuzzing
./target/release/securechain scan -i token.sol --no-fuzz
```

Just run one command and get comprehensive security analysis! 🛡️
