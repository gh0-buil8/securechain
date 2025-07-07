
# SecureChain Quick Start

## Installation
The tool is already installed via cargo. You can access it from anywhere using `securechain` or run it locally.

## Quick Commands

### 1. Run from SecureChain directory
```bash
cd SecureChain
./quick_start.sh
```

### 2. Analyze a contract
```bash
cd SecureChain
./target/release/securechain analyze -i test_contracts/vulnerable_sample.sol -t evm -d standard -o markdown
```

### 3. Get help
```bash
cd SecureChain
./target/release/securechain --help
```

### 4. Test with sample contracts
```bash
cd SecureChain
./target/release/securechain analyze -i test_contracts/ -t evm -d deep --ai
```

## Available Commands
- `analyze` - Analyze smart contracts for vulnerabilities
- `audit` - Run comprehensive security audit
- `fetch` - Fetch contracts from blockchain
- `config` - Configure settings
- `update` - Update tools and databases

## Supported Platforms
- EVM (Ethereum, Polygon, BSC, Arbitrum, Optimism)
- Solana (Rust)
- Move (Aptos, Sui)
- Cairo (StarkNet)
- Ink! (Polkadot/Substrate)

## Quick Tips
1. Use the Run button or click on workflows in the left panel
2. Start with the "Test SecureChain" workflow to verify installation
3. Use "Run SecureChain" workflow for help and commands
4. Check `test_contracts/` for sample vulnerable contracts
