// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableContract
 * @dev This contract contains several intentional vulnerabilities for testing BugForgeX
 */
contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalSupply;
    bool private locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    modifier noReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 10**18;
        balances[owner] = totalSupply;
    }

    /**
     * @dev Deposit Ether to the contract
     * Vulnerability: No checks on deposit amount
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Withdraw Ether from the contract
     * Vulnerability: Reentrancy attack possible
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerability: External call before state update
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Safe withdrawal with reentrancy protection
     */
    function safeWithdraw(uint256 amount) external noReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Transfer tokens between accounts
     * Vulnerability: Integer overflow possible in older versions
     */
    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "Cannot transfer to zero address");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @dev Mint new tokens
     * Vulnerability: Missing access control
     */
    function mint(address to, uint256 amount) external {
        require(to != address(0), "Cannot mint to zero address");
        
        // Vulnerability: Anyone can mint tokens
        balances[to] += amount;
        totalSupply += amount;
    }

    /**
     * @dev Burn tokens
     * Vulnerability: No check if user has sufficient balance
     */
    function burn(uint256 amount) external {
        // Vulnerability: Could underflow if balance < amount
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }

    /**
     * @dev Emergency function - only owner
     * Vulnerability: Centralization risk
     */
    function emergencyDrain() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    /**
     * @dev Update owner
     * Vulnerability: No two-step ownership transfer
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }

    /**
     * @dev Price calculation with potential manipulation
     * Vulnerability: Division by zero, price manipulation
     */
    function getPrice(uint256 supply, uint256 demand) external pure returns (uint256) {
        // Vulnerability: Division by zero if demand is 0
        return supply / demand;
    }

    /**
     * @dev Batch transfer - gas optimization gone wrong
     * Vulnerability: DoS via gas limit
     */
    function batchTransfer(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        
        // Vulnerability: No limit on array length - potential DoS
        for (uint256 i = 0; i < recipients.length; i++) {
            transfer(recipients[i], amounts[i]);
        }
    }

    /**
     * @dev Time-based function
     * Vulnerability: Timestamp manipulation
     */
    function timeBasedFunction() external view returns (bool) {
        // Vulnerability: Miners can manipulate block.timestamp
        return block.timestamp % 10 == 0;
    }

    /**
     * @dev Randomness function
     * Vulnerability: Predictable randomness
     */
    function generateRandom() external view returns (uint256) {
        // Vulnerability: Predictable "randomness"
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }

    /**
     * @dev Get contract balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Get user balance
     */
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /**
     * @dev Fallback function to receive Ether
     */
    receive() external payable {
        deposit();
    }
}