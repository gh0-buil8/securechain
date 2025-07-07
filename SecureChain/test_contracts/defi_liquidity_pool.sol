// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title DeFi Liquidity Pool
 * @dev Complex DeFi contract with multiple vulnerabilities for advanced testing
 */
contract DeFiLiquidityPool {
    IERC20 public tokenA;
    IERC20 public tokenB;
    
    mapping(address => uint256) public liquidityShares;
    mapping(address => uint256) public lastDepositTime;
    mapping(address => bool) public isWhitelisted;
    
    uint256 public totalLiquidity;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public feeRate = 3; // 0.3%
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    
    address public owner;
    address public feeRecipient;
    bool public paused;
    
    event LiquidityAdded(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event LiquidityRemoved(address indexed provider, uint256 amountA, uint256 amountB, uint256 liquidity);
    event Swap(address indexed user, uint256 amountIn, uint256 amountOut, bool isTokenA);
    event EmergencyWithdraw(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier notPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    modifier onlyWhitelisted() {
        require(isWhitelisted[msg.sender] || msg.sender == owner, "Not whitelisted");
        _;
    }

    constructor(address _tokenA, address _tokenB, address _feeRecipient) {
        tokenA = IERC20(_tokenA);
        tokenB = IERC20(_tokenB);
        owner = msg.sender;
        feeRecipient = _feeRecipient;
        isWhitelisted[msg.sender] = true;
    }

    /**
     * @dev Add liquidity to the pool
     * Vulnerability: Price manipulation during low liquidity
     */
    function addLiquidity(uint256 amountA, uint256 amountB) external notPaused {
        require(amountA > 0 && amountB > 0, "Invalid amounts");
        
        uint256 liquidity;
        
        if (totalLiquidity == 0) {
            // Initial liquidity
            liquidity = sqrt(amountA * amountB);
            require(liquidity > MINIMUM_LIQUIDITY, "Insufficient liquidity");
        } else {
            // Vulnerability: No slippage protection
            uint256 liquidityA = (amountA * totalLiquidity) / reserveA;
            uint256 liquidityB = (amountB * totalLiquidity) / reserveB;
            liquidity = liquidityA < liquidityB ? liquidityA : liquidityB;
        }
        
        require(liquidity > 0, "Insufficient liquidity minted");
        
        // Transfer tokens
        tokenA.transferFrom(msg.sender, address(this), amountA);
        tokenB.transferFrom(msg.sender, address(this), amountB);
        
        // Update state
        liquidityShares[msg.sender] += liquidity;
        totalLiquidity += liquidity;
        reserveA += amountA;
        reserveB += amountB;
        lastDepositTime[msg.sender] = block.timestamp;
        
        emit LiquidityAdded(msg.sender, amountA, amountB, liquidity);
    }

    /**
     * @dev Remove liquidity from pool
     * Vulnerability: No time lock, immediate withdrawal possible
     */
    function removeLiquidity(uint256 liquidity) external notPaused {
        require(liquidity > 0, "Invalid liquidity amount");
        require(liquidityShares[msg.sender] >= liquidity, "Insufficient liquidity");
        
        uint256 amountA = (liquidity * reserveA) / totalLiquidity;
        uint256 amountB = (liquidity * reserveB) / totalLiquidity;
        
        require(amountA > 0 && amountB > 0, "Insufficient liquidity burned");
        
        // Update state
        liquidityShares[msg.sender] -= liquidity;
        totalLiquidity -= liquidity;
        reserveA -= amountA;
        reserveB -= amountB;
        
        // Transfer tokens
        tokenA.transfer(msg.sender, amountA);
        tokenB.transfer(msg.sender, amountB);
        
        emit LiquidityRemoved(msg.sender, amountA, amountB, liquidity);
    }

    /**
     * @dev Swap tokens using constant product formula
     * Vulnerability: MEV attacks, front-running susceptible
     */
    function swapAforB(uint256 amountAIn, uint256 minAmountBOut) external notPaused {
        require(amountAIn > 0, "Invalid input amount");
        require(reserveA > 0 && reserveB > 0, "Insufficient liquidity");
        
        uint256 amountBOut = getAmountOut(amountAIn, reserveA, reserveB);
        require(amountBOut >= minAmountBOut, "Slippage exceeded");
        
        // Vulnerability: External call before state update
        tokenA.transferFrom(msg.sender, address(this), amountAIn);
        tokenB.transfer(msg.sender, amountBOut);
        
        // Update reserves
        reserveA += amountAIn;
        reserveB -= amountBOut;
        
        emit Swap(msg.sender, amountAIn, amountBOut, true);
    }

    /**
     * @dev Swap tokens B for A
     */
    function swapBforA(uint256 amountBIn, uint256 minAmountAOut) external notPaused {
        require(amountBIn > 0, "Invalid input amount");
        require(reserveA > 0 && reserveB > 0, "Insufficient liquidity");
        
        uint256 amountAOut = getAmountOut(amountBIn, reserveB, reserveA);
        require(amountAOut >= minAmountAOut, "Slippage exceeded");
        
        tokenB.transferFrom(msg.sender, address(this), amountBIn);
        tokenA.transfer(msg.sender, amountAOut);
        
        reserveB += amountBIn;
        reserveA -= amountAOut;
        
        emit Swap(msg.sender, amountBIn, amountAOut, false);
    }

    /**
     * @dev Flash loan functionality
     * Vulnerability: Reentrancy possible, no proper flash loan protection
     */
    function flashLoan(uint256 amount, bool isTokenA, bytes calldata data) external notPaused {
        require(amount > 0, "Invalid amount");
        
        uint256 balanceBefore;
        uint256 fee = (amount * feeRate) / 1000;
        
        if (isTokenA) {
            require(amount <= reserveA, "Insufficient tokenA");
            balanceBefore = tokenA.balanceOf(address(this));
            tokenA.transfer(msg.sender, amount);
        } else {
            require(amount <= reserveB, "Insufficient tokenB");
            balanceBefore = tokenB.balanceOf(address(this));
            tokenB.transfer(msg.sender, amount);
        }
        
        // Vulnerability: External call without proper reentrancy protection
        (bool success, ) = msg.sender.call(data);
        require(success, "Flash loan callback failed");
        
        // Check repayment
        if (isTokenA) {
            require(tokenA.balanceOf(address(this)) >= balanceBefore + fee, "Flash loan not repaid");
            reserveA = tokenA.balanceOf(address(this));
        } else {
            require(tokenB.balanceOf(address(this)) >= balanceBefore + fee, "Flash loan not repaid");
            reserveB = tokenB.balanceOf(address(this));
        }
        
        // Send fee to recipient
        if (fee > 0) {
            if (isTokenA) {
                tokenA.transfer(feeRecipient, fee);
                reserveA -= fee;
            } else {
                tokenB.transfer(feeRecipient, fee);
                reserveB -= fee;
            }
        }
    }

    /**
     * @dev Emergency withdrawal - only whitelisted users
     * Vulnerability: Centralization risk, emergency function abuse
     */
    function emergencyWithdraw() external onlyWhitelisted {
        uint256 userLiquidity = liquidityShares[msg.sender];
        require(userLiquidity > 0, "No liquidity to withdraw");
        
        // Vulnerability: No time restrictions on emergency withdrawals
        uint256 amountA = (userLiquidity * reserveA) / totalLiquidity;
        uint256 amountB = (userLiquidity * reserveB) / totalLiquidity;
        
        liquidityShares[msg.sender] = 0;
        totalLiquidity -= userLiquidity;
        reserveA -= amountA;
        reserveB -= amountB;
        
        tokenA.transfer(msg.sender, amountA);
        tokenB.transfer(msg.sender, amountB);
        
        emit EmergencyWithdraw(msg.sender, userLiquidity);
    }

    /**
     * @dev Calculate output amount using constant product formula
     * Vulnerability: Potential for price manipulation
     */
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) 
        public view returns (uint256) {
        require(amountIn > 0, "Invalid input amount");
        require(reserveIn > 0 && reserveOut > 0, "Insufficient liquidity");
        
        uint256 amountInWithFee = amountIn * (1000 - feeRate);
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        
        return numerator / denominator;
    }

    /**
     * @dev Get current price ratio
     * Vulnerability: Price oracle manipulation
     */
    function getPrice() external view returns (uint256) {
        require(reserveA > 0 && reserveB > 0, "No liquidity");
        return (reserveB * 1e18) / reserveA;
    }

    /**
     * @dev Admin functions with potential for abuse
     */
    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function setFeeRate(uint256 newFeeRate) external onlyOwner {
        require(newFeeRate <= 100, "Fee too high"); // Max 10%
        feeRate = newFeeRate;
    }

    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "Invalid address");
        feeRecipient = newRecipient;
    }

    function addToWhitelist(address user) external onlyOwner {
        isWhitelisted[user] = true;
    }

    function removeFromWhitelist(address user) external onlyOwner {
        isWhitelisted[user] = false;
    }

    /**
     * @dev Governance function with potential for abuse
     * Vulnerability: No timelock, immediate execution
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }

    /**
     * @dev Utility function for calculating square root
     */
    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        return y;
    }

    /**
     * @dev Sync reserves with actual token balances
     * Vulnerability: Public function that can be called to manipulate reserves
     */
    function sync() external {
        reserveA = tokenA.balanceOf(address(this));
        reserveB = tokenB.balanceOf(address(this));
    }

    /**
     * @dev Get contract statistics
     */
    function getReserves() external view returns (uint256, uint256, uint256) {
        return (reserveA, reserveB, totalLiquidity);
    }

    function getUserLiquidity(address user) external view returns (uint256) {
        return liquidityShares[user];
    }
}