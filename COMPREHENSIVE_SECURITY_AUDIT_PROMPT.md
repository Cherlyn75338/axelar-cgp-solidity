# Axelar Cross-Chain Gateway Protocol - Comprehensive Security Audit Prompt

## Protocol Overview

Axelar is a decentralized interoperability network enabling cross-chain token transfers and arbitrary message passing between EVM chains. The protocol uses a decentralized validator network to confirm events on source chains and execute signed commands on destination chains through gateway smart contracts.

**Critical Impact Targets:**
- Privilege escalation resulting in severe impact
- Unauthorized mint/burn/transfer of wrapped assets  
- Protocol insolvency
- Permanent freezing of funds
- Direct theft of user funds (at-rest or in-motion)

## Architecture Summary

### Core Components
1. **AxelarGateway.sol** - Main gateway contract handling cross-chain operations
2. **AxelarAuthWeighted.sol** - Weighted multisig authentication module
3. **BurnableMintableCappedERC20.sol** - Wrapped token contract
4. **AxelarDepositService.sol** - Deposit address generation and management
5. **DepositHandler.sol** - Temporary contract for token burning/locking
6. **DepositReceiver.sol** - Temporary contract for deposit processing
7. **Proxy Contracts** - Upgradeable proxy pattern implementation

### Key Flows
- **Token Transfer**: User deposits → Axelar validators confirm → Signed command execution → Token mint on destination
- **Cross-chain Calls**: Contract call → Event confirmation → Approval command → Message execution
- **Deposit Service**: Dynamic address generation → Deposit detection → Automatic cross-chain sending

---

## Critical Security Areas for Audit

### 1. **AxelarGateway.sol - Core Attack Vectors**

#### **Entry Points Analysis**
```solidity
// PUBLIC FUNCTIONS - Critical Entry Points
function sendToken(string calldata destinationChain, string calldata destinationAddress, string calldata symbol, uint256 amount)
function callContract(string calldata destinationChain, string calldata destinationContractAddress, bytes calldata payload)  
function callContractWithToken(string calldata destinationChain, string calldata destinationContractAddress, bytes calldata payload, string calldata symbol, uint256 amount)
function execute(bytes calldata input) // ⚠️ MOST CRITICAL - Processes signed commands
```

#### **Critical Vulnerability Patterns to Examine:**

**A. Command Execution Flow (Lines 472-534)**
```solidity
function execute(bytes calldata input) external override {
    (bytes memory data, bytes memory proof) = abi.decode(input, (bytes, bytes));
    bytes32 messageHash = ECDSA.toEthSignedMessageHash(keccak256(data));
    bool allowOperatorshipTransfer = IAxelarAuth(authModule).validateProof(messageHash, proof);
    // ... command processing
}
```

**🔍 AUDIT FOCUS:**
- **Signature Replay**: Can the same signature be reused across chains/contexts?
- **Command ID Manipulation**: Can `commandId` uniqueness be bypassed? (Line 499)
- **Reentrancy in Command Execution**: Self-call at line 528 - vulnerable to reentrancy?
- **Proof Validation Bypass**: Can `validateProof` be manipulated?
- **Chain ID Validation**: Is `block.chainid` check sufficient? (Line 489)

**B. Token Operations - Mint/Burn Logic**
```solidity
function _mintToken(string memory symbol, address account, uint256 amount) internal {
    address tokenAddress = tokenAddresses(symbol);
    if (tokenAddress == address(0)) revert TokenDoesNotExist(symbol);
    _setTokenMintAmount(symbol, tokenMintAmount(symbol) + amount);
    
    if (_getTokenType(symbol) == TokenType.External) {
        IERC20(tokenAddress).safeTransfer(account, amount); // ⚠️ External token transfer
    } else {
        IBurnableMintableCappedERC20(tokenAddress).mint(account, amount); // ⚠️ Internal mint
    }
}
```

**🔍 AUDIT FOCUS:**
- **Mint Limit Bypass**: Can `_setTokenMintAmount` checks be circumvented? (Lines 824-828)
- **Token Type Confusion**: Can `TokenType.External` vs `TokenType.InternalBurnableFrom` be manipulated?
- **Double Minting**: Race conditions in mint amount tracking?
- **Unauthorized Minting**: Can mint commands be forged or replayed?

**C. Burn Token Mechanism (Lines 603-629)**
```solidity
function burnToken(bytes calldata params, bytes32) external onlySelf {
    (string memory symbol, bytes32 salt) = abi.decode(params, (string, bytes32));
    
    if (_getTokenType(symbol) == TokenType.External) {
        address depositHandlerAddress = _getCreate2Address(salt, keccak256(abi.encodePacked(type(DepositHandler).creationCode)));
        if (depositHandlerAddress.isContract()) return; // ⚠️ Early return without burning
        
        DepositHandler depositHandler = new DepositHandler{ salt: salt }();
        // ... transfer and destroy logic
    }
}
```

**🔍 AUDIT FOCUS:**
- **CREATE2 Collision**: Can `salt` be manipulated to cause address collisions?
- **Burn Bypass**: Early return on line 613 - can this be exploited?
- **DepositHandler Destruction**: Is the destroy pattern secure?
- **Token Recovery**: Can tokens be recovered from destroyed handlers?

### 2. **Authentication & Authorization System**

#### **AxelarAuthWeighted.sol - Signature Validation**
```solidity
function validateProof(bytes32 messageHash, bytes calldata proof) external view returns (bool) {
    (address[] memory operators, uint256[] memory weights, uint256 threshold, bytes[] memory signatures) = abi.decode(proof, (address[], uint256[], uint256, bytes[]));
    
    bytes32 operatorsHash = keccak256(abi.encode(operators, weights, threshold));
    uint256 operatorsEpoch = epochForHash[operatorsHash];
    
    if (operatorsEpoch == 0 || epoch - operatorsEpoch >= OLD_KEY_RETENTION) revert InvalidOperators();
    _validateSignatures(messageHash, operators, weights, threshold, signatures);
    
    return operatorsEpoch == epoch;
}
```

**🔍 AUDIT FOCUS:**
- **Signature Malleability**: ECDSA signature validation in `_validateSignatures` (Lines 91-119)
- **Operator Set Manipulation**: Can operator arrays be manipulated during validation?
- **Epoch Confusion**: Can old epochs be used maliciously?
- **Weight Threshold Bypass**: Integer overflow/underflow in weight calculations?
- **Duplicate Operator Attack**: Sorted operator validation bypass?

### 3. **Proxy & Upgrade System**

#### **AxelarGatewayProxy.sol - Proxy Pattern**
```solidity
fallback() external payable {
    address implementation = getAddress(KEY_IMPLEMENTATION);
    assembly {
        calldatacopy(0, 0, calldatasize())
        let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
        returndatacopy(0, 0, returndatasize())
        switch result
        case 0 { revert(0, returndatasize()) }
        default { return(0, returndatasize()) }
    }
}
```

**🔍 AUDIT FOCUS:**
- **Implementation Slot Collision**: `KEY_IMPLEMENTATION` storage collision with other variables?
- **Upgrade Authorization**: Can `upgrade()` function be called by unauthorized parties?
- **Setup Function Bypass**: Empty `setup()` function - can this be exploited?
- **Storage Layout Compatibility**: Upgrade safety between implementation versions?

### 4. **Deposit Service System**

#### **AxelarDepositService.sol - Dynamic Address Generation**
```solidity
function _depositAddress(bytes32 salt, bytes memory delegateData, address refundAddress) internal view returns (address) {
    return address(uint160(uint256(keccak256(abi.encodePacked(
        hex'ff',
        address(this),
        salt,
        keccak256(abi.encodePacked(type(DepositReceiver).creationCode, abi.encode(delegateData, refundAddress)))
    )))));
}
```

**🔍 AUDIT FOCUS:**
- **Address Prediction**: Can attackers predict and front-run deposit addresses?
- **Salt Collision**: Can `salt` be manipulated to cause address reuse?
- **Refund Mechanism**: Can refund logic be exploited for theft?
- **DepositReceiver Destruction**: Immediate selfdestruct - any race conditions?

#### **DepositReceiver.sol - Temporary Contract Pattern**
```solidity
constructor(bytes memory delegateData, address refundAddress) {
    (bool success, ) = IAxelarDepositService(msg.sender).receiverImplementation().delegatecall(delegateData);
    if (!success) {
        assembly {
            let ptr := mload(0x40)
            let size := returndatasize()
            returndatacopy(ptr, 0, size)
            revert(ptr, size)
        }
    }
    if (refundAddress == address(0)) refundAddress = msg.sender;
    selfdestruct(payable(refundAddress));
}
```

**🔍 AUDIT FOCUS:**
- **Delegatecall Safety**: Can malicious `delegateData` exploit the receiver?
- **Refund Address Manipulation**: Can `refundAddress` be controlled by attackers?
- **Selfdestruct Timing**: Race conditions during destruction?
- **ETH/Token Recovery**: Can value be extracted during destruction?

### 5. **Token Contract Security**

#### **BurnableMintableCappedERC20.sol**
```solidity
function burn(bytes32 salt) external onlyOwner {
    address account = depositAddress(salt);
    _burn(account, balanceOf[account]);
}

function burnFrom(address account, uint256 amount) external onlyOwner {
    uint256 _allowance = allowance[account][msg.sender];
    if (_allowance != type(uint256).max) {
        _approve(account, msg.sender, _allowance - amount);
    }
    _burn(account, amount);
}
```

**🔍 AUDIT FOCUS:**
- **Owner Privilege**: Gateway as owner - can ownership be transferred maliciously?
- **Allowance Manipulation**: Infinite allowance handling - overflow issues?
- **Deposit Address Calculation**: CREATE2 address prediction vulnerabilities?
- **Cap Enforcement**: Mint cap bypass in `MintableCappedERC20`?

---

## Specific Attack Scenarios to Test

### **Scenario 1: Cross-Chain Token Theft**
1. User deposits 1000 USDC on Ethereum for transfer to Polygon
2. Attacker manipulates command execution to mint tokens to their address
3. Original user never receives tokens on destination chain
**Test**: Can command parameters be manipulated post-signature?

### **Scenario 2: Signature Replay Attack**
1. Valid command signed by operators for Chain A
2. Attacker replays same signature on Chain B
3. Unauthorized minting occurs on Chain B
**Test**: Are signatures properly bound to specific chains/contexts?

### **Scenario 3: Deposit Address Front-Running**
1. User generates deposit address for cross-chain transfer
2. Attacker predicts address and deposits malicious tokens first
3. Legitimate deposit fails or gets mixed with malicious tokens
**Test**: Can deposit addresses be predicted and exploited?

### **Scenario 4: Mint Limit Bypass**
1. Token has daily mint limit of 100,000 USDC
2. Attacker finds way to reset or bypass mint amount tracking
3. Unlimited minting occurs, breaking protocol solvency
**Test**: Can mint amount tracking be manipulated?

### **Scenario 5: Governance/Upgrade Exploit**
1. Attacker gains control of governance or exploits upgrade mechanism
2. Malicious implementation deployed that steals all tokens
3. All protocol funds drained
**Test**: Are governance controls and upgrade mechanisms secure?

### **Scenario 6: DepositHandler/Receiver Exploitation**
1. User deposits tokens to generated address
2. Attacker exploits DepositReceiver logic during delegatecall
3. Tokens redirected to attacker instead of cross-chain transfer
**Test**: Can temporary contract patterns be exploited?

---

## Code Quality Red Flags

### **Dangerous Patterns Found:**
1. **Self-calls in execute()** - Line 528: `address(this).call(abi.encodeWithSelector(commandSelector, params[i], commandId))`
2. **Multiple delegatecalls** - Proxy pattern, upgrade mechanism, deposit service
3. **CREATE2 address prediction** - Salt-based address generation
4. **Immediate selfdestruct** - DepositReceiver pattern
5. **Complex access control** - Multiple modifiers and role-based permissions
6. **External token interactions** - SafeTransfer library usage with external contracts

### **Slither Suppressions to Investigate:**
- `controlled-delegatecall` suppressions
- `reentrancy-no-eth` suppressions  
- `costly-loop` suppressions
- `reentrancy-benign` suppressions

---

## Testing Methodology

### **1. Static Analysis**
- Run Slither, Mythril, and other automated tools
- Focus on suppressed warnings - they may hide real issues
- Check for storage collisions in proxy pattern
- Validate access control modifiers

### **2. Dynamic Testing**
- Deploy on testnet and test all cross-chain flows
- Attempt signature replay attacks
- Test mint limit bypasses
- Validate deposit address generation
- Test upgrade mechanisms

### **3. Formal Verification**
- Verify mint/burn invariants
- Prove signature uniqueness properties
- Validate access control properties
- Check proxy storage layout safety

### **4. Integration Testing**
- Test with real Axelar validator network
- Validate cross-chain message integrity
- Test deposit service under load
- Validate token recovery mechanisms

---

## Expected Deliverables

For each contract and entry point, provide:

1. **Vulnerability Assessment**
   - Critical/High/Medium/Low severity classification
   - Detailed exploit path description
   - Proof of concept code where applicable

2. **Impact Analysis**
   - Funds at risk quantification
   - Protocol availability impact
   - User trust implications

3. **Mitigation Recommendations**
   - Immediate fixes required
   - Long-term architectural improvements
   - Monitoring and detection recommendations

4. **Test Cases**
   - Specific test scenarios to validate fixes
   - Regression test recommendations
   - Continuous security monitoring suggestions

---

## Critical Questions for Auditors

1. **Can command execution be manipulated to mint/burn unauthorized amounts?**
2. **Are signature replay attacks possible across chains or contexts?**
3. **Can deposit addresses be predicted and exploited?**
4. **Is the proxy upgrade mechanism secure against malicious implementations?**
5. **Can mint limits be bypassed through race conditions or integer overflow?**
6. **Are temporary contracts (DepositHandler/DepositReceiver) secure during their lifecycle?**
7. **Can governance be compromised to steal protocol funds?**
8. **Are there any reentrancy vulnerabilities in the complex call chains?**

The goal is to find vulnerabilities that could lead to the critical impacts specified: privilege escalation, unauthorized asset operations, insolvency, fund freezing, or direct theft. Pay special attention to the complex interactions between contracts and the cross-chain nature of the protocol.