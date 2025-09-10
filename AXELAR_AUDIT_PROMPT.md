# 🔥 AXELAR CROSS-CHAIN GATEWAY PROTOCOL - CRITICAL SECURITY AUDIT PROMPT

## 🎯 PROTOCOL OVERVIEW & ATTACK SURFACE

The Axelar Gateway Protocol is a **decentralized cross-chain interoperability system** that enables:
- **Token transfers** between EVM chains via burn/mint or lock/unlock mechanisms
- **General message passing** with arbitrary payload execution
- **Validator-authenticated commands** using weighted multi-signature validation
- **Upgradeable proxy architecture** with governance controls

### Core Components Under Audit:
1. **AxelarGateway.sol** - Central gateway managing cross-chain operations
2. **AxelarAuthWeighted.sol** - Weighted multi-sig validator authentication
3. **DepositHandler.sol** - CREATE2-deployed handlers for token burns
4. **AxelarDepositService.sol** - Service layer for deposit address generation
5. **BurnableMintableCappedERC20.sol** - Wrapped token implementation
6. **Proxy contracts** - Upgradeable proxy pattern implementation

## 🚨 CRITICAL VULNERABILITY CATEGORIES TO HUNT

### 🔴 TIER 1: CATASTROPHIC (Direct Fund Theft / Total Protocol Compromise)

#### 1. **Validator Authentication Bypass**
```solidity
// CRITICAL PATH: AxelarAuthWeighted.validateProof() -> AxelarGateway.execute()
```
**Attack Vectors:**
- Signature malleability exploitation in ECDSA recovery
- Operator epoch manipulation allowing replay of old operator sets
- Weight calculation overflow/underflow bypassing threshold checks
- Race conditions in operator rotation during command execution

**Deep Dive Areas:**
- Line 30-44 in AxelarAuthWeighted.sol: validateProof logic
- Line 91-119: _validateSignatures weight accumulation
- Line 14: OLD_KEY_RETENTION = 16 epoch window exploitation

#### 2. **Command Execution Manipulation**
```solidity
// CRITICAL PATH: execute() -> self-delegatecall pattern
```
**Attack Vectors:**
- Command replay attacks via commandId manipulation
- Chain ID validation bypass (line 489 AxelarGateway)
- Reentrancy through execute() -> address(this).call pattern (line 528)
- Failed command re-execution vulnerability (line 532)

**Key Code Sections:**
- Lines 472-534: Main execute() function
- Lines 524-532: Command execution retry logic
- Line 499: Duplicate commandId check bypass

#### 3. **CREATE2 Address Collision & Front-running**
```solidity
// CRITICAL PATH: DepositHandler deployment via CREATE2
```
**Attack Vectors:**
- Salt prediction and front-running deposit addresses
- DepositHandler selfdestruct timing exploitation
- Address collision through controlled bytecode
- Race conditions between deployment and destruction

**Critical Code:**
- AxelarGateway lines 610-629: burnToken with CREATE2
- BurnableMintableCappedERC20 lines 19-32: depositAddress calculation
- DepositHandler line 29: selfdestruct vulnerability window

#### 4. **Token Mint/Burn Authorization Bypass**
```solidity
// CRITICAL PATH: mintToken() / burnToken() / burnFrom()
```
**Attack Vectors:**
- Mint limit bypass through epoch manipulation (6-hour window)
- Unauthorized minting via validateContractCallAndMint reentrancy
- Token type confusion (External vs Internal)
- Approval frontrunning in burnFrom operations

**Focus Areas:**
- Lines 696-712: _mintToken internal logic
- Lines 824-829: Mint limit enforcement
- Lines 270-278: validateContractCallAndMint reentrancy point

### 🔴 TIER 2: SEVERE (Protocol Insolvency / Permanent Fund Lock)

#### 5. **Proxy Upgrade Hijacking**
```solidity
// CRITICAL PATH: upgrade() -> delegatecall to new implementation
```
**Attack Vectors:**
- Storage collision in EternalStorage pattern
- Unauthorized upgrade through governance manipulation
- Implementation contract initialization bypass
- Proxy selector clashing attacks

**Critical Sections:**
- Lines 420-439: upgrade() function
- Line 435: Uncontrolled delegatecall
- Storage slot KEY_IMPLEMENTATION manipulation

#### 6. **Cross-chain Message Validation Bypass**
```solidity
// CRITICAL PATH: validateContractCall() state manipulation
```
**Attack Vectors:**
- Double-spending through approval state manipulation
- Payload hash collision attacks
- Source chain/address spoofing
- Contract call approval persistence bugs

**Key Areas:**
- Lines 233-246: validateContractCall approval consumption
- Lines 260-278: validateContractCallAndMint double-spend vector
- Line 242 & 272: _setBool(key, false) race conditions

#### 7. **Deposit Service Refund Mechanism Exploitation**
```solidity
// CRITICAL PATH: AxelarDepositService refund functions
```
**Attack Vectors:**
- Refund token state manipulation
- Reentrancy through refund callbacks
- Unauthorized refund extraction
- DepositReceiver delegatecall exploitation

**Focus Points:**
- Lines 137-170: refundTokenDeposit reentrancy
- Line 154: refundToken storage manipulation
- ReceiverImplementation delegatecall context confusion

### 🔴 TIER 3: HIGH (Access Control / DoS / Logic Flaws)

#### 8. **Governance & Admin Privilege Escalation**
```solidity
// CRITICAL PATH: Governance transfer and mint limiter controls
```
**Attack Vectors:**
- Governance transfer to zero address
- Mint limiter bypass through dual role confusion
- Setup function re-initialization
- Operator transfer during active commands

#### 9. **Gas Griefing & DoS Vectors**
```solidity
// CRITICAL PATH: Unbounded loops and external calls
```
**Attack Vectors:**
- Unbounded command array processing
- Signature validation gas exhaustion
- Storage operation gas bombs
- External call failure cascades

## 🔍 ADVANCED ATTACK PATTERNS TO INVESTIGATE

### A. **Multi-Block MEV Attacks**
```solidity
// Sandwich attacks on cross-chain transfers
1. Front-run: Manipulate token price on source chain
2. Victim tx: Cross-chain transfer executes
3. Back-run: Arbitrage on destination chain
```

### B. **Time-Dependent Vulnerabilities**
```solidity
// 6-hour epoch windows for mint limits
block.timestamp / 6 hours // Line 315, 828
```
- Timestamp manipulation near epoch boundaries
- Miner collusion for timestamp control
- Cross-epoch mint limit reset exploitation

### C. **Cross-Contract Reentrancy Chains**
```solidity
Gateway -> DepositHandler -> Token -> Gateway
```
- Complex reentrancy through token callbacks
- State inconsistency during nested calls
- Lock bypass through alternate entry points

### D. **Cryptographic Implementation Flaws**
```solidity
// ECDSA implementation (ECDSA.sol)
ecrecover(hash, v, r, s) // Line 63
```
- Signature malleability (high s values)
- Invalid signature acceptance
- Zero address recovery edge cases
- Ethereum signed message prefix bypass

## 🎯 CRITICAL CODE PATHS REQUIRING DEEP ANALYSIS

### 1. **Command Execution Flow**
```
execute(input) -> validateProof() -> commandSelector routing -> self.call() -> state changes
```
**Key Invariants to Break:**
- Command uniqueness (commandId)
- Operator set validity
- Chain ID verification
- Command type authorization

### 2. **Token Transfer Flow**
```
sendToken() -> _burnTokenFrom() -> [burn/lock] -> Event -> Validators -> execute() -> mintToken()
```
**Attack Surface:**
- Balance manipulation pre-burn
- Event emission tampering
- Validator consensus corruption
- Mint/burn asymmetry

### 3. **Contract Call Approval Flow**
```
approveContractCall() -> storage -> validateContractCall() -> execute -> clear approval
```
**Vulnerabilities:**
- Approval replay
- Storage key collision
- Validation race conditions
- Approval persistence bugs

### 4. **Deposit Address Generation**
```
CREATE2(salt, bytecode) -> DepositHandler -> execute() -> selfdestruct()
```
**Exploit Vectors:**
- Address prediction
- Deployment front-running
- Destruction race conditions
- Bytecode manipulation

## 🛠️ SPECIALIZED TESTING SCENARIOS

### 1. **Validator Set Transition Edge Cases**
- Commands submitted during operator rotation
- Overlapping epoch validation
- Threshold changes mid-execution
- Emergency operator updates

### 2. **Token Type Confusion**
- External tokens marked as Internal
- Deployment collision with existing tokens
- Symbol hijacking attacks
- Zero-address token handling

### 3. **Upgrade Path Vulnerabilities**
- Storage layout changes
- Initialization front-running
- Implementation contract direct calls
- Proxy fallback manipulation

### 4. **Cross-Chain Race Conditions**
- Simultaneous burns on multiple chains
- Conflicting commands from different chains
- Mint limit exhaustion races
- Approval consumption races

## 📊 HIGH-VALUE EXPLOIT SCENARIOS

### Scenario 1: **Validator Takeover**
```solidity
1. Exploit OLD_KEY_RETENTION window
2. Replay old operator set with known keys
3. Forge malicious commands
4. Drain all gateway-held tokens
```

### Scenario 2: **Mint Limit Bypass**
```solidity
1. Submit commands at epoch boundary
2. Exploit timestamp dependency
3. Double-mint across epoch transition
4. Exceed intended supply caps
```

### Scenario 3: **CREATE2 Front-run**
```solidity
1. Monitor mempool for deposit address generation
2. Pre-deploy malicious contract at predicted address
3. Intercept user deposits
4. Extract funds before legitimate deployment
```

### Scenario 4: **Upgrade Hijack**
```solidity
1. Exploit governance proposal mechanism
2. Deploy malicious implementation
3. Upgrade gateway to backdoored version
4. Full protocol control
```

## 🔐 INVARIANTS THAT MUST NEVER BREAK

1. **Conservation of Value**: `sum(burns) == sum(mints)` across all chains
2. **Command Uniqueness**: Each commandId executes exactly once
3. **Operator Authority**: Only current epoch operators can authorize commands
4. **Mint Limits**: Token mints never exceed configured limits per epoch
5. **Approval Atomicity**: Contract call approvals are consumed exactly once
6. **Token Isolation**: External tokens never gain mint/burn capabilities
7. **Upgrade Authorization**: Only governance can upgrade implementation
8. **Deposit Address Uniqueness**: Each salt generates unique deposit address

## 🎲 PROBABILISTIC ATTACK VECTORS

### 1. **Birthday Attack on Command IDs**
- Probability of collision with 2^256 space
- Potential for command replay

### 2. **Signature Grinding**
- Malicious validators generating specific r,s values
- Bypassing signature verification

### 3. **Salt Enumeration**
- Brute-force salt values for favorable addresses
- Address grinding for vanity exploits

## 🚀 IMMEDIATE HIGH-PRIORITY TARGETS

1. **Line 528 AxelarGateway.sol**: Self-call reentrancy vector
2. **Line 272 AxelarGateway.sol**: State change before external call
3. **Line 435 AxelarGateway.sol**: Unvalidated delegatecall
4. **Line 615 AxelarGateway.sol**: CREATE2 deployment race
5. **Line 29 DepositHandler.sol**: Selfdestruct timing
6. **Line 40 AxelarAuthWeighted.sol**: Epoch validation window
7. **Line 105 AxelarAuthWeighted.sol**: Signature weight accumulation
8. **Line 825 AxelarGateway.sol**: Mint limit check timing

## 🔥 FINAL AUDITOR NOTES

**Remember**: The most devastating vulnerabilities in cross-chain protocols arise from:
1. **Trust assumption violations** between chains
2. **Timing dependencies** in distributed systems
3. **State synchronization failures** across validators
4. **Cryptographic implementation subtleties**
5. **Economic incentive misalignment**

**Your mission**: Find the path to steal funds, lock funds permanently, or compromise the entire protocol. The bugs are there - they always are in complex cross-chain systems. Hunt with the mindset that every external call is hostile, every signature can be forged, every timestamp can be manipulated, and every assumption will be violated.

**Focus Areas by Impact**:
- 🔴 **CRITICAL**: Validator bypass, mint/burn auth, fund theft
- 🟠 **HIGH**: Governance takeover, DoS, reentrancy
- 🟡 **MEDIUM**: Front-running, griefing, state corruption

The protocol's complexity is its weakness. Every interaction between components is a potential exploit. Every trust boundary is a target. Every state transition is an opportunity.

**Hunt. Break. Exploit. Protect.**