Title: High — Signatures not bound to gateway address (cross-deployment replay)

Severity: Critical impact potential (Privilege escalation; Unauthorized mint/transfer; Insolvency; Direct theft)

Components Affected
- contracts/AxelarGateway.sol (command processing and proof verification)
- contracts/auth/AxelarAuthWeighted.sol (signature validation policy)
- contracts/ECDSA.sol (signature malleability checks)
- Proxy and upgrade path: contracts/AxelarGatewayProxy.sol

Summary
The Axelar Gateway accepts validator-signed batches via execute(bytes). The signed data includes the chainId but not the verifying contract address (address(this)) or an equivalent domain discriminator. If two gateway deployments exist on the same chain using the same authModule (operator set) and command stream, the same signed batch can be valid for both deployments. Because command replay prevention is stored per deployment, a batch executed on deployment A can be re-executed on deployment B, enabling unauthorized state changes (e.g., minting tokens or approving GMP calls) on B.

Root Cause
- Domain separation for signed batches omits the verifying contract address. The signed message is toEthSignedMessageHash(keccak256(data)) where data contains chainId and batch contents but not address(this).
- Replay prevention is tracked per-deployment via isCommandExecuted(commandId) in EternalStorage, so a fresh deployment has an empty executed set.

Line-by-line Evidence
```472:489:contracts/AxelarGateway.sol
(bytes memory data, bytes memory proof) = abi.decode(input, (bytes, bytes));
bytes32 messageHash = ECDSA.toEthSignedMessageHash(keccak256(data));
bool allowOperatorshipTransfer = IAxelarAuth(authModule).validateProof(messageHash, proof);
...
(chainId, commandIds, commands, params) = abi.decode(data, (uint256, bytes32[], string[], bytes[]));
if (chainId != block.chainid) revert InvalidChainId();
```

The proof covers only keccak256(data) wrapped by EIP-191; address(this) is never included in data.

```355:357:contracts/AxelarGateway.sol
function isCommandExecuted(bytes32 commandId) public view override returns (bool) {
    return getBool(_getIsCommandExecutedKey(commandId));
}
```

Executed tracking is local to deployment storage; a new proxy starts empty.

Signature policy is standard (non-malleable) but does not add domain binding:
```31:64:contracts/ECDSA.sol
// lower-half s and v in {27,28}
```

Upgrade path verifies implementation identity but not signature domain:
```420:439:contracts/AxelarGateway.sol
if (newImplementationCodeHash != newImplementation.codehash) revert InvalidCodeHash();
if (contractId() != IContractIdentifier(newImplementation).contractId()) revert InvalidImplementation();
... delegatecall(setup)
```

Why This Is a Vulnerability
- Without binding to address(this), the same signed batch is valid for any contract on the same chain that shares the same authModule and understands the same batch encoding. If a second gateway (proxy) is deployed—accidentally, for migration, or for testing—and it points to the same authModule, any batch intended for A can be replayed on B, as long as B has not marked those commandIds executed.
- Because many commands trigger sensitive state changes (deployToken, mintToken, approveContractCallWithMint, burnToken), re-executing them on B can produce unauthorized mints, transfers of escrowed external tokens, or re-approvals.

Realistic Exploit Scenarios (Mainnet)
1) Parallel Deployment Replay
   - Preconditions: Gateway A (canonical) and a mistakenly deployed Gateway B exist on the same chain. Both use the same authModule and token registry. B has fresh storage.
   - Attack: Relayer or attacker resubmits a previously executed, validator-signed execute batch to B. Since signatures are valid for chainId and not contract address, B accepts. If commands include mintToken(symbol, attacker, amount) or approveContractCallWithMint to attacker-controlled destination, B repeats the mint/transfer.

2) Migration to Fresh Proxy
   - Preconditions: Governance migrates to a new proxy with the same implementation and authModule, but storage is fresh (executed map empty).
   - Attack: Re-submit old batches to the new proxy. Same outcomes as above until governance realizes and halts.

Expanded Impact
- Privilege escalation across deployments: Attackers can cause state transitions on B without any new validator authorization.
- Unauthorized mint/transfer: Internal tokens minted again on B; external token escrow at B can be drained via mintToken (which uses safeTransfer for external type).
- Insolvency: Additional wrapped supply minted without corresponding locked/burned collateral; external escrow drained.

Proof-of-Concept (PoC) / Validation Steps
Environment
- Use the repo’s tests and a local Hardhat/Foundry environment.

Steps
1) Deploy Auth and TokenDeployer
   - Deploy AxelarAuthWeighted with a current operator set.
   - Deploy TokenDeployer.

2) Deploy Gateway A (proxy)
   - Deploy AxelarGateway implementation with addresses of Auth and TokenDeployer.
   - Deploy AxelarGatewayProxy pointed at implementation; call setup with governance, mintLimiter, and operatorship.

3) Deploy Gateway B (proxy)
   - Repeat step 2, but as a separate proxy that uses the SAME authModule.
   - Do NOT copy storage (executed flags empty on B).

4) Prepare a valid signed batch (chainId = block.chainid)
   - Build data = abi.encode(chainId, [cmdIds], [commands], [params]).
   - Have the current operators sign ECDSA to produce proof for messageHash = toEthSignedMessageHash(keccak256(data)).

5) Submit to Gateway A: gatewayA.execute(abi.encode(data, proof))
   - Observe effects (e.g., mintToken on an internal token to a known account, or approveContractCallWithMint).
   - commandId i marked executed in A storage.

6) Replay to Gateway B: gatewayB.execute(abi.encode(data, proof))
   - Expected: Succeeds. Effects repeat on B because signatures validate and B’s executed set is empty.
   - If commands include mintToken(symbol, attacker, amount), attacker receives tokens from B’s perspective; for external tokens, safeTransfer sends escrowed tokens held by B.

What Would Prevent the PoC
- If signatures included address(this) (or full EIP-712 domain including verifyingContract), the same proof would be invalid for B and the call would revert.

Mitigations (Primary)
1) Bind signatures to verifying contract
   - Move to EIP-712 typed data: Domain(name = "axelar-gateway", version, chainId, verifyingContract = address(this)).
   - Sign a struct that includes command batch fields; verify on-chain with EIP-712.
   - Alternatively, keep EIP-191 and include address(this) inside the hashed data.

2) Deployment nonce/domain version
   - Include a deploymentNonce or contractVersion in the signed payload. Increment when migrating to a new proxy.

Defense-in-Depth
- Operational controls: enforce single canonical proxy; forbid fresh-proxy migrations without state carry-over; run canary replay tests during migration to assert rejection.
- Monitoring: detect duplicate commandIds executed by more than one gateway address on the same chain.

Potential Bypasses and How Mitigations Address Them
- Using the same authModule on B: EIP-712 verifyingContract makes signatures specific to A; B’s verification fails.
- Fresh storage on B: Deployment nonce in signatures ensures old batches are not accepted by B unless nonce matches, which it won’t.

Test Additions
- Unit: Spawn two proxies with same auth. Prove that prior to the fix, replay on B succeeds; after the fix, B rejects because verifyingContract differs.
- Invariant: For a fixed signed batch, only one verifying contract on a chain can accept it.

References
- contracts/AxelarGateway.sol execute: 472–489, 495–533
- contracts/auth/AxelarAuthWeighted.sol validateProof: 30–45
- contracts/ECDSA.sol: 31–64
- contracts/AxelarGatewayProxy.sol (proxy storage and setup)