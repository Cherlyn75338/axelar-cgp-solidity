Title: High — Old operator sets can authorize state-changing commands during retention window

Severity: Critical impact potential (Unauthorized mint/transfer; Insolvency; Direct theft) contingent on compromised old keys within retention

Components Affected
- contracts/auth/AxelarAuthWeighted.sol (operator set retention and validation)
- contracts/AxelarGateway.sol (command execution policy)

Summary
AxelarAuthWeighted.validateProof accepts signatures from any of the last 16 epochs (OLD_KEY_RETENTION). It returns a boolean indicating whether the provided operators are the current epoch, but only reverts if the operators are unknown or older than the retention window. AxelarGateway.execute uses this boolean strictly to gate transferOperatorship; all other state-changing commands (deployToken, mintToken, approveContractCall, approveContractCallWithMint, burnToken) proceed as long as signatures meet threshold—even if they are from a non-current (but retained) operator set. If an old epoch is compromised but remains within the retention window, attackers can authorize state changes.

Root Cause
- validateProof enforces only that the operators exist and are not older than OLD_KEY_RETENTION; it does not require current-epoch for general authorization.
- execute only enforces current-epoch signatures for transferOperatorship. Sensitive commands lack an isCurrentEpoch requirement.

Line-by-line Evidence
```30:45:contracts/auth/AxelarAuthWeighted.sol
if (operatorsEpoch == 0 || epoch - operatorsEpoch >= OLD_KEY_RETENTION) revert InvalidOperators();
_validateSignatures(messageHash, operators, weights, threshold, signatures);
return operatorsEpoch == epoch;
```

```504:519:contracts/AxelarGateway.sol
if (commandHash == SELECTOR_DEPLOY_TOKEN) {
    commandSelector = AxelarGateway.deployToken.selector;
} else if (commandHash == SELECTOR_MINT_TOKEN) {
    commandSelector = AxelarGateway.mintToken.selector;
} else if (commandHash == SELECTOR_APPROVE_CONTRACT_CALL) {
    commandSelector = AxelarGateway.approveContractCall.selector;
} else if (commandHash == SELECTOR_APPROVE_CONTRACT_CALL_WITH_MINT) {
    commandSelector = AxelarGateway.approveContractCallWithMint.selector;
} else if (commandHash == SELECTOR_BURN_TOKEN) {
    commandSelector = AxelarGateway.burnToken.selector;
} else if (commandHash == SELECTOR_TRANSFER_OPERATORSHIP) {
    if (!allowOperatorshipTransfer) continue;
    allowOperatorshipTransfer = false;
    commandSelector = AxelarGateway.transferOperatorship.selector;
}
```

Why This Is a Vulnerability
- If old operators are compromised (or partially compromised) but remain within retention (for liveness/reorg tolerance), they can authorize arbitrary state-changing commands aside from transferOperatorship. This includes mintToken and approveContractCallWithMint, enabling token issuance or transfer from escrow.
- Mint caps per 6-hour window limit the amount per symbol but still allow unauthorized issuance within caps and across windows. External token handling for mintToken performs a safeTransfer from the gateway escrow, enabling direct theft of escrowed funds.

Realistic Exploit Scenarios (Mainnet)
1) Post-rotation residual authority
   - Preconditions: Current epoch E is active; epoch E-1 keys are partially compromised but still within retention (E - (E-1) < 16). Governance rotated to E to mitigate risk.
   - Attack: Attackers with E-1 threshold sign a batch containing mintToken or approveContractCallWithMint. A relayer submits execute; validateProof passes (operators within retention), allowOperatorshipTransfer is false (not current-epoch), but execute processes mint/approve commands anyway.

2) Combined with cross-deployment replay (if present)
   - Preconditions: As above, plus a fresh proxy (new gateway) deployed with same authModule.
   - Attack: Old-epoch signed batches can be replayed onto the new proxy as well, multiplying impact.

Expanded Impact
- Unauthorized mint/transfer of wrapped assets; for external tokens, direct transfer out of gateway escrow.
- Bridging insolvency: wrapped token supply exceeds collateral.
- Repeated approval of contract calls with token, enabling repeated mints upon validateContractCallAndMint if approvals are distinct.

Proof-of-Concept (PoC) / Validation Steps
Environment
- Local testnet; ability to rotate operatorship.

Steps
1) Deploy AxelarAuthWeighted with two consecutive operator sets: E-1 and E
   - Initialize with recentOperators including E-1 (epoch 1) and E (epoch 2). currentEpoch becomes 2.

2) Deploy AxelarGateway (proxy) using the authModule from step 1
   - Complete setup.

3) Prepare a signed batch using E-1 operators (not current, but within retention)
   - Construct data for a mintToken(symbol, attacker, amount) command with valid params.
   - Sign with E-1 operators meeting threshold.

4) Submit execute(abi.encode(data, proof_E_minus_1))
   - Expected: validateProof returns false (not current) but does NOT revert; allowOperatorshipTransfer=false; execute still processes mintToken path.
   - Observe tokens minted/transferred as per token type.

What Would Prevent the PoC
- If execute required current-epoch signatures for state-changing commands (i.e., checked isCurrentEpoch for all such commands), the batch would be skipped or reverted.

Mitigations (Primary)
1) Require current-epoch signatures for state-changing commands
   - In execute, if !isCurrentEpoch (allowOperatorshipTransfer == false), then only accept non-state-changing or explicitly permitted commands; otherwise skip/revert deployToken, mintToken, approveContractCall*, burnToken.

2) Alternatively, include operatorsEpoch in signed payload and enforce equality to currentEpoch for sensitive commands
   - This supports explicit on-chain policy and can be audited via events.

Defense-in-Depth
- Emergency switch: governance-controlled flag to reject non-current epochs entirely during incidents.
- Reduce OLD_KEY_RETENTION or make it command-specific (retention for read-only or liveness-only actions).
- Monitoring: detect any execute batches where operatorsEpoch != currentEpoch and command type is state-changing.

Potential Bypasses and How Mitigations Address Them
- Splitting mints across time buckets: Still blocked if signatures must be current-epoch; old-epoch signatures are invalid for sensitive commands regardless of timing.
- Cross-deployment replay: Independent risk; addressed by binding signatures to verifying contract in the separate mitigation.

Test Additions
- Unit: After rotation, attempt mint/approve with old-epoch proof; assert rejection once current-epoch requirement is enforced.
- Fuzz: Randomize epoch gaps from 1..15 and ensure state-changing commands only accept current-epoch.

References
- contracts/auth/AxelarAuthWeighted.sol validateProof: 30–45
- contracts/AxelarGateway.sol execute: 504–519