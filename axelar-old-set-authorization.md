## Brief/Intro
A critical authorization flaw in Axelar’s gateway allows any retained (non-current) validator set within `OLD_KEY_RETENTION` to authorize and execute new state-changing command batches on-chain (e.g., `deployToken`, `mintToken`, `approveContractCall`, `approveContractCallWithMint`, `burnToken`). Only `transferOperatorship` is gated to the current epoch. This enables unauthorized minting or transfer of assets and can render the bridge insolvent if exploited in production/mainnet.

## Vulnerability Details
The Axelar validator authorization module (`AxelarAuthWeighted`) validates signatures from any operator set whose epoch is within a configured retention window. It returns a boolean that indicates whether the provided operators correspond to the current epoch, but it does not revert for retained-yet-non-current epochs. The gateway (`AxelarGateway.execute`) then uses that boolean exclusively to allow or skip `transferOperatorship` while proceeding with all other commands if `validateProof` does not revert.

Key code paths and behaviors:

- Validation accepts retained (but not current) operator sets and returns whether the set is current epoch:
```31:45:contracts/auth/AxelarAuthWeighted.sol
function validateProof(bytes32 messageHash, bytes calldata proof) external view returns (bool) {
    (address[] memory operators, uint256[] memory weights, uint256 threshold, bytes[] memory signatures) = abi.decode(
        proof, (address[], uint256[], uint256, bytes[])
    );
    bytes32 operatorsHash = keccak256(abi.encode(operators, weights, threshold));
    uint256 operatorsEpoch = epochForHash[operatorsHash];
    uint256 epoch = currentEpoch;
    if (operatorsEpoch == 0 || epoch - operatorsEpoch >= OLD_KEY_RETENTION) revert InvalidOperators();
    _validateSignatures(messageHash, operators, weights, threshold, signatures);
    return operatorsEpoch == epoch; // true only for current epoch
}
```

- The gateway only uses the boolean to decide if `transferOperatorship` is allowed; all other commands execute if `validateProof` does not revert:
```476:481:contracts/AxelarGateway.sol
bool allowOperatorshipTransfer = IAxelarAuth(authModule).validateProof(messageHash, proof);
```

```500:523:contracts/AxelarGateway.sol
            bytes4 commandSelector;
            bytes32 commandHash = keccak256(abi.encodePacked(commands[i]));
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
            } else {
                // Ignore unknown commands
                continue;
            }
```

- Execute pre-marking and rollback on failure (good hygiene but not relevant to authorization scope):
```524:533:contracts/AxelarGateway.sol
            _setCommandExecuted(commandId, true);
            (bool success, ) = address(this).call(abi.encodeWithSelector(commandSelector, params[i], commandId));
            if (success) emit Executed(commandId);
            else _setCommandExecuted(commandId, false);
```

What is signed and why the current-epoch binding is missing
- The signed message `messageHash` hashes the `data` batch (which includes `chainId`, `commandIds`, `commands`, and encoded `params`), but it does not include or otherwise bind to the `currentEpoch` or a key-id unique to the active operatorship.
- Consequently, a retained-but-not-current operator set can sign a fresh batch and pass `validateProof` so long as it remains within `OLD_KEY_RETENTION`. The boolean returned (`false` for non-current) is checked only for `transferOperatorship`; other sensitive commands execute regardless.

Root cause
- Signed batch domain is not bound to the current validator set epoch/key-id.
- `AxelarGateway.execute` uses `isCurrentEpoch` exclusively to gate `transferOperatorship`. Other state-changing commands are not restricted to the current epoch.
- Reliance on `OLD_KEY_RETENTION` for liveness does not prevent retained sets from originating new non-operatorship commands.

Why this is a vulnerability
- During the retention window, any prior epoch with an intact quorum can authorize new batches that the gateway will process for all non-operatorship commands, including `mintToken` and `approveContractCallWithMint`.
- No key compromise is necessary for exploitation; it is sufficient for the old set’s quorum to collude or mistakenly sign a new batch. If an old set is compromised (partially or fully), the risk escalates to direct theft and insolvency.

Preconditions for exploitation
- A previous operator set remains within `OLD_KEY_RETENTION` of the current epoch.
- The previous set’s quorum agrees to sign a new batch or is compromised.
- A relayer submits `execute(data, proof)` containing the old set’s signatures.

Non-impacted areas (in this context)
- Duplicate signature counting and sorted-operator enforcement are correctly implemented.
- ECDSA malleability constraints are enforced.
- `transferOperatorship` is correctly limited to the current epoch via the boolean gate.

Recommended remediation (design-level)
- Bind signatures to the current epoch/key-id by including `currentEpoch` (or equivalent key-id) in the signed `data`, and require `operatorsEpoch == currentEpoch` for all sensitive commands.
- Alternatively (or additionally), enforce `isCurrentEpoch == true` in `execute` for all state-changing commands; skip or revert otherwise.
- Operationally, reduce `OLD_KEY_RETENTION` where possible and monitor for batches where `operatorsEpoch != currentEpoch`.

## Impact Details
- Unauthorized mint/transfer
  - Internal tokens: `mintToken` can mint wrapped assets to attacker-controlled accounts, breaking peg and enabling liquidation.
  - External tokens: the `_mintToken` path for `TokenType.External` executes a `safeTransfer` from gateway custody, enabling direct draining of escrowed funds to attacker addresses.
- Insolvency risk
  - Wrapped supply can exceed collateral if unauthorized mints occur, creating redemption shortfalls and user losses.
- Invalid command execution by non-current set
  - Governance and authorization assumptions are violated; a non-current validator set executes commands during the retention window.
- Repeatability across time windows
  - Even with per-symbol mint caps, the attack can be repeated across time buckets and symbols, compounding losses.

These losses map to critical, user-facing financial impact: unauthorized issuance, asset theft from escrow, and systemic insolvency.

## References
- `contracts/auth/AxelarAuthWeighted.sol` — `validateProof`, `epochForHash`, `currentEpoch`, `OLD_KEY_RETENTION` usage
- `contracts/AxelarGateway.sol` — `execute`, command selector resolution, `transferOperatorship` gating
- Code citations included inline above for clarity

## Proof of Concept
The vulnerability can be validated locally (unit test) or on a fork with real operator sets.

High-level steps (applies to both local and fork):
1) Let epoch `E` be current and epoch `E-1` be within `OLD_KEY_RETENTION`.
2) Construct a fresh batch `data` containing a sensitive command (e.g., `mintToken(symbol, beneficiary, amount)`) with a fresh `commandId`.
3) Have operators from epoch `E-1` sign `messageHash = ECDSA.toEthSignedMessageHash(keccak256(data))` and build `proof = abi.encode(operatorsEminus1, weightsEminus1, thresholdEminus1, signaturesEminus1)`.
4) Call `AxelarGateway.execute(abi.encode(data, proof))`.
5) Observe: `validateProof` does not revert and returns `false` (not current). `execute` processes non-operatorship commands; `transferOperatorship` (if present) is skipped. `Executed(commandId)` is emitted; balances change accordingly for `mintToken`.

Foundry-style unit test (illustrative)
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// import {AxelarGateway} from "contracts/AxelarGateway.sol";
// import {AxelarAuthWeighted} from "contracts/auth/AxelarAuthWeighted.sol";

contract OldSetAuthorizationTest is Test {
    using ECDSA for bytes32;

    // Addresses for testing; replace with deployed instances in your repo
    address gateway;
    address auth;

    // Epoch operator fixtures (replace with your setup logic)
    address[] operatorsEminus1;
    uint256[] weightsEminus1;
    uint256 thresholdEminus1;

    function setUp() public {
        // 1) Deploy auth and gateway, initialize two consecutive epochs: E-1, then rotate to E
        //    Ensure E-1 remains within OLD_KEY_RETENTION.
        // auth = address(new AxelarAuthWeighted(/* constructor args */));
        // gateway = address(new AxelarGateway(/* constructor args incl. auth */));
        // configureOperatorsForEpoch(E-1, operatorsEminus1, weightsEminus1, thresholdEminus1);
        // rotateToEpochE(); // sets currentEpoch = E
    }

    function test_OldSetCanExecuteNonOperatorshipCommands() public {
        // 2) Prepare a batch with a mintToken command
        bytes32[] memory commandIds = new bytes32[](1);
        commandIds[0] = keccak256(abi.encodePacked("cmd-1", address(this)));
        string[] memory commands = new string[](1);
        commands[0] = "mintToken";
        bytes[] memory params = new bytes[](1);
        // params[0] should encode (symbol, beneficiary, amount)
        params[0] = abi.encode("wTEST", address(0xBEEF), uint256(1000 ether));

        bytes memory data = abi.encode(block.chainid, commandIds, commands, params);
        bytes32 msgHash = keccak256(data).toEthSignedMessageHash();

        // 3) Produce signatures from epoch E-1
        bytes[] memory signaturesEminus1 = new bytes[](/* quorum signatures */);
        // signaturesEminus1[i] = signWithOperatorEminus1PrivateKey(msgHash);

        bytes memory proof = abi.encode(operatorsEminus1, weightsEminus1, thresholdEminus1, signaturesEminus1);

        // 4) Execute with old-epoch proof
        (bool ok, ) = gateway.call(abi.encodeWithSignature("execute(bytes)", abi.encode(data, proof)));
        require(ok, "execute reverted unexpectedly");

        // 5) Assert: mint executed (observe token balance or Executed event)
        // assertEq(ERC20Like(wTEST).balanceOf(address(0xBEEF)), 1000 ether);
    }
}
```

Manual validation on a fork
1) Identify current epoch `E` and previous epoch `E-1` in `AxelarAuthWeighted` from on-chain state/events; confirm `E-1` is within `OLD_KEY_RETENTION`.
2) Build a batch `data = abi.encode(block.chainid, commandIds, commands, params)` containing `mintToken` (or `approveContractCallWithMint`) with a fresh `commandId`.
3) Collect signatures from the `E-1` operators meeting the threshold; form `proof = abi.encode(operatorsEminus1, weightsEminus1, thresholdEminus1, signaturesEminus1)`.
4) Submit `AxelarGateway.execute(abi.encode(data, proof))` via a relayer or directly.
5) Observe the transaction: `validateProof` returns `false` (not current) but does not revert; `transferOperatorship` (if present) is skipped; all other commands run and emit `Executed(commandId)`. For `mintToken`, verify the beneficiary’s balance increases or escrow transfer occurs for external tokens.

What would prevent the PoC
- If the signed domain is bound to the current epoch/key-id and `execute` enforces `operatorsEpoch == currentEpoch` for sensitive commands, submissions with old-epoch signatures will revert or be skipped, blocking the attack.