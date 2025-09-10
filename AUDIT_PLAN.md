Axelar Solidity Audit Plan (math-focused)

Scope
- Primary: `AxelarGateway`, `AxelarAuthWeighted`, `BurnableMintableCappedERC20`, `MintableCappedERC20`, `DepositHandler`, `AxelarDepositService` (+ `DepositReceiver`, `ReceiverImplementation`), gas service, proxies, libraries (`ECDSA`, `Safe{Transfer,NativeTransfer}`, `EternalStorage`).
- Interfaces/integrations: `IWETH9`, arbitrary ERC-20s (fee-on-transfer, rebasing, non-standard returns), Cosmos-side assumptions enforced on-chain (weights, thresholds, epochs).
- Impact focus: unauthorized mint/burn/transfer, insolvency, freezes, theft in-flight/at-rest, governance manipulation, privilege escalation.

Threat model (assets/trust/assumptions)
- Assets: locked canonical tokens, wrapped supplies, operator weights/threshold, command ids/nonces, fee treasuries.
- Trust boundaries: validator-signed command ingestion, chain-id/domain separation, callbacks to untrusted executables, token integrations, CREATE2 deposit receivers, gas accounting.
- Assumptions to validate: uniqueness and one-time execution of commands; authenticated, monotonic, atomic validator-set updates; normalization correctness across decimals; global cap/supply conservation.

Core invariants
- Supply conservation: locks+burns 1:1 with mints/unlocks after normalization; global cap respected.
- Normalization correctness: amount scaling by 10^(dst-dec) with explicit rounding policy and dust handling.
- Cap invariants: `totalSupply <= cap` always; cap updates cannot undercut `totalSupply`.
- Quorum security: deduped signatures; weight sum >= threshold with domain separation (includes chainId, gateway, function selector/batch hash).
- Uniqueness: command/message ids consumed exactly once; nonces monotonic; epochs strictly increase; no cross-epoch replay.
- Fee accounting: safe percentage math; dust retained in contract; refunds ≤ collected fees.
- Temporal: no rollback to old validator sets; window math consistent.

Module-focused checks
- AxelarGateway: signature aggregation math and duplicates; chainId binding; `execute` pre-mark then execute with revert rollback; correct key derivations; approval keys bind all fields (chain, addr, payloadHash, symbol, amount).
- AuthWeighted: sorted unique operators; weight summation in uint256; threshold bounds; OLD_KEY_RETENTION; signature recovery low-s and v in {27,28}; duplicate signer prevention.
- BurnableMintableCappedERC20/MintableCappedERC20: cap math vs decimals; owner-only mint/burn; CREATE2 depositAddress correctness and domain separation; burnFrom allowance math.
- Deposit service/receivers: CREATE2 salts, constructor params in address derivation; IWETH9 unwrap ordering; reentrancy guards; refundToken state; single-use receiver lifecycle.
- Libraries/storage: ECDSA malleability checks; abi.encode vs encodePacked consistency in keys; EternalStorage key domains.

Math review checklist
- Decimals/scaling: multiply before divide overflow; SafeCast on downcasts; precomputed powers of ten; normalization on all cross-chain paths.
- Rounding: document direction; bound cumulative rounding extraction; dust retention.
- Caps/limits: same decimals; no cap < totalSupply; handle external/fee-on-transfer tokens.
- Weights/thresholds: sum in uint256; dedupe; ordering; consistent ≥ logic.
- Nonces/batching: batch hash binds exact ordered list; atomic increments; epoch reset safety.
- Rate limits: sliding windows off-by-one; timestamp math.
- Gas/fees: safe percentages; min/max; refund ≤ collected.
- CREATE2: salt covers token, amount, dst, refund; keccak inputs include constructor args.

Adversarial scenarios
- Decimals mismatch fuzzer (6..27 decs), random amounts, end-to-end 1:1 conservation.
- Rounding-drain: many small transfers to maximize dust; assert bound B.
- Threshold edge: sum == T and T-1, duplicates, permutations; signer mismatch.
- Replay/nonce: reorder/duplicate batches; cross-epoch replay; revert-and-retry.
- Rate limit/window: t, t+window-1, t+window boundaries.
- Fee-on-transfer: approve N, receive N-ε; under/over-mint detection.
- Reentrancy: executable -> gateway; deposit receiver -> token hooks; IWETH9 withdraw callbacks.
- CREATE2 collisions: salt crafting; domain separation validation.

Property/invariant testing
- Tools: Foundry invariants/fuzz, Echidna, Slither; optional Halmos/Medusa; Scribble annotations for key properties.
- Properties: P1 no mint without valid quorum; P2 `totalSupply <= cap`; P3 single-consumption of approvals; P4 normalized supply conservation within bound; P5 validator-set update requires quorum on prior set; P6 fee balances never negative; P7 nonces monotonic.

Deliverables
- Short report of critical/high issues with PoCs; `INVARIANTS.md`; Foundry/Echidna test suite; hardening recommendations; optional Scribble specs.

