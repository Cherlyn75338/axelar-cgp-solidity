Axelar Gateway Invariants (math and storage)

Global
- Supply conservation across chains: every destination mint corresponds to an origin burn/lock, after normalization. Global wrapped supply plus locked origin equals tracked canonical supply.
- Normalization correctness: normalization uses factor 10^(dstDec - srcDec); rounding policy is explicit; no overflow/underflow; dust either retained or bounded.
- Cap safety: for each wrapped token `totalSupply <= cap` always; cap updates cannot reduce below current `totalSupply`.
- Quorum/threshold: signatures are deduped; sum of weights ≥ threshold; domain separation binds chainId, gateway address, batch content.
- Uniqueness: each `commandId` consumed once; approval keys bind exact (sourceChain, sourceAddress, contractAddress, payloadHash[, symbol, amount]).
- Temporal monotonicity: validator epochs strictly increase; old sets cannot approve new messages; nonces and per-epoch mints are monotonic and atomic.
- Fee accounting: fee treasuries never negative; refunds ≤ collected; rounding cannot drain.

Gateway specifics
- `isCommandExecuted[commandId]` flips to true before execution and reverts to false on failure; cannot be double-executed.
- `validateContractCall*` mark-used before external callbacks and mint, preventing reentrancy-based double spend.
- Storage key derivations use `abi.encode` when tuple-ambiguous; no collisions between prefixes.

AuthWeighted
- Operators sorted strictly ascending and non-zero; no duplicates.
- Total weight is uint256 sum; threshold in (0, totalWeight].
- `validateProof` accepts only epochs within retention window and validates signatures with malleability protections.

Deposit service/receivers
- CREATE2 address derivation includes constructor args (delegateData, refundAddress) and salt; no collisions across intents.
- IWETH9 unwraps are ordered to prevent reentrancy; refundToken lifecycle is single-tx and cleared.

Libraries
- ECDSA enforces low-s and v in {27,28}; recover never returns zero on success.

Properties to test (Foundry/Echidna)
- P1: No mint without valid quorum on exact domain-separated digest (mocked to isolate math, and full-signature path in integration tests).
- P2: `totalSupply <= cap` invariant.
- P3: Single-consumption of approvals mapping keys.
- P4: Normalized supply conservation across multi-chain simulator.
- P5: Validator set updates require quorum of prior set; epochs strictly increase.
- P6: Fee/refund balances never negative.
- P7: Nonces strictly monotonic; no wrap.

