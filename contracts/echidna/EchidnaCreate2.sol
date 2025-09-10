// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import { AxelarDepositService } from '../deposit-service/AxelarDepositService.sol';

// Minimal gateway-like mock exposing tokenAddresses behavior that DepositService reads.
contract GatewayMock {
    function tokenAddresses(string memory) public pure returns (address) { return address(0x1234); }
}

// Invariant: CREATE2 addresses differ when intents differ
contract EchidnaCreate2Uniqueness {
    AxelarDepositService public ds;
    mapping(address => bytes32) private addressToDomain;

    constructor() {
        ds = new AxelarDepositService(address(new GatewayMock()), 'WETH', msg.sender);
    }

    // Action: record a deposit address and assert domain separation if a collision occurs
    function action_record(bytes32 salt, address refund, string calldata chain, string calldata dst, string calldata sym) external {
        bytes32 domain = keccak256(abi.encode(chain, dst, sym));
        address a = ds.addressForTokenDeposit(salt, refund, chain, dst, sym);
        bytes32 prev = addressToDomain[a];
        if (prev == bytes32(0)) {
            addressToDomain[a] = domain;
        } else {
            // If we collide to same address, domains must match
            assert(prev == domain);
        }
    }
}

