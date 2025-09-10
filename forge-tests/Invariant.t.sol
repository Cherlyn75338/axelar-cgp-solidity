// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import { Test, console2 } from 'forge-std/Test.sol';

import { AxelarGateway } from '../contracts/AxelarGateway.sol';
import { AxelarAuthWeighted } from '../contracts/auth/AxelarAuthWeighted.sol';
import { TokenDeployer } from '../contracts/TokenDeployer.sol';
import { IBurnableMintableCappedERC20 } from '../contracts/interfaces/IBurnableMintableCappedERC20.sol';
import { ECDSA } from '../contracts/ECDSA.sol';

contract InvariantTest is Test {
    AxelarGateway gateway;
    AxelarAuthWeighted auth;
    TokenDeployer deployer;

    uint256 internal operatorSk;
    address internal operatorAddr;

    function setUp() public {
        // Initialize minimal auth with a single operator of weight 1 and threshold 1
        operatorSk = 0xA11CE;
        operatorAddr = vm.addr(operatorSk);

        address[] memory ops = new address[](1);
        ops[0] = operatorAddr;
        uint256[] memory w = new uint256[](1);
        w[0] = 1;
        bytes memory params = abi.encode(ops, w, uint256(1));
        bytes[] memory recents = new bytes[](1);
        recents[0] = params;
        auth = new AxelarAuthWeighted(recents);
        deployer = new TokenDeployer();
        gateway = new AxelarGateway(address(auth), address(deployer));
    }

    function sign(bytes32 messageHash) internal view returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorSk, messageHash);
        sig = abi.encodePacked(r, s, v);
    }

    function buildProof(bytes32 messageHash) internal view returns (bytes memory proof) {
        address[] memory ops = new address[](1);
        ops[0] = operatorAddr;
        uint256[] memory w = new uint256[](1);
        w[0] = 1;
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = sign(messageHash);
        proof = abi.encode(ops, w, uint256(1), sigs);
    }

    function exec(bytes memory data) internal returns (bool ok) {
        bytes32 msgHash = ECDSA.toEthSignedMessageHash(keccak256(data));
        bytes memory proof = buildProof(msgHash);
        (ok, ) = address(gateway).call(abi.encodeWithSelector(AxelarGateway.execute.selector, abi.encode(data, proof)));
    }

    function test_mint_does_not_exceed_cap() public {
        string memory name = 'Token';
        string memory symbol = 'TKN';
        uint8 decs = 18;
        uint256 cap = 1_000_000 ether;
        bytes memory deployParams = abi.encode(name, symbol, decs, cap, address(0), uint256(0));

        uint256 chainId = block.chainid;
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = keccak256('cmd-deploy');
        string[] memory cmds = new string[](1);
        cmds[0] = 'deployToken';
        bytes[] memory params = new bytes[](1);
        params[0] = deployParams;
        bool ok = exec(abi.encode(chainId, ids, cmds, params));
        require(ok, 'deployToken failed');

        address token = gateway.tokenAddresses(symbol);
        IBurnableMintableCappedERC20 t = IBurnableMintableCappedERC20(token);

        // Mint up to cap
        ids = new bytes32[](1);
        ids[0] = keccak256('cmd-mint-1');
        cmds = new string[](1);
        cmds[0] = 'mintToken';
        params = new bytes[](1);
        params[0] = abi.encode(symbol, address(this), cap);
        ok = exec(abi.encode(chainId, ids, cmds, params));
        require(ok, 'mintToken failed at cap');

        // Next mint should fail internally but execute() should not revert; verify cap holds
        ids[0] = keccak256('cmd-mint-2');
        params[0] = abi.encode(symbol, address(this), 1);
        exec(abi.encode(chainId, ids, cmds, params));
        assertLe(t.totalSupply(), t.cap(), 'totalSupply must be <= cap');
    }
}

