// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import { AxelarGateway } from '../AxelarGateway.sol';
import { TokenDeployer } from '../TokenDeployer.sol';
import { IBurnableMintableCappedERC20 } from '../interfaces/IBurnableMintableCappedERC20.sol';
import { IAxelarAuth } from '../interfaces/IAxelarAuth.sol';
import { ECDSA } from '../ECDSA.sol';

contract EchidnaAuthMock2 is IAxelarAuth {
    address private _owner;
    address private _pendingOwner;

    constructor() {
        _owner = msg.sender;
    }

    function validateProof(bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }

    function transferOperatorship(bytes calldata) external {}

    function owner() external view returns (address) { return _owner; }
    function pendingOwner() external view returns (address) { return _pendingOwner; }
    function proposeOwnership(address newOwner) external { _pendingOwner = newOwner; }
    function transferOwnership(address newOwner) external { _owner = newOwner; }
    function acceptOwnership() external { _owner = _pendingOwner; _pendingOwner = address(0); }
}

// Invariants on AxelarGateway: replay guard; approvals single-use; no double-mint on duplicate commandId.
contract EchidnaGatewayInvariants {
    AxelarGateway public gateway;
    TokenDeployer public deployer;
    IBurnableMintableCappedERC20 public token;
    string internal constant SYMBOL = 'TKN';
    
    // Tracking expected supply increases
    mapping(bytes32 => bool) private mintedById;
    uint256 private sumUniqueMinted;
    bytes32 private lastId;
    
    mapping(bytes32 => bool) private approvalUsed;
    uint256 private sumApprovalMinted;

    constructor() {
        EchidnaAuthMock2 auth = new EchidnaAuthMock2();
        deployer = new TokenDeployer();
        gateway = new AxelarGateway(address(auth), address(deployer));

        // Deploy internal token via execute
        string memory name = 'Token';
        uint8 decs = 18;
        uint256 cap = 10_000_000 ether;
        bytes memory deployParams = abi.encode(name, SYMBOL, decs, cap, address(0), uint256(0));
        uint256 chainId = block.chainid;
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = keccak256('cmd-deploy');
        string[] memory cmds = new string[](1);
        cmds[0] = 'deployToken';
        bytes[] memory params = new bytes[](1);
        params[0] = deployParams;
        _exec(abi.encode(chainId, ids, cmds, params));
        token = IBurnableMintableCappedERC20(gateway.tokenAddresses(SYMBOL));
    }

    function _sign(bytes32 messageHash) internal pure returns (bytes memory sig) {
        // EchidnaAuthMock validates all proofs. We can pass empty signatures.
        sig = bytes('');
    }

    function _exec(bytes memory data) internal returns (bool ok) {
        bytes32 msgHash = ECDSA.toEthSignedMessageHash(keccak256(data));
        bytes memory proof = _sign(msgHash);
        (ok, ) = address(gateway).call(abi.encodeWithSelector(AxelarGateway.execute.selector, abi.encode(data, proof)));
    }

    // Action: mint with a provided id and amount
    function mint(bytes32 id, uint256 amount) public {
        amount = (amount % 1e24) + 1;
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = id;
        string[] memory cmds = new string[](1);
        cmds[0] = 'mintToken';
        bytes[] memory params = new bytes[](1);
        params[0] = abi.encode(SYMBOL, address(this), amount);
        uint256 beforeSupply = token.totalSupply();
        _exec(abi.encode(block.chainid, ids, cmds, params));
        uint256 afterSupply = token.totalSupply();
        if (!mintedById[id] && afterSupply == beforeSupply + amount) {
            mintedById[id] = true;
            sumUniqueMinted += amount;
        }
        lastId = id;
    }
    
    // Action: replay last command id
    function replay() public {
        if (lastId == bytes32(0)) return;
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = lastId;
        string[] memory cmds = new string[](1);
        cmds[0] = 'mintToken';
        bytes[] memory params = new bytes[](1);
        // amount is ignored by gateway for id uniqueness; use 0 to avoid cap issues
        params[0] = abi.encode(SYMBOL, address(this), uint256(0));
        _exec(abi.encode(block.chainid, ids, cmds, params));
    }

    // Approvals with mint: valid exactly once per key; second validation must fail and not mint again.
    // Action: register approval and validate once (mint). Keyed by commandId+payloadHash+amount.
    function approveAndMint(bytes32 commandId, bytes32 payloadSalt, uint256 amt) public {
        uint256 amount = (amt % 1e24) + 1;
        bytes32 payloadHash = keccak256(abi.encodePacked('payload', payloadSalt));
        bytes memory enc = abi.encode('src','0xabc',address(this),payloadHash,SYMBOL,amount,bytes32(0),uint256(0));
        string[] memory cmds = new string[](1);
        cmds[0] = 'approveContractCallWithMint';
        bytes[] memory params = new bytes[](1);
        params[0] = enc;
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = commandId;
        uint256 before = token.totalSupply();
        _exec(abi.encode(block.chainid, ids, cmds, params));
        bool ok = gateway.validateContractCallAndMint(commandId, 'src', '0xabc', payloadHash, SYMBOL, amount);
        if (ok) {
            bytes32 key = keccak256(abi.encodePacked(commandId, payloadHash, amount));
            if (!approvalUsed[key] && token.totalSupply() == before + amount) {
                approvalUsed[key] = true;
                sumApprovalMinted += amount;
            }
        }
    }

    // Invariant: totalSupply cannot exceed sum of unique minted amounts and unique approvals
    function echidna_supply_within_expected() public view returns (bool) {
        return token.totalSupply() <= (sumUniqueMinted + sumApprovalMinted);
    }
}

