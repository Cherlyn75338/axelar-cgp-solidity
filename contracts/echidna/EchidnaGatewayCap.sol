// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;

import { AxelarGateway } from '../AxelarGateway.sol';
import { TokenDeployer } from '../TokenDeployer.sol';
import { IBurnableMintableCappedERC20 } from '../interfaces/IBurnableMintableCappedERC20.sol';
import { IAxelarAuth } from '../interfaces/IAxelarAuth.sol';
import { ECDSA } from '../ECDSA.sol';

contract EchidnaAuthMock is IAxelarAuth {
    address private _owner;
    address private _pendingOwner;

    constructor() {
        _owner = msg.sender;
    }

    function validateProof(bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }

    function transferOperatorship(bytes calldata) external {}

    // IOwnable minimal implementation
    function owner() external view returns (address) {
        return _owner;
    }

    function pendingOwner() external view returns (address) {
        return _pendingOwner;
    }

    function proposeOwnership(address newOwner) external {
        _pendingOwner = newOwner;
    }

    function transferOwnership(address newOwner) external {
        _owner = newOwner;
    }

    function acceptOwnership() external {
        _owner = _pendingOwner;
        _pendingOwner = address(0);
    }
}

contract EchidnaGatewayCap {
    AxelarGateway public gateway;
    TokenDeployer public deployer;
    IBurnableMintableCappedERC20 public token;

    constructor() {
        EchidnaAuthMock auth = new EchidnaAuthMock();
        deployer = new TokenDeployer();
        gateway = new AxelarGateway(address(auth), address(deployer));

        // Deploy internal token via execute
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

        bytes memory data = abi.encode(chainId, ids, cmds, params);
        bytes memory input = abi.encode(data, bytes(''));
        (bool ok, ) = address(gateway).call(abi.encodeWithSelector(AxelarGateway.execute.selector, input));
        require(ok, 'deploy failed');
        token = IBurnableMintableCappedERC20(gateway.tokenAddresses(symbol));
    }

    // Action: attempt to mint arbitrary amount
    function mint(uint256 amount) public {
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = keccak256(abi.encodePacked('cmd-mint', amount));
        string[] memory cmds = new string[](1);
        cmds[0] = 'mintToken';
        bytes[] memory params = new bytes[](1);
        params[0] = abi.encode('TKN', address(this), amount);
        bytes memory data = abi.encode(block.chainid, ids, cmds, params);
        bytes memory input = abi.encode(data, bytes(''));
        // ignore success/failure; property checks totalSupply
        // solhint-disable-next-line avoid-low-level-calls
        address(gateway).call(abi.encodeWithSelector(AxelarGateway.execute.selector, input));
    }

    // Invariant: totalSupply never exceeds cap
    function echidna_totalSupply_lte_cap() public view returns (bool) {
        return token.totalSupply() <= token.cap();
    }
}

