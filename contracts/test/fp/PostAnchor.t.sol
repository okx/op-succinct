// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";

import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {IOptimismPortal2} from "interfaces/L1/IOptimismPortal2.sol";

import {PostAnchor} from "src/fp/PostAnchor.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {
    InvalidASR,
    InvalidPortal,
    InvalidRootManager,
    InvalidPushGasLimit,
    NoAnchorGame,
    InvalidAnchorGame,
    SequenceNumberOverflow
} from "src/fp/lib/Errors.sol";

/// @notice Anchor registry stub matching the selectors PostAnchor reads (duck-typed by address).
contract MockASR {
    address internal anchorGameAddr;
    bool internal claimValid;

    function setAnchorGame(address game_) external {
        anchorGameAddr = game_;
    }

    function setClaimValid(bool valid_) external {
        claimValid = valid_;
    }

    function anchorGame() external view returns (address) {
        return anchorGameAddr;
    }

    function isGameClaimValid(address) external view returns (bool) {
        return claimValid;
    }
}

/// @notice TZ claim game stub exposing the source getters PostAnchor reads.
contract MockTZGame {
    uint256 internal seq;
    bytes32 internal wRoot;
    bytes32 internal fRoot;

    function set(uint256 seq_, bytes32 w_, bytes32 f_) external {
        seq = seq_;
        wRoot = w_;
        fRoot = f_;
    }

    function l2SequenceNumber() external view returns (uint256) {
        return seq;
    }

    function withdrawalRoot() external view returns (bytes32) {
        return wRoot;
    }

    function forceRoot() external view returns (bytes32) {
        return fRoot;
    }
}

/// @notice Portal stub recording the last deposit args, with an optional forced revert.
contract RecordingPortal {
    address public lastTo;
    uint256 public lastValue;
    uint64 public lastGasLimit;
    bool public lastIsCreation;
    bytes public lastData;
    uint256 public callCount;
    bool internal shouldRevert;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function depositTransaction(address _to, uint256 _value, uint64 _gasLimit, bool _isCreation, bytes memory _data)
        external
        payable
    {
        if (shouldRevert) revert("portal down");
        lastTo = _to;
        lastValue = _value;
        lastGasLimit = _gasLimit;
        lastIsCreation = _isCreation;
        lastData = _data;
        callCount++;
    }
}

contract PostAnchorTest is Test {
    MockASR internal asr;
    RecordingPortal internal portal;
    MockTZGame internal game;
    MockTZGame internal newerGame;
    PostAnchor internal postAnchor;

    address internal constant ROOT_MANAGER = address(0xCAFE);
    uint64 internal constant PUSH_GAS = 150_000;
    bytes32 internal constant W = keccak256("withdrawalRoot");
    bytes32 internal constant F = keccak256("forceRoot");

    event RootsEnqueued(address indexed game, uint64 indexed l2BlockNumber, bytes32 withdrawalRoot, bytes32 forceRoot);

    function setUp() public {
        asr = new MockASR();
        portal = new RecordingPortal();
        game = new MockTZGame();
        newerGame = new MockTZGame();
        postAnchor = _newPostAnchor(address(asr), address(portal), ROOT_MANAGER, PUSH_GAS);
    }

    function _newPostAnchor(address asr_, address portal_, address rm_, uint64 gas_) internal returns (PostAnchor) {
        return new PostAnchor(IAnchorStateRegistry(asr_), IOptimismPortal2(payable(portal_)), rm_, gas_);
    }

    // -- constructor guards --

    function test_constructor_revertsOnNoCodeASR() public {
        vm.expectRevert(InvalidASR.selector);
        _newPostAnchor(address(0x1234), address(portal), ROOT_MANAGER, PUSH_GAS);
    }

    function test_constructor_revertsOnNoCodePortal() public {
        vm.expectRevert(InvalidPortal.selector);
        _newPostAnchor(address(asr), address(0x1234), ROOT_MANAGER, PUSH_GAS);
    }

    function test_constructor_revertsOnZeroRootManager() public {
        vm.expectRevert(InvalidRootManager.selector);
        _newPostAnchor(address(asr), address(portal), address(0), PUSH_GAS);
    }

    function test_constructor_revertsOnZeroGasLimit() public {
        vm.expectRevert(InvalidPushGasLimit.selector);
        _newPostAnchor(address(asr), address(portal), ROOT_MANAGER, 0);
    }

    // -- push validity --

    function test_push_revertsWhenNoAnchorGame() public {
        asr.setAnchorGame(address(0));
        asr.setClaimValid(true);
        vm.expectRevert(NoAnchorGame.selector);
        postAnchor.push();
    }

    function test_push_revertsWhenAnchorGameInvalid() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(false);
        vm.expectRevert(InvalidAnchorGame.selector);
        postAnchor.push();
    }

    function test_push_revertsOnSequenceOverflow() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(type(uint64).max) + 1, W, F);
        vm.expectRevert(SequenceNumberOverflow.selector);
        postAnchor.push();
    }

    // -- push happy path --

    function test_push_forwardsFixedDepositAndEmits() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        uint64 height = 12345;
        game.set(uint256(height), W, F);

        vm.expectEmit(true, true, false, true, address(postAnchor));
        emit RootsEnqueued(address(game), height, W, F);
        postAnchor.push();

        assertEq(portal.callCount(), 1);
        assertEq(portal.lastTo(), ROOT_MANAGER);
        assertEq(portal.lastValue(), 0, "value must be zero");
        assertEq(portal.lastGasLimit(), PUSH_GAS);
        assertFalse(portal.lastIsCreation());
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (W, F, height)));
    }

    function test_push_succeedsAtUint64Max() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(type(uint64).max), W, F);
        postAnchor.push();
        assertEq(portal.lastGasLimit(), PUSH_GAS);
        assertEq(portal.callCount(), 1);
    }

    /// @notice Permissionless parity: any caller reaches the same delivery, no privilege granted.
    function test_push_permissionlessCallerParity() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(777), W, F);
        vm.prank(address(0xD00D));
        postAnchor.push();
        assertEq(portal.callCount(), 1);
        assertEq(portal.lastTo(), ROOT_MANAGER);
    }

    function test_push_afterASRAdvancesUsesNewAnchor() public {
        asr.setClaimValid(true);

        game.set(uint256(100), W, F);
        asr.setAnchorGame(address(game));
        postAnchor.push();
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (W, F, uint64(100))));

        bytes32 newerW = keccak256("newer withdrawalRoot");
        bytes32 newerF = keccak256("newer forceRoot");
        newerGame.set(uint256(200), newerW, newerF);
        asr.setAnchorGame(address(newerGame));
        postAnchor.push();

        assertEq(portal.callCount(), 2);
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (newerW, newerF, uint64(200))));
    }

    function testFuzz_push_forwardsCallerIndependentFixedDeposit(
        address caller,
        uint64 height,
        bytes32 withdrawalRoot,
        bytes32 forceRoot
    ) public {
        vm.assume(caller != address(0));
        vm.assume(withdrawalRoot != forceRoot);

        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(height), withdrawalRoot, forceRoot);

        vm.prank(caller);
        postAnchor.push();

        assertEq(portal.callCount(), 1);
        assertEq(portal.lastTo(), ROOT_MANAGER);
        assertEq(portal.lastValue(), 0);
        assertEq(portal.lastGasLimit(), PUSH_GAS);
        assertFalse(portal.lastIsCreation());
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (withdrawalRoot, forceRoot, height)));
    }

    function test_postAnchorStorageUnaffectedByPush() public {
        bytes32 slot0Before = vm.load(address(postAnchor), bytes32(uint256(0)));
        bytes32 slot1Before = vm.load(address(postAnchor), bytes32(uint256(1)));
        bytes32 slot2Before = vm.load(address(postAnchor), bytes32(uint256(2)));
        bytes32 slot3Before = vm.load(address(postAnchor), bytes32(uint256(3)));

        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(1), W, F);
        postAnchor.push();

        assertEq(vm.load(address(postAnchor), bytes32(uint256(0))), slot0Before);
        assertEq(vm.load(address(postAnchor), bytes32(uint256(1))), slot1Before);
        assertEq(vm.load(address(postAnchor), bytes32(uint256(2))), slot2Before);
        assertEq(vm.load(address(postAnchor), bytes32(uint256(3))), slot3Before);
    }

    function test_push_portalRevertBubbles() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(1), W, F);
        portal.setShouldRevert(true);
        vm.expectRevert(bytes("portal down"));
        postAnchor.push();
    }

    /// @notice Payable-surface negative smoke: push() is non-payable; a nonzero-value call reverts.
    function test_push_rejectsValue() public {
        asr.setAnchorGame(address(game));
        asr.setClaimValid(true);
        game.set(uint256(1), W, F);
        (bool ok,) = address(postAnchor).call{value: 1 wei}(abi.encodeWithSignature("push()"));
        assertFalse(ok, "push must reject msg.value");
    }

    function test_directEthSend_reverts() public {
        (bool ok,) = address(postAnchor).call{value: 1 wei}("");
        assertFalse(ok, "direct ETH send must revert");
    }
}
