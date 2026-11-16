// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Test} from "forge-std/Test.sol";

import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";
import {IOptimismPortal2} from "interfaces/L1/IOptimismPortal2.sol";

import {PostAnchor} from "src/fp/PostAnchor.sol";
import {ITZRootManager} from "src/fp/interfaces/ITZRootManager.sol";
import {InvalidASR, InvalidPortal, InvalidRootManager, InvalidPushGasLimit, NoAnchorGame} from "src/fp/lib/Errors.sol";

/// @notice Anchor registry stub matching the selectors PostAnchor reads (duck-typed by address).
contract MockASR {
    address internal anchorGameAddr;

    function setAnchorGame(address game_) external {
        anchorGameAddr = game_;
    }

    function anchorGame() external view returns (address) {
        return anchorGameAddr;
    }
}

/// @notice TZ claim game stub exposing the five source getters PostAnchor reads.
contract MockTZGame {
    uint256 internal seq;
    bytes32 internal bHash;
    bytes32 internal aHash;
    bytes32 internal wRoot;
    bytes32 internal fRoot;

    function set(uint256 seq_, bytes32 b_, bytes32 a_, bytes32 w_, bytes32 f_) external {
        seq = seq_;
        bHash = b_;
        aHash = a_;
        wRoot = w_;
        fRoot = f_;
    }

    function l2SequenceNumber() external view returns (uint256) {
        return seq;
    }

    function blockHash() external view returns (bytes32) {
        return bHash;
    }

    function appHash() external view returns (bytes32) {
        return aHash;
    }

    function bridgeRoot() external view returns (bytes32) {
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
    bytes32 internal constant B = keccak256("blockHash");
    bytes32 internal constant A = keccak256("appHash");
    bytes32 internal constant W = keccak256("bridgeRoot");
    bytes32 internal constant F = keccak256("forceRoot");

    event RootsEnqueued(
        address indexed game,
        uint256 indexed blockHeight,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 bridgeRoot,
        bytes32 forceRoot
    );

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
        vm.expectRevert(NoAnchorGame.selector);
        postAnchor.push();
    }

    // -- push happy path --

    function test_push_forwardsFixedDepositAndEmits() public {
        asr.setAnchorGame(address(game));
        uint256 height = 12345;
        game.set(height, B, A, W, F);

        vm.expectEmit(true, true, false, true, address(postAnchor));
        emit RootsEnqueued(address(game), height, B, A, W, F);
        postAnchor.push();

        assertEq(portal.callCount(), 1);
        assertEq(portal.lastTo(), ROOT_MANAGER);
        assertEq(portal.lastValue(), 0, "value must be zero");
        assertEq(portal.lastGasLimit(), PUSH_GAS);
        assertFalse(portal.lastIsCreation());
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (height, B, A, W, F)));
        // The canonical standard-ABI calldata for record is 4-byte selector + 5 x 32-byte words.
        assertEq(portal.lastData().length, 164, "record calldata is 164 bytes");
    }

    function test_push_succeedsAboveUint64Max() public {
        asr.setAnchorGame(address(game));
        uint256 height = uint256(type(uint64).max) + 1;
        game.set(height, B, A, W, F);
        postAnchor.push();
        assertEq(portal.lastGasLimit(), PUSH_GAS);
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (height, B, A, W, F)));
        assertEq(portal.callCount(), 1);
    }

    /// @notice Zero block hash and app hash are legal and forwarded verbatim.
    function test_push_forwardsZeroBlockAndAppHash() public {
        asr.setAnchorGame(address(game));
        game.set(uint256(42), bytes32(0), bytes32(0), W, F);
        postAnchor.push();
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (uint256(42), bytes32(0), bytes32(0), W, F)));
    }

    /// @notice Permissionless parity: any caller reaches the same delivery, no privilege granted.
    function test_push_permissionlessCallerParity() public {
        asr.setAnchorGame(address(game));
        game.set(uint256(777), B, A, W, F);
        vm.prank(address(0xD00D));
        postAnchor.push();
        assertEq(portal.callCount(), 1);
        assertEq(portal.lastTo(), ROOT_MANAGER);
    }

    function test_push_afterASRAdvancesUsesNewAnchor() public {
        game.set(uint256(100), B, A, W, F);
        asr.setAnchorGame(address(game));
        postAnchor.push();
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (uint256(100), B, A, W, F)));

        bytes32 newerB = keccak256("newer blockHash");
        bytes32 newerA = keccak256("newer appHash");
        bytes32 newerW = keccak256("newer bridgeRoot");
        bytes32 newerF = keccak256("newer forceRoot");
        newerGame.set(uint256(200), newerB, newerA, newerW, newerF);
        asr.setAnchorGame(address(newerGame));
        postAnchor.push();

        assertEq(portal.callCount(), 2);
        assertEq(
            portal.lastData(), abi.encodeCall(ITZRootManager.record, (uint256(200), newerB, newerA, newerW, newerF))
        );
    }

    function testFuzz_push_forwardsCallerIndependentFixedDeposit(
        address caller,
        uint256 height,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 bridgeRoot,
        bytes32 forceRoot
    ) public {
        vm.assume(caller != address(0));
        vm.assume(height > 0);

        asr.setAnchorGame(address(game));
        game.set(height, blockHash, appHash, bridgeRoot, forceRoot);

        vm.prank(caller);
        postAnchor.push();

        assertEq(portal.callCount(), 1);
        assertEq(portal.lastTo(), ROOT_MANAGER);
        assertEq(portal.lastValue(), 0);
        assertEq(portal.lastGasLimit(), PUSH_GAS);
        assertFalse(portal.lastIsCreation());
        assertEq(
            portal.lastData(),
            abi.encodeCall(ITZRootManager.record, (height, blockHash, appHash, bridgeRoot, forceRoot))
        );
    }

    function test_push_sameAnchorTwiceEnqueuesTwiceForTargetChainRetry() public {
        asr.setAnchorGame(address(game));
        game.set(uint256(100), B, A, W, F);

        postAnchor.push();
        postAnchor.push();

        assertEq(portal.callCount(), 2, "same anchor must remain retryable");
        assertEq(portal.lastData(), abi.encodeCall(ITZRootManager.record, (uint256(100), B, A, W, F)));
    }

    function test_push_doesNotMutateForwarderStorage() public {
        bytes32 slot0Before = vm.load(address(postAnchor), bytes32(uint256(0)));

        asr.setAnchorGame(address(game));
        game.set(uint256(100), B, A, W, F);
        postAnchor.push();

        assertEq(vm.load(address(postAnchor), bytes32(uint256(0))), slot0Before);
    }

    function test_push_alwaysForwardsCurrentASRAnchorWithoutLocalWatermark() public {
        newerGame.set(uint256(200), B, A, W, F);
        asr.setAnchorGame(address(newerGame));
        postAnchor.push();

        game.set(uint256(100), keccak256("old-b"), keccak256("old-a"), keccak256("old-w"), keccak256("old-f"));
        asr.setAnchorGame(address(game));
        postAnchor.push();

        assertEq(portal.callCount(), 2);
        assertEq(
            portal.lastData(),
            abi.encodeCall(
                ITZRootManager.record,
                (uint256(100), keccak256("old-b"), keccak256("old-a"), keccak256("old-w"), keccak256("old-f"))
            )
        );
    }

    function test_push_portalRevertBubbles() public {
        asr.setAnchorGame(address(game));
        game.set(uint256(1), B, A, W, F);
        portal.setShouldRevert(true);
        vm.expectRevert(bytes("portal down"));
        postAnchor.push();

        assertEq(portal.callCount(), 0);

        portal.setShouldRevert(false);
        postAnchor.push();
        assertEq(portal.callCount(), 1, "recovered portal must accept retry");
    }

    /// @notice Payable-surface negative smoke: push() is non-payable; a nonzero-value call reverts.
    function test_push_rejectsValue() public {
        asr.setAnchorGame(address(game));
        game.set(uint256(1), B, A, W, F);
        (bool ok,) = address(postAnchor).call{value: 1 wei}(abi.encodeWithSignature("push()"));
        assertFalse(ok, "push must reject msg.value");
    }

    function test_directEthSend_reverts() public {
        (bool ok,) = address(postAnchor).call{value: 1 wei}("");
        assertFalse(ok, "direct ETH send must revert");
    }
}
