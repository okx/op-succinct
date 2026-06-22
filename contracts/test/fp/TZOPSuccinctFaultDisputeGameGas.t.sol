// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Inherits all setUp + helpers from the main test contract.
import {TZOPSuccinctFaultDisputeGameTest} from "./TZOPSuccinctFaultDisputeGame.t.sol";

import {Claim, Duration, GameStatus, Hash, Timestamp} from "src/dispute/lib/Types.sol";
import {TZOPSuccinctFaultDisputeGame} from "src/fp/TZOPSuccinctFaultDisputeGame.sol";

/// @title TZOPSuccinctFaultDisputeGameGasTest
/// @notice Gas baselines for SPEC operations + regression assertions.
///         Run `forge snapshot --match-path test/fp/TZOPSuccinctFaultDisputeGameGas.t.sol`
///         to record current gas in `.gas-snapshot`; subsequent CI runs use `--check`
///         to detect regressions against the committed baseline.
///
/// @dev    Each test:
///         1. Stages contract state up to just before the target operation
///         2. Brackets the target op with `gasleft()` calls and `emit log_named_uint`
///         3. `assertLt` against a documented upper-bound budget (regression guard)
///
///         Budgets are conservative; tighten them after the first snapshot is taken.
contract TZOPSuccinctFaultDisputeGameGasTest is TZOPSuccinctFaultDisputeGameTest {
    // ===================== initialize() gas =====================

    /// @notice initialize() with N=1 (V1-equivalent CWIA layout, no intermediate roots).
    function test_gas_initialize_N1() public {
        vm.startPrank(proposer);
        uint256 g0 = gasleft();
        factory.create{value: CREATE_BOND}(
            gameType,
            rootClaim,
            _encodeExtraDataN1(2000, 0)
        );
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("initialize N=1 gas (incl. factory.create overhead)", used);
        // factory.create overhead + initialize() body
        assertLt(used, 500_000, "init N=1 gas regression");
    }

    /// @notice initialize() with N=4 (3 intermediate roots in extraData).
    function test_gas_initialize_N4() public {
        bytes32[] memory roots = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) roots[i] = keccak256(abi.encodePacked("seg", i));
        bytes memory extra = _encodeExtraData(2000, 0, roots);

        vm.startPrank(proposer);
        uint256 g0 = gasleft();
        factory.create{value: CREATE_BOND}(gameType, rootClaim, extra);
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("initialize N=4 gas", used);
        assertLt(used, 550_000, "init N=4 gas regression");
    }

    /// @notice initialize() with N=256 (max segments; 255 intermediate roots = ~8.2 KB calldata).
    function test_gas_initialize_N256() public {
        bytes32[] memory roots = new bytes32[](255);
        for (uint256 i = 0; i < 255; i++) roots[i] = keccak256(abi.encodePacked("seg", i));
        bytes memory extra = _encodeExtraData(2024, 0, roots); // batchSize 1024 = 256*4

        vm.startPrank(proposer);
        uint256 g0 = gasleft();
        factory.create{value: CREATE_BOND}(gameType, rootClaim, extra);
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("initialize N=256 gas", used);
        // N=256 calldata adds ~130k gas for ~8.2 KB intermediate roots (16 gas/byte).
        // SPEC §4 budget: <250K body + factory overhead.
        assertLt(used, 8_000_000, "init N=256 gas regression");
    }

    // ===================== challenge(uint64) gas =====================

    function test_gas_challenge_firstChallenger() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.startPrank(challenger);
        uint256 g0 = gasleft();
        g.challenge{value: CHAL_BOND}(uint64(0));
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("challenge first segment gas", used);
        // Cold storage writes: ChallengerInfo (2 slots) + DisputeEntry (2 slots) + counter + ledger
        assertLt(used, 200_000, "challenge gas regression");
    }

    function test_gas_challenge_secondSegment_warmStatus() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Warm up status by challenging k=0 first (cheap subsequent challenges).
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        vm.deal(challenger2, 10 ether);
        vm.startPrank(challenger2);
        uint256 g0 = gasleft();
        g.challenge{value: CHAL_BOND}(uint64(2));
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("challenge subsequent segment gas (warm status)", used);
        assertLt(used, 150_000, "challenge subsequent gas regression");
    }

    // ===================== prove(uint64,bytes) gas =====================

    function test_gas_proveSegment_k0() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        vm.startPrank(prover);
        uint256 g0 = gasleft();
        g.prove(uint64(0), "");
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("prove(0, bytes) endpoint k=0 gas", used);
        // SP1 verify mock is ~50 gas; rest is state updates + L-bond push.
        assertLt(used, 200_000, "proveSegment k=0 gas regression");
    }

    function test_gas_proveSegment_middle_k1() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        vm.startPrank(prover);
        uint256 g0 = gasleft();
        g.prove(uint64(1), "");
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("prove(1, bytes) middle k=1 gas (intermediateRoot read)", used);
        assertLt(used, 200_000, "proveSegment middle gas regression");
    }

    function test_gas_proveSegment_endpoint_lastK() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(3)); // last segment

        vm.startPrank(prover);
        uint256 g0 = gasleft();
        g.prove(uint64(3), "");
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("prove(3, bytes) endpoint k=N-1 gas (rootClaim read)", used);
        assertLt(used, 200_000, "proveSegment last gas regression");
    }

    // ===================== prove(bytes) early-finalize gas =====================

    function test_gas_proveFull_N1() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = TZOPSuccinctFaultDisputeGame(
            address(factory.create{value: CREATE_BOND}(gameType, rootClaim, _encodeExtraDataN1(2000, 0)))
        );

        vm.startPrank(prover);
        uint256 g0 = gasleft();
        g.prove("");
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("prove(bytes) early-finalize N=1 gas", used);
        // SPEC §6 Phase 3.5 budget: ~280K with real SP1 verify; mock is ~30K.
        assertLt(used, 100_000, "proveFull N=1 gas regression");
    }

    function test_gas_proveFull_N4() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.startPrank(prover);
        uint256 g0 = gasleft();
        g.prove("");
        uint256 used = g0 - gasleft();
        vm.stopPrank();
        emit log_named_uint("prove(bytes) early-finalize N=4 gas", used);
        assertLt(used, 100_000, "proveFull N=4 gas regression");
    }

    // ===================== resolve() gas =====================

    function test_gas_resolve_Unchallenged_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.warp(g.challengeEnd().raw() + 1);

        uint256 g0 = gasleft();
        g.resolve();
        uint256 used = g0 - gasleft();
        emit log_named_uint("resolve Unchallenged DW gas", used);
        // No challengers; just status flip + CREATE_BOND push.
        assertLt(used, 100_000, "resolve Unchallenged DW gas regression");
    }

    function test_gas_resolve_FullProved_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(prover);
        g.prove("");

        uint256 g0 = gasleft();
        g.resolve();
        uint256 used = g0 - gasleft();
        emit log_named_uint("resolve FullProved DW gas", used);
        assertLt(used, 100_000, "resolve FullProved gas regression");
    }

    function test_gas_resolve_Challenged_DW_allProved() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(prover);
        g.prove(uint64(0), "");

        (, Timestamp pd, , , ) = _readClaimData(g);
        vm.warp(pd.raw() + 1);

        uint256 g0 = gasleft();
        g.resolve();
        uint256 used = g0 - gasleft();
        emit log_named_uint("resolve Challenged DW (all proved) gas", used);
        assertLt(used, 100_000, "resolve all-proved DW gas regression");
    }

    function test_gas_resolve_Challenged_CHW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        // No prove → CHW.

        (, Timestamp pd, , , ) = _readClaimData(g);
        vm.warp(pd.raw() + 1);

        uint256 g0 = gasleft();
        g.resolve();
        uint256 used = g0 - gasleft();
        emit log_named_uint("resolve Challenged CHW gas (no immediate push)", used);
        // CHW path doesn't push any credit at resolve time; lazy compute deferred to claimCredit.
        assertLt(used, 80_000, "resolve CHW gas regression");
    }

    // ===================== claimCredit gas =====================

    function test_gas_claimCredit_proposer_DW() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        _finalizeGame(g);

        uint256 g0 = gasleft();
        g.claimCredit(proposer);
        uint256 used = g0 - gasleft();
        emit log_named_uint("claimCredit proposer DW gas (no lazy compute)", used);
        // includes closeGame() ASR calls + isGameProper check + ETH transfer
        assertLt(used, 150_000, "claimCredit proposer gas regression");
    }

    function test_gas_claimCredit_lowestS_lazyComputeN4() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.deal(challenger, 10 ether);
        vm.deal(challenger2, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0)); // lowest-S
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(2));

        (, Timestamp pd, , , ) = _readClaimData(g);
        vm.warp(pd.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        uint256 g0 = gasleft();
        g.claimCredit(challenger);
        uint256 used = g0 - gasleft();
        emit log_named_uint("claimCredit lowest-S w/lazy compute N=4 gas", used);
        // First S-path claimer pays the O(N) scan; N=4 is cheap.
        assertLt(used, 200_000, "claimCredit lazy N=4 gas regression");
    }

    function test_gas_claimCredit_lowestS_lazyComputeN256_worstCase() public {
        // N=256 worst case: 255 distinct challengers, all unproven, all S.
        // First S-claimer pays the worst-case O(N) scan.
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(256, 1000 + 1024, 0, rootClaim);

        for (uint64 k = 0; k < 256; k++) {
            address actor = address(uint160(0x20000 + k));
            accessManager.setChallenger(actor, true);
            vm.deal(actor, 10 ether);
            vm.prank(actor);
            g.challenge{value: CHAL_BOND}(k);
        }

        (, Timestamp pd, , , ) = _readClaimData(g);
        vm.warp(pd.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Have the lowest-S actor (k=0) claim first → triggers full O(N) scan.
        address lowestSActor = address(uint160(0x20000));

        uint256 g0 = gasleft();
        g.claimCredit(lowestSActor);
        uint256 used = g0 - gasleft();
        emit log_named_uint("claimCredit lazy compute N=256 WORST CASE gas", used);
        // SPEC §6.4.2 estimated ~540k for the loop alone; actual ~700k including settle + transfer.
        // Generous bound: well under block gas limit (30M).
        assertLt(used, 2_000_000, "claimCredit lazy N=256 worst case gas regression");
    }
}
