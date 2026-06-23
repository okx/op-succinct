// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Inherits all setUp + helpers from the main test contract.
import {TZOPSuccinctFaultDisputeGameTest} from "./TZOPSuccinctFaultDisputeGame.t.sol";

import {Claim, Duration, GameStatus, Hash, Timestamp} from "src/dispute/lib/Types.sol";
import {
    BadAuth,
    IncorrectBondAmount,
    NoCreditToClaim,
    ClaimAlreadyResolved,
    BondTransferFailed
} from "src/dispute/lib/Errors.sol";
import {
    ClaimAlreadyChallenged,
    AlreadyCountered,
    NotUnchallenged
} from "src/fp/lib/Errors.sol";
import {AggregationOutputs} from "src/lib/Types.sol";
import {TZOPSuccinctFaultDisputeGame} from "src/fp/TZOPSuccinctFaultDisputeGame.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

/// @notice Receiver that re-enters claimCredit on receive — for testing CEI ordering.
contract ReentrantClaimer {
    TZOPSuccinctFaultDisputeGame public game;
    bool public reenterAttempted;
    bool public reenterReverted;

    constructor(TZOPSuccinctFaultDisputeGame _game) {
        game = _game;
    }

    receive() external payable {
        // Try to re-enter claimCredit on receive. Should hit NoCreditToClaim because the
        // outer call zeroed our credit BEFORE the transfer (CEI pattern).
        reenterAttempted = true;
        try game.claimCredit(address(this)) {
            // If we get here without revert, the contract is reentrancy-vulnerable.
        } catch {
            reenterReverted = true;
        }
    }
}

/// @notice Receiver that always reverts on receive — for testing BondTransferFailed propagation.
contract RevertingReceiver {
    receive() external payable {
        revert("nope");
    }
}

/// @title TZOPSuccinctFaultDisputeGameAttacksTest
/// @notice Regression tests for the SPEC §10 attack surface. Inherits setUp from
///         TZOPSuccinctFaultDisputeGameTest. Each test exercises a documented attack
///         scenario and asserts the in-contract defense holds.
contract TZOPSuccinctFaultDisputeGameAttacksTest is TZOPSuccinctFaultDisputeGameTest {
    address attackerA = address(0xAAA);
    address attackerB = address(0xBBB);

    function setUp() public override {
        super.setUp();
        // Whitelist attacker addresses as challengers so they can call challenge() — the test
        // is whether the protocol economics defeat them, not whether ACL stops them.
        accessManager.setChallenger(attackerA, true);
        accessManager.setChallenger(attackerB, true);
        vm.deal(attackerA, 100 ether);
        vm.deal(attackerB, 100 ether);
        // Fund the standard test actors so any test in this suite can call challenge() / prove().
        vm.deal(challenger, 100 ether);
        vm.deal(challenger2, 100 ether);
        vm.deal(prover, 100 ether);
    }

    // ===================== §10.1 Attack: Pile-on dilution =====================

    /// @notice Multiple addresses cannot all counter the same segment k → index-level dedup
    ///         (each k can be counter'd by at most one address). Defends against bond dilution
    ///         where N attackers all "join" segment k to spread the reward over N.
    function test_attack_pileOnDilution_blockedBySegmentDedup() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // First challenger counter k=1.
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Three more attackers try the same segment.
        vm.prank(attackerA);
        vm.expectRevert(ClaimAlreadyChallenged.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));

        vm.prank(attackerB);
        vm.expectRevert(ClaimAlreadyChallenged.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // totalCountered stays at 1.
        assertEq(g.totalCountered(), 1);
    }

    // ===================== §10.1 Attack: Sock-puppet self-challenge =====================

    /// @notice Proposer's sock-puppet challenges a non-first-mismatch segment to dilute
    ///         honest challenger's reward. First-mismatch winner-takes-all defeats this:
    ///         sock-puppet (non-lowest-S) gets only its own CHAL_BOND back; cannot steal CREATE_BOND.
    function test_attack_sockPuppetSelfChallenge_nonLowestGetsNoCreateBond() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Honest challenger picks the true first-mismatch k=1 (lowest-S).
        vm.deal(challenger, 10 ether);
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Sock-puppet on k=3 (higher index) — tries to bias the CREATE_BOND payout.
        vm.prank(attackerA);
        g.challenge{value: CHAL_BOND}(uint64(3));

        // Neither is proven (proposer's fault means no valid proof exists).
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Sock-puppet claims FIRST — only gets own CHAL_BOND back; lowestSIndex compute
        // identifies k=1 (honest's) as winner regardless of claim order.
        uint256 sockBefore = attackerA.balance;
        g.claimCredit(attackerA);
        assertEq(attackerA.balance - sockBefore, CHAL_BOND, "sock-puppet gets only own CHAL");

        // lowestSIndex lazy-computed correctly.
        assertEq(g.lowestSIndex(), 1, "true first-mismatch is honest's k=1");

        // Honest claims — gets CHAL_BOND + CREATE_BOND.
        uint256 honestBefore = challenger.balance;
        g.claimCredit(challenger);
        assertEq(challenger.balance - honestBefore, CHAL_BOND + CREATE_BOND, "honest gets full reward");
    }

    // ===================== §10.1 Attack: Per-address dedup =====================

    /// @notice Single attacker cannot counter multiple segments to inflate their "presence"
    ///         in the dispute. The `countered` flag is permanent → second challenge reverts.
    function test_attack_perAddressDedup_singleAttackerCannotCounterTwoSegments() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(attackerA);
        g.challenge{value: CHAL_BOND}(uint64(0));

        vm.prank(attackerA);
        vm.expectRevert(AlreadyCountered.selector);
        g.challenge{value: CHAL_BOND}(uint64(1));
    }

    /// @notice After prove() consumed the challenger's bond, the `countered` flag remains true
    ///         → challenger still cannot re-challenge. SPEC §11 Invariant 13.
    function test_attack_reChallenge_afterProveBlocksReChallenge() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Prove the segment; this zeroes challengers[challenger].bond but NOT .countered.
        vm.prank(prover);
        g.prove(uint64(0), "");

        // challenger's bond is now 0, but countered flag is preserved.
        (uint256 bond, bool counteredFlag, ) = g.challengers(challenger);
        assertEq(bond, 0);
        assertTrue(counteredFlag);

        // challenger cannot re-challenge another segment.
        vm.prank(challenger);
        vm.expectRevert(AlreadyCountered.selector);
        g.challenge{value: CHAL_BOND}(uint64(2));
    }

    // ===================== §10.1 Attack: Parent-forced CHW grief =====================

    /// @notice Multiple resolve() calls after parent-CHW propagation only execute once;
    ///         subsequent reverts cleanly with ClaimAlreadyResolved. No proposer cost beyond
    ///         the first call.
    function test_attack_parentCHWGrief_resolveIsIdempotent() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Honest case: no challenger, clock-DW.
        vm.warp(g.challengeEnd().raw() + 1);
        g.resolve();

        // Repeated resolve attempts revert cleanly.
        vm.expectRevert(ClaimAlreadyResolved.selector);
        g.resolve();

        // 10x repeat to verify no accidental state change.
        for (uint256 i = 0; i < 10; i++) {
            vm.expectRevert(ClaimAlreadyResolved.selector);
            g.resolve();
        }
    }

    // ===================== §10.3 DOS: Fast-finalize censoring =====================

    /// @notice Adversary frontruns a fast-finalize prove(bytes) tx with a cheap challenge(k).
    ///         This forces the game into the ~2-day challenge+prove pipeline. Spec accepts
    ///         this as "DOS-of-feature" — proveFull is best-effort, not a liveness guarantee.
    /// @dev    Verifies the mechanic: post-challenge, prove(bytes) reverts with NotUnchallenged.
    function test_attack_fastFinalizeDOS_challengeBlocksProveBytes() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Adversary lands challenge first (e.g., from private mempool).
        vm.prank(attackerA);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Now proveFull (prove(bytes)) reverts.
        vm.prank(prover);
        vm.expectRevert(NotUnchallenged.selector);
        g.prove("");

        // Adversary's CHAL_BOND is at risk: if anyone proves k=0 within proveDeadline, attacker loses.
        vm.prank(prover);
        g.prove(uint64(0), "");

        // Walk through DW resolution: proposer gets CREATE_BOND; prover gets attacker's CHAL_BOND.
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        uint256 proverBefore = prover.balance;
        g.claimCredit(prover);
        assertEq(prover.balance - proverBefore, CHAL_BOND, "attacker CHAL_BOND goes to prover");

        // attacker has no credit.
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(attackerA);
    }

    // ===================== §10 Reentrancy in claimCredit =====================

    /// @notice claimCredit follows checks-effects-interactions: ledger writes (zero-out) happen
    ///         BEFORE the external _recipient.call. A malicious recipient that re-enters via
    ///         receive() will see zeroed credit on the recursive call → NoCreditToClaim revert.
    ///         No double payment possible.
    function test_attack_reentrancy_claimCreditCEISafe() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Deploy attacker contract; whitelist it as challenger.
        ReentrantClaimer reentrant = new ReentrantClaimer(g);
        accessManager.setChallenger(address(reentrant), true);
        vm.deal(address(reentrant), 10 ether);

        // Reentrant attacker challenges k=0.
        vm.prank(address(reentrant));
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Add another S challenger so the game goes CHW (and reentrant gets a payout).
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(2));

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Attacker claims — reentrant attempt on receive() should fail (CEI ordering protects).
        uint256 attackerBalBefore = address(reentrant).balance;
        g.claimCredit(address(reentrant));

        // Got payment exactly once.
        // reentrant is lowest-S → gets CHAL + CREATE.
        assertEq(address(reentrant).balance - attackerBalBefore, CHAL_BOND + CREATE_BOND);

        // Reentrancy was attempted but reverted.
        assertTrue(reentrant.reenterAttempted(), "reentry attempted on receive");
        assertTrue(reentrant.reenterReverted(), "reentry hit NoCreditToClaim (CEI worked)");
    }

    /// @notice A recipient that reverts on receive triggers BondTransferFailed (preserves CEI
    ///         while signaling failure to caller).
    function test_attack_revertingReceiver_BondTransferFailed() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(4, 2000, 0, rootClaim);

        // Deploy attacker contract that always reverts on receive; whitelist + counter.
        RevertingReceiver bad = new RevertingReceiver();
        accessManager.setChallenger(address(bad), true);
        vm.deal(address(bad), 10 ether);

        vm.prank(address(bad));
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Need at least one S to force CHW.
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(2));

        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // claimCredit reverts BondTransferFailed.
        vm.expectRevert(BondTransferFailed.selector);
        g.claimCredit(address(bad));
    }

    // ===================== §10 Unbounded challenger DoS =====================

    /// @notice N=256 with one distinct challenger per segment → totalCountered = 256.
    ///         Resolve still works within block gas limit; claimCredit lazy compute scans
    ///         all segments but stays bounded (~540k gas worst case in spec).
    function test_attack_unboundedChallengerDoS_N256_resolves() public {
        // Need batchSize = 256k where k>=1 and k*256 is the batch size in blocks.
        // Use batchSize = 256 * 4 = 1024 blocks. l2Seq = 1000 (parent) + 1024 = 2024.
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(256, 1000 + 1024, 0, rootClaim);

        // Stage: spawn 256 unique challengers, each counters a distinct segment.
        for (uint64 k = 0; k < 256; k++) {
            address attacker = address(uint160(0x10000 + k));
            accessManager.setChallenger(attacker, true);
            vm.deal(attacker, 10 ether);
            vm.prank(attacker);
            g.challenge{value: CHAL_BOND}(k);
        }

        assertEq(g.totalCountered(), 256);

        // No one proves; warp to proveDeadline and resolve to CHW.
        (, Timestamp proveDeadline, , , ) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve(); // resolve() itself is O(1); does not iterate disputes.

        assertEq(uint8(g.status()), uint8(GameStatus.CHALLENGER_WINS));

        // First S-path claimCredit triggers the O(N) lazy compute. Just verify it succeeds.
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);
        address lowestSAttacker = address(uint160(0x10000));
        g.claimCredit(lowestSAttacker);

        // lowestSIndex should be 0 (segment 0's attacker).
        assertEq(g.lowestSIndex(), 0);
    }

    // ===================== SP1 Replay protection (static checks) =====================

    /// @notice Two games with different rootClaim produce distinct public input hashes
    ///         → an SP1 proof for game A cannot be replayed on game B (the SP1 verifier
    ///         rejects mismatched publicValues).
    /// @dev    With SP1MockVerifier we cannot operationally test verify-rejection, but the
    ///         binding is purely a function of publicValues content. Asserting publicValues
    ///         distinctness proves the cryptographic separation.
    function test_attack_replay_publicInputDiffersAcrossRootClaim() public {
        // Construct hypothetical publicValues for two games.
        AggregationOutputs memory pvA = AggregationOutputs({
            l1Head: bytes32(0),
            l2PreRoot: keccak256("start"),
            claimRoot: keccak256("rootClaimA"),
            claimBlockNum: 1000,
            rollupConfigHash: bytes32(0),
            rangeVkeyCommitment: bytes32(0),
            proverAddress: prover
        });
        AggregationOutputs memory pvB = AggregationOutputs({
            l1Head: bytes32(0),
            l2PreRoot: keccak256("start"),
            claimRoot: keccak256("rootClaimB"), // ← differs
            claimBlockNum: 1000,
            rollupConfigHash: bytes32(0),
            rangeVkeyCommitment: bytes32(0),
            proverAddress: prover
        });
        assertTrue(keccak256(abi.encode(pvA)) != keccak256(abi.encode(pvB)));
    }

    /// @notice Two segments within the same game have different `claimBlockNum` in publicValues
    ///         → cross-segment proof replay rejected by SP1 verifier.
    function test_attack_replay_publicInputDiffersAcrossSegments() public {
        AggregationOutputs memory pvSeg0 = AggregationOutputs({
            l1Head: bytes32(0),
            l2PreRoot: keccak256("start"),
            claimRoot: keccak256("seg1"),
            claimBlockNum: 1250, // startingSeq + SEGMENT_SIZE * 1
            rollupConfigHash: bytes32(0),
            rangeVkeyCommitment: bytes32(0),
            proverAddress: prover
        });
        AggregationOutputs memory pvSeg1 = AggregationOutputs({
            l1Head: bytes32(0),
            l2PreRoot: keccak256("seg1"),
            claimRoot: keccak256("seg2"),
            claimBlockNum: 1500, // startingSeq + SEGMENT_SIZE * 2
            rollupConfigHash: bytes32(0),
            rangeVkeyCommitment: bytes32(0),
            proverAddress: prover
        });
        assertTrue(keccak256(abi.encode(pvSeg0)) != keccak256(abi.encode(pvSeg1)));
    }

    /// @notice publicValues includes `proverAddress = msg.sender` — attacker that copies an
    ///         honest prover's proof bytes but submits with own msg.sender produces different
    ///         publicValues → SP1 verifier rejects.
    function test_attack_frontrunProver_publicInputIncludesMsgSender() public {
        AggregationOutputs memory pvHonest = AggregationOutputs({
            l1Head: bytes32(0),
            l2PreRoot: keccak256("start"),
            claimRoot: keccak256("claim"),
            claimBlockNum: 1500,
            rollupConfigHash: bytes32(0),
            rangeVkeyCommitment: bytes32(0),
            proverAddress: prover
        });
        AggregationOutputs memory pvAttacker = AggregationOutputs({
            l1Head: bytes32(0),
            l2PreRoot: keccak256("start"),
            claimRoot: keccak256("claim"),
            claimBlockNum: 1500,
            rollupConfigHash: bytes32(0),
            rangeVkeyCommitment: bytes32(0),
            proverAddress: attackerA // ← only difference
        });
        assertTrue(keccak256(abi.encode(pvHonest)) != keccak256(abi.encode(pvAttacker)));
    }

    // ===================== §10.5 Same-range multi-N spam (design-accepted) =====================

    /// @notice Two games with same (rootClaim, parent) but different N have different factory
    ///         UUIDs (extraData length differs) → both can coexist. Spec accepts this.
    function test_attack_multiNSpam_sameRangeDifferentN_independentGames() public {
        bytes memory inputClaim = abi.encode(keccak256("dupeClaim"));

        // Game A: N=2 → 1 intermediate root; batchSize=1000 → SEGMENT_SIZE=500.
        bytes32[] memory roots2 = new bytes32[](1);
        roots2[0] = keccak256("rootA");
        vm.prank(proposer);
        address gameA = address(
            factory.create{value: CREATE_BOND}(
                gameType, Claim.wrap(bytes32(inputClaim)), _encodeExtraData(2000, 0, roots2)
            )
        );

        // Game B: N=4 → 3 intermediate roots; same range and rootClaim.
        bytes32[] memory roots4 = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) roots4[i] = keccak256(abi.encodePacked("rootB", i));
        vm.prank(proposer);
        address gameB = address(
            factory.create{value: CREATE_BOND}(
                gameType, Claim.wrap(bytes32(inputClaim)), _encodeExtraData(2000, 0, roots4)
            )
        );

        // Both games coexist.
        assertTrue(gameA != gameB, "different game proxies");
        assertEq(TZOPSuccinctFaultDisputeGame(gameA).numSegments(), 2);
        assertEq(TZOPSuccinctFaultDisputeGame(gameB).numSegments(), 4);
        // Each holds its own CREATE_BOND deposit (no shared bond pool).
        assertEq(address(gameA).balance, CREATE_BOND);
        assertEq(address(gameB).balance, CREATE_BOND);
    }

    // ===================== Creator-as-Challenger Bond Inflation Regression =====================

    /// @notice REGRESSION: when the proposer is also whitelisted as a challenger and uses both
    ///         roles in the same game, `refundModeCredit[gameCreator()]` is +=ed twice
    ///         (CREATE_BOND at initialize, CHAL_BOND at challenge). Earlier code used this ledger
    ///         as a CREATE_BOND amount proxy in resolve()/claimCredit, which double-counted the
    ///         self-CHAL_BOND and made the contract insolvent. The fix snapshots CREATE_BOND
    ///         into `createBond` at initialize and reads that field instead.
    /// @dev    DW path: status=DEFENDER_WINS (Challenged + totalProved == totalCountered).
    function test_attack_creatorAsChallenger_bondConservation_DW() public {
        // Setup: same address gets both proposer and challenger whitelist.
        accessManager.setChallenger(proposer, true);

        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(2, 2000, 0, rootClaim);

        // Same address challenges segment 1 — refundModeCredit[proposer] becomes inflated.
        vm.prank(proposer);
        g.challenge{value: CHAL_BOND}(uint64(1));

        assertEq(g.refundModeCredit(proposer), CREATE_BOND + CHAL_BOND,
            "refundModeCredit is inflated by self-CHAL_BOND (this is the attack premise)");
        assertEq(g.createBond(), CREATE_BOND,
            "createBond snapshot equals exactly CREATE_BOND");

        // Independent prover proves segment 1 → consumes proposer's CHAL_BOND via L-bond push.
        vm.prank(prover);
        g.prove(uint64(1), "");
        assertEq(g.totalProved(), 1);
        assertEq(g.totalCountered(), 1);

        // Resolve under DW path (Challenged + all proved).
        (, Timestamp proveDeadline, , ,) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        assertEq(uint8(g.status()), uint8(GameStatus.DEFENDER_WINS));

        // Wait for finality + game-proper acceptance.
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Proposer claims: must receive exactly CREATE_BOND, NOT CREATE_BOND + CHAL_BOND.
        // (Self-CHAL_BOND was forfeited to prover via the L-bond push at prove() Step 4.)
        uint256 proposerBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - proposerBefore, CREATE_BOND,
            "creator-as-challenger DW: receives only CREATE_BOND (not inflated by self-CHAL_BOND)");

        // Prover claims their L-bond.
        uint256 proverBefore = prover.balance;
        g.claimCredit(prover);
        assertEq(prover.balance - proverBefore, CHAL_BOND, "prover receives CHAL_BOND from L-push");

        // Bond conservation: total paid = total deposited; contract drains to 0.
        assertEq(address(g).balance, 0, "bond conservation holds: contract balance is zero");
    }

    /// @notice REGRESSION (CHW path): proposer-as-challenger on the lowest-S segment must not
    ///         get the inflated `refundModeCredit[creator]` value when claimCredit's lazy
    ///         winner-takes-all push fires.
    /// @dev    CHW path: status=CHALLENGER_WINS (Challenged + totalProved < totalCountered).
    ///         The proposer challenges k=0 (lowest-S) themselves but nobody proves it → they
    ///         win the CHW lazy push. Should receive: own CHAL_BOND (settle) + CREATE_BOND
    ///         (winner push). Total = CHAL_BOND + CREATE_BOND, NOT 2*CHAL_BOND + CREATE_BOND.
    function test_attack_creatorAsChallenger_bondConservation_CHW_lowestS() public {
        accessManager.setChallenger(proposer, true);

        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(2, 2000, 0, rootClaim);

        // Proposer challenges segment 0 (will be lowest-S; nobody proves it).
        vm.prank(proposer);
        g.challenge{value: CHAL_BOND}(uint64(0));

        // Resolve past prove deadline → CHW (totalProved=0 < totalCountered=1).
        (, Timestamp proveDeadline, , ,) = _readClaimData(g);
        vm.warp(proveDeadline.raw() + 1);
        g.resolve();
        assertEq(uint8(g.status()), uint8(GameStatus.CHALLENGER_WINS));

        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Proposer (as lowest-S challenger) claims:
        //   - settle block: own CHAL_BOND back
        //   - lazy lowest-S push: createBond (NOT refundModeCredit[creator] = CREATE_BOND+CHAL_BOND)
        // Expected total = CHAL_BOND + CREATE_BOND.
        uint256 proposerBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - proposerBefore, CHAL_BOND + CREATE_BOND,
            "creator-as-challenger CHW: receives CHAL_BOND + CREATE_BOND (no double CHAL_BOND inflation)");

        assertEq(address(g).balance, 0, "bond conservation holds in CHW path");
    }

    // ===================== Parent-CHW CREATE_BOND Burn Regression =====================

    /// @notice REGRESSION (code-review #2): parent-CHW with `totalProved == totalCountered > 0`
    ///         (all challenged segments proved, S == ∅). Earlier code's parent-CHW branch only
    ///         burned CREATE_BOND when totalCountered == 0; the totalCountered > 0 case relied on
    ///         claimCredit's lazy lowest-S compute, but that compute is gated on `!d.proved` and
    ///         never runs when all segments are proved → CREATE_BOND ETH stranded in contract
    ///         with NO ledger entry pointing at it (silent §11 Inv 2 violation).
    /// @dev    Fix collapses the burn condition to `totalProved == totalCountered`, covering
    ///         both 0==0 and N==N (>0).
    function test_attack_parentCHW_allProved_createBondBurned() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(2, 2000, 0, rootClaim);

        // Two challengers, both segments countered.
        vm.prank(challenger);
        g.challenge{value: CHAL_BOND}(uint64(0));
        vm.prank(challenger2);
        g.challenge{value: CHAL_BOND}(uint64(1));

        // Both segments proved → totalProved == totalCountered == 2, S == ∅.
        vm.prank(prover);
        g.prove(uint64(0), "");
        vm.prank(prover);
        g.prove(uint64(1), "");
        assertEq(g.totalProved(), 2);
        assertEq(g.totalCountered(), 2);

        // Simulate parent resolving CHW (e.g., fraud detected upstream after this game ran).
        vm.mockCall(
            address(parentGame),
            abi.encodeWithSelector(IDisputeGame.status.selector),
            abi.encode(GameStatus.CHALLENGER_WINS)
        );

        g.resolve();
        vm.clearMockedCalls();

        assertEq(uint8(g.status()), uint8(GameStatus.CHALLENGER_WINS));

        // #2 fix: CREATE_BOND explicitly burned to address(0) (no longer stranded under NORMAL mode).
        assertEq(g.normalModeCredit(address(0)), CREATE_BOND,
            "parent-CHW + all-proved: CREATE_BOND burn ledger entry recorded");

        // refundModeCredit[creator] is intentionally preserved — REFUND mode (governance override)
        // must be able to roll back the burn to original depositor, matching V1 baseline behavior.
        assertEq(g.refundModeCredit(proposer), CREATE_BOND,
            "refundModeCredit[creator] preserved for REFUND-mode override rollback");

        // Burn flag set so claimCredit lazy push is skipped.
        assertTrue(g.createBondPushedAtResolve(), "createBondPushedAtResolve flag set");

        // Wait for finality.
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Provers still claim their L-bonds (parent-CHW does not reclaim L-bonds — design-accepted
        // per SPEC §11 Inv 2 / code-review #4 finding).
        uint256 proverBefore = prover.balance;
        g.claimCredit(prover);
        assertEq(prover.balance - proverBefore, 2 * CHAL_BOND, "prover claims both L-bonds");

        // NORMAL mode: proposer has no normalModeCredit entry → revert.
        vm.expectRevert(NoCreditToClaim.selector);
        g.claimCredit(proposer);

        // CREATE_BOND ETH remains burned in contract (no recipient holds address(0)'s private key).
        assertEq(address(g).balance, CREATE_BOND, "CREATE_BOND remains burned in contract under NORMAL mode");
    }

    /// @notice REGRESSION: REFUND mode semantics override §9.4.b burn — matches V1 baseline.
    ///         When a parent-CHW game later flips to REFUND mode (ASR.isGameProper=false, e.g.,
    ///         Guardian retirement / blacklist), the burn intent is overridden by REFUND's
    ///         emergency-rollback semantics: all original deposits return to their depositors
    ///         regardless of resolve outcome. The proposer reclaims their CREATE_BOND via the
    ///         REFUND branch — matches V1 OPSuccinctFaultDisputeGame.sol behavior.
    /// @dev    The §9.4.b burn lands in normalModeCredit[address(0)] (only paid in NORMAL mode);
    ///         refundModeCredit[gameCreator()] is intentionally NOT cleared at burn time so
    ///         REFUND mode can roll back as designed.
    function test_parentCHW_burn_refundModeOverridesBurn_V1Compatible() public {
        vm.prank(proposer);
        TZOPSuccinctFaultDisputeGame g = _createChildGame(1, 2000, 0, rootClaim);

        // No challenger → totalCountered == 0; parent-CHW hits the burn branch.
        vm.mockCall(
            address(parentGame),
            abi.encodeWithSelector(IDisputeGame.status.selector),
            abi.encode(GameStatus.CHALLENGER_WINS)
        );
        g.resolve();
        vm.clearMockedCalls();

        // Burn ledger entry recorded (claimed under NORMAL mode), but creator's refund ledger
        // is intentionally untouched so REFUND mode can roll back as designed.
        assertEq(g.normalModeCredit(address(0)), CREATE_BOND,
            "burn recorded in normalModeCredit[address(0)] (NORMAL-mode burn)");
        assertEq(g.refundModeCredit(proposer), CREATE_BOND,
            "REFUND-mode override: refundModeCredit[creator] preserved for emergency rollback");

        // Wait for finality.
        vm.warp(g.resolvedAt().raw() + portal.disputeGameFinalityDelaySeconds() + 1);

        // Force isGameProper() = false → closeGame() flips bondDistributionMode to REFUND.
        vm.mockCall(
            address(anchorStateRegistry),
            abi.encodeWithSelector(IAnchorStateRegistry.isGameProper.selector, IDisputeGame(address(g))),
            abi.encode(false)
        );

        // Proposer reclaims CREATE_BOND via REFUND branch — V1-compatible behavior.
        uint256 proposerBefore = proposer.balance;
        g.claimCredit(proposer);
        assertEq(proposer.balance - proposerBefore, CREATE_BOND,
            "REFUND mode: proposer reclaims CREATE_BOND (overrides SPEC 9.4.b burn)");

        vm.clearMockedCalls();

        // Contract balance drained (CREATE_BOND refunded to proposer).
        assertEq(address(g).balance, 0, "REFUND mode rolls back to original depositor");
    }
}
