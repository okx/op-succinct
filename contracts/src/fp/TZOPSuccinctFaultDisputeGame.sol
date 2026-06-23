// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

// Libraries
import {Clone} from "@solady/utils/Clone.sol";
import {
    BondDistributionMode,
    Claim,
    Clock,
    Duration,
    GameStatus,
    GameType,
    Hash,
    LibClock,
    Proposal,
    Timestamp
} from "src/dispute/lib/Types.sol";
import {
    AlreadyInitialized,
    AnchorRootNotFound,
    BadAuth,
    BadExtraData,
    BondTransferFailed,
    ClaimAlreadyResolved,
    ClockTimeExceeded,
    GameNotFinalized,
    GameNotInProgress,
    IncorrectBondAmount,
    InvalidBondDistributionMode,
    NoCreditToClaim,
    UnexpectedRootClaim
} from "src/dispute/lib/Errors.sol";
import "src/fp/lib/Errors.sol";
import {AggregationOutputs, OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE} from "src/lib/Types.sol";

// Interfaces
import {ISemver} from "interfaces/universal/ISemver.sol";
import {IDisputeGameFactory} from "interfaces/dispute/IDisputeGameFactory.sol";
import {IDisputeGame} from "interfaces/dispute/IDisputeGame.sol";
import {ISP1Verifier} from "@sp1-contracts/src/ISP1Verifier.sol";
import {IAnchorStateRegistry} from "interfaces/dispute/IAnchorStateRegistry.sol";

// Contracts
import {AccessManager} from "src/fp/AccessManager.sol";

/// @title TZOPSuccinctFaultDisputeGame
/// @notice TradeZone fault-proof dispute game; baseline copied from OPSuccinctFaultDisputeGame.
///         Subsequent commits modify this baseline per SPEC_GAME_V2_CALLDATA.md
///         (multi-segment + multi-challenger + variable batch + early-finalize overload).
contract TZOPSuccinctFaultDisputeGame is Clone, ISemver, IDisputeGame {
    ////////////////////////////////////////////////////////////////
    //                         Enums                              //
    ////////////////////////////////////////////////////////////////

    enum ProposalStatus {
        // The initial state of a new proposal (no challenger; no proveFull).
        Unchallenged,
        // ≥1 challenger has countered some segment, awaiting per-segment prove.
        Challenged,
        // Optional early-finalize mark: no challenger + entire-batch SP1 proof verified
        // by `prove(bytes)` overload. Equivalent to V1's UnchallengedAndValidProofProvided.
        // See SPEC §6 Phase 3.5.
        FullProved,
        // The final state after resolution, either GameStatus.CHALLENGER_WINS or GameStatus.DEFENDER_WINS.
        Resolved
    }

    ////////////////////////////////////////////////////////////////
    //                         Structs                            //
    ////////////////////////////////////////////////////////////////

    /// @notice The `ClaimData` struct represents the data associated with a Claim.
    /// @dev    Field order chosen for slot-1 packing: prover(20) + proveDeadline(8) + parentIndex(4) = 32B.
    ///         vs V1: drops `counteredBy` (per-segment tracking moved to `disputes[k].counteredBy`);
    ///         renames `deadline` → `proveDeadline` and switches semantics from rolling to absolute-time
    ///         (initialized once, never updated). See SPEC §8.1.
    struct ClaimData {
        address prover;             // SPEC §6 Phase 3.5 `prove(bytes)` writes msg.sender; default address(0)
        Timestamp proveDeadline;    // = createdAt + MAX_CHALLENGE_DURATION + MAX_PROVE_DURATION; absolute, never updated
        uint32 parentIndex;
        ProposalStatus status;
        Claim claim;
    }

    /// @notice Per-address challenger state for multi-challenger dispute mode (SPEC §6 Phase 1).
    /// @dev    `countered` is permanent once true → prevents re-challenge after prove() drains bond.
    struct ChallengerInfo {
        uint256 bond;               // CHAL_BOND deposit, zeroed in prove() Step 4 (L-path) or claimCredit() (S-path)
        bool    countered;          // permanent true after first challenge()
        uint64  counteredIndex;     // segment k that this challenger countered
    }

    /// @notice Per-segment dispute state for multi-challenger dispute mode (SPEC §6 Phase 1/2/4).
    /// @dev    Two slots packed: slot a = counteredBy(20)+proved(1)+claimed(1) = 22B; slot b = provedBy(20).
    struct DisputeEntry {
        address counteredBy;        // first challenger who counters segment k (index dedup)
        bool    proved;             // true after successful per-segment prove(uint64,bytes)
        bool    claimed;            // SPEC §6.4.2 lazy S-path settle marker (set in claimCredit)
        address provedBy;           // prover address for L-bond push at prove() Step 4
    }

    ////////////////////////////////////////////////////////////////
    //                         Events                             //
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted when the game is challenged on a specific segment.
    /// @param challenger The address of the challenger.
    /// @param segment   Segment index k that was countered.
    event Challenged(address indexed challenger, uint64 indexed segment);

    /// @notice Emitted when a per-segment SP1 proof verifies (SPEC §6 Phase 2 prove(uint64,bytes)).
    /// @param prover  The address whose msg.sender was committed to the zk proof's public input.
    /// @param segment The segment index k that was proven.
    event Proved(address indexed prover, uint64 indexed segment);

    /// @notice Emitted when a full-batch SP1 proof verifies (SPEC §6 Phase 3.5 prove(bytes) overload).
    /// @param prover  The address whose msg.sender was committed to the zk proof's public input.
    event FullProved(address indexed prover);

    /// @notice Emitted when the game is closed.
    event GameClosed(BondDistributionMode bondDistributionMode);

    ////////////////////////////////////////////////////////////////
    //          Errors (TZ-spec additions per SPEC §12.4)         //
    //   (will be consolidated into lib/Errors.sol in a later commit)
    ////////////////////////////////////////////////////////////////

    // `BadExtraData` is imported from `src/dispute/lib/Errors.sol`.

    /// @notice Thrown when derived numSegments is outside `[1, MAX_NUM_SEGMENTS]`.
    /// @param  actual Derived numSegments value from CWIA calldata length.
    error InvalidNumSegments(uint64 actual);

    /// @notice Thrown when `batchSize % numSegments != 0` (SEGMENT_SIZE would not be a positive integer).
    error InvalidBatchSize();

    /// @notice Thrown by any mutator first-check when `status != IN_PROGRESS` (SPEC §11.9 Invariant 31).
    /// @dev    resolve() uses V1's `ClaimAlreadyResolved` instead per SPEC §6 Phase 3 alignment note.
    error GameAlreadyResolved();

    /// @notice Thrown by challenge() / proveFull() when `claimData.status == FullProved`
    ///         (SPEC §6 Phase 1/3.5 — game already early-finalized; reject for clarity vs ClaimAlreadyChallenged).
    error AlreadyFullProved();

    /// @notice Thrown by challenge() when caller has already countered another segment in this game
    ///         (SPEC §6 Phase 1 per-address dedup; `challengers[msg.sender].countered == true`).
    error AlreadyCountered();

    /// @notice Thrown by challenge() / prove(uint64,bytes) when segment index `k >= numSegments`.
    error IndexOutOfRange();

    /// @notice Thrown by prove(uint64,bytes) when segment k has no challenger (or proveFull was used).
    error IndexNotCountered();

    /// @notice Thrown by prove(uint64,bytes) when segment k has already been successfully proven.
    error AlreadyProved();

    /// @notice Thrown by prove(bytes) early-finalize when claimData.status != Unchallenged.
    error NotUnchallenged();

    /// @notice Thrown by prove(bytes) early-finalize when called after challengeEnd().
    error ChallengeWindowEnded();

    /// @notice Thrown by prove(bytes) when parent game has already resolved CHALLENGER_WINS
    ///         (this game is doomed; off-chain SP1 work would be wasted).
    error ParentAlreadyLost();

    ////////////////////////////////////////////////////////////////
    //                         State Vars                         //
    ////////////////////////////////////////////////////////////////

    /// @notice Upper bound on per-game `numSegments` (SPEC §3, §4 bond economics calibration).
    uint64 internal constant MAX_NUM_SEGMENTS = 256;

    /// @notice Sentinel value for uninitialized `lowestSIndex` (SPEC §6.4.2 lazy compute, §11 Inv 15).
    /// @dev    Solidity-default 0 would be ambiguous with "segment 0 is the lowest"; explicit sentinel required.
    uint64 internal constant LOWEST_S_NOT_SET = type(uint64).max;

    /// @notice The maximum duration allowed for a challenger to challenge a game.
    Duration internal immutable MAX_CHALLENGE_DURATION;

    /// @notice The maximum duration allowed for a proposer to prove against a challenge.
    Duration internal immutable MAX_PROVE_DURATION;

    /// @notice The game type ID.
    GameType internal immutable GAME_TYPE;

    /// @notice The dispute game factory.
    IDisputeGameFactory internal immutable DISPUTE_GAME_FACTORY;

    /// @notice The SP1 verifier.
    ISP1Verifier internal immutable SP1_VERIFIER;

    /// @notice The rollup config hash.
    bytes32 internal immutable ROLLUP_CONFIG_HASH;

    /// @notice The vkey for the aggregation program.
    bytes32 internal immutable AGGREGATION_VKEY;

    /// @notice The 32 byte commitment to the BabyBear representation of the verification key of the range SP1 program. Specifically,
    /// this verification is the output of converting the [u32; 8] range BabyBear verification key to a [u8; 32] array.
    bytes32 internal immutable RANGE_VKEY_COMMITMENT;

    /// @notice The challenger bond for the game. This is the amount of the bond that the
    ///         challenger has to bond to challenge. The prover will receive this bond if they
    ///         provide a valid proof in response to a challenge.
    uint256 internal immutable CHALLENGER_BOND;

    /// @notice The anchor state registry.
    IAnchorStateRegistry internal immutable ANCHOR_STATE_REGISTRY;

    /// @notice The access manager.
    AccessManager internal immutable ACCESS_MANAGER;

    /// @notice Semantic version.
    /// @custom:semver 2.0.0-tz-segment
    string public constant version = "2.0.0-tz-segment";

    /// @notice The starting timestamp of the game.
    Timestamp public createdAt;

    /// @notice The timestamp of the game's global resolution.
    Timestamp public resolvedAt;

    /// @notice The current status of the game.
    GameStatus public status;

    /// @notice Flag for the `initialize` function to prevent re-initialization.
    bool internal initialized;

    /// @notice The claim made by the proposer.
    ClaimData public claimData;

    /// @notice Credited balances for winning participants.
    mapping(address => uint256) public normalModeCredit;

    /// @notice A mapping of each claimant's refund mode credit.
    mapping(address => uint256) public refundModeCredit;

    /// @notice The starting output root of the game that is proven from in case of a challenge.
    /// @dev This should match the claim root of the parent game.
    Proposal public startingOutputRoot;

    /// @notice A boolean for whether or not the game type was respected when the game was created.
    bool public wasRespectedGameTypeWhenCreated;

    /// @notice The bond distribution mode of the game.
    BondDistributionMode public bondDistributionMode;

    ////////////////////////////////////////////////////////////////
    //              Multi-segment / Multi-challenger              //
    //   (SPEC §3 / §6 / §12.3; new vs V1)                        //
    ////////////////////////////////////////////////////////////////

    /// @notice Per-game total batch span = `l2SequenceNumber() - startingOutputRoot.l2SequenceNumber`.
    /// @dev    Decided by proposer at create; `batchSize % numSegments == 0` enforced in initialize.
    uint64 public batchSize;

    /// @notice Per-game segment count chosen by proposer at create.
    /// @dev    Range `[1, MAX_NUM_SEGMENTS]`; derived from CWIA calldata length in initialize.
    ///         SEGMENT_SIZE = batchSize / numSegments (view-derived; not stored).
    uint64 public numSegments;

    /// @notice Total number of segments that have been countered (SPEC §6.4.2 / §9 invariants).
    uint64 public totalCountered;

    /// @notice Total number of countered segments that have been successfully proved.
    uint64 public totalProved;

    /// @notice First-mismatch winner index (smallest k ∈ S set), lazy-computed in claimCredit (SPEC §6.4.2 / §9.5).
    /// @dev    Initialized to LOWEST_S_NOT_SET in initialize; written once on first S-path claimCredit().
    uint64 public lowestSIndex;

    /// @notice Set true when parent-CHW forces game CHW with `totalCountered == 0`
    ///         (SPEC §9.4.b: CREATE_BOND burned to address(0), claimCredit must skip re-distribution).
    bool public createBondPushedAtResolve;

    /// @notice CREATE_BOND amount snapshot, captured from `msg.value` at initialize().
    /// @dev    The factory enforces `msg.value == initBonds(GAME_TYPE)` at create-time, so this
    ///         is the canonical CREATE_BOND for this game. Stored separately from
    ///         `refundModeCredit[gameCreator()]` to avoid creator-as-challenger ledger inflation:
    ///         if the creator also calls `challenge()`, `refundModeCredit[creator]` is +=ed by
    ///         CHAL_BOND and can no longer be used as a CREATE_BOND amount proxy.
    uint256 public createBondAmount;

    /// @notice Per-address challenger registry (multi-challenger dedup + bond tracking).
    mapping(address => ChallengerInfo) public challengers;

    /// @notice Per-segment dispute registry (segment-level dedup + L-bond push + lazy S-settle).
    mapping(uint64 => DisputeEntry) public disputes;

    /// @param _maxChallengeDuration The maximum duration allowed for a challenger to challenge a game.
    /// @param _maxProveDuration The maximum duration allowed for a proposer to prove against a challenge.
    /// @param _disputeGameFactory The factory that creates the dispute games.
    /// @param _sp1Verifier The address of the SP1 verifier that verifies the proof for the aggregation program.
    /// @param _rollupConfigHash The rollup config hash for the L2 network.
    /// @param _aggregationVkey The vkey for the aggregation program.
    /// @param _rangeVkeyCommitment The commitment to the range vkey.
    /// @param _challengerBond The bond amount that must be submitted by the challenger.
    /// @param _anchorStateRegistry The anchor state registry for the L2 network.
    constructor(
        Duration _maxChallengeDuration,
        Duration _maxProveDuration,
        IDisputeGameFactory _disputeGameFactory,
        ISP1Verifier _sp1Verifier,
        bytes32 _rollupConfigHash,
        bytes32 _aggregationVkey,
        bytes32 _rangeVkeyCommitment,
        uint256 _challengerBond,
        IAnchorStateRegistry _anchorStateRegistry,
        AccessManager _accessManager
    ) {
        // Set up initial game state.
        GAME_TYPE = GameType.wrap(OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE);
        MAX_CHALLENGE_DURATION = _maxChallengeDuration;
        MAX_PROVE_DURATION = _maxProveDuration;
        DISPUTE_GAME_FACTORY = _disputeGameFactory;
        SP1_VERIFIER = _sp1Verifier;
        ROLLUP_CONFIG_HASH = _rollupConfigHash;
        AGGREGATION_VKEY = _aggregationVkey;
        RANGE_VKEY_COMMITMENT = _rangeVkeyCommitment;
        CHALLENGER_BOND = _challengerBond;
        ANCHOR_STATE_REGISTRY = _anchorStateRegistry;
        ACCESS_MANAGER = _accessManager;
    }

    /// @notice Initializes the contract.
    /// @dev This function may only be called once.
    function initialize() external payable virtual {
        // SAFETY: Any revert in this function will bubble up to the DisputeGameFactory and
        // prevent the game from being created.
        //
        // Implicit assumptions:
        // - The `gameStatus` state variable defaults to 0, which is `GameStatus.IN_PROGRESS`
        // - The dispute game factory will enforce the required bond to initialize the game.
        //
        // Explicit checks:
        // - The game must not have already been initialized.
        // - An output root cannot be proposed at or before the starting block number.

        // INVARIANT: The game must not have already been initialized.
        if (initialized) revert AlreadyInitialized();

        // INVARIANT: The game can only be initialized by the dispute game factory.
        if (address(DISPUTE_GAME_FACTORY) != msg.sender) revert IncorrectDisputeGameFactory();

        // INVARIANT: The proposer must be whitelisted.
        if (!ACCESS_MANAGER.isAllowedProposer(gameCreator())) revert BadAuth();

        // SPEC §6 Phase 0: dynamic CWIA length + numSegments derivation.
        //
        // CWIA total calldata = 0x7E + 0x20 × (numSegments - 1), so:
        //   - 0x7E minimum  (N=1: no intermediate roots; byte-identical to V1)
        //   - extraRootsLen = calldatasize - 0x7E must be a multiple of 0x20
        //   - numSegments = (extraRootsLen / 0x20) + 1, capped at MAX_NUM_SEGMENTS
        //
        // The strict length match prevents factory-UUID grief described in V1's comment
        // (same proposal cannot be re-created with extra/omitted bytes), while still
        // permitting per-game variable numSegments via the length-→-N derivation.
        uint256 cz;
        assembly { cz := calldatasize() }
        if (cz < 0x7E) revert BadExtraData();
        uint256 extraRootsLen = cz - 0x7E;
        if (extraRootsLen % 0x20 != 0) revert BadExtraData();
        uint64 _numSegments = uint64(extraRootsLen / 0x20) + 1;
        if (_numSegments > MAX_NUM_SEGMENTS) revert InvalidNumSegments(_numSegments);

        // The first game is initialized with a parent index of uint32.max
        if (parentIndex() != type(uint32).max) {
            // For subsequent games, get the parent game's information
            (,, IDisputeGame proxy) = DISPUTE_GAME_FACTORY.gameAtIndex(parentIndex());

            // We perform a subset of AnchorStateRegistry.isGameProper() checks plus isGameRespected():
            // 1. isGameRespected(): Verifies the parent game was respected when it was created.
            //    There's only one respected game type in an AnchorStateRegistry at a time.
            // 2. isGameRetired(): Ensures the game hasn't been retroactively marked as retired.
            // 3. isGameBlacklisted(): Confirms the parent game isn't blacklisted.
            // Note: isGameRegistered() check is skipped since the parent game is coming directly from factory.
            if (
                !ANCHOR_STATE_REGISTRY.isGameRespected(proxy) || ANCHOR_STATE_REGISTRY.isGameBlacklisted(proxy)
                    || ANCHOR_STATE_REGISTRY.isGameRetired(proxy)
            ) {
                revert InvalidParentGame();
            }

            startingOutputRoot = Proposal({
                l2SequenceNumber: TZOPSuccinctFaultDisputeGame(address(proxy)).l2SequenceNumber(),
                root: Hash.wrap(TZOPSuccinctFaultDisputeGame(address(proxy)).rootClaim().raw())
            });

            // INVARIANT: The parent game must be a valid game.
            if (proxy.status() == GameStatus.CHALLENGER_WINS) revert InvalidParentGame();

            // INVARIANT: The parent game's L2 block must be ahead of the anchor. This prevents
            // duplicate games (same startingOutputRoot via parent index vs uint32.max) and ensures
            // that after a game type switch, proposals resume from the anchor rather than a stale parent.
            (, uint256 anchorL2SeqNum) = ANCHOR_STATE_REGISTRY.getAnchorRoot();
            if (startingOutputRoot.l2SequenceNumber <= anchorL2SeqNum) {
                revert InvalidParentGame();
            }
        } else {
            // When there is no parent game, start from the current anchor root. This allows
            // resuming from the latest anchor after game type switches (e.g., retirement recovery).
            (Hash anchorRoot, uint256 anchorL2SeqNum) = ANCHOR_STATE_REGISTRY.getAnchorRoot();
            startingOutputRoot = Proposal({root: anchorRoot, l2SequenceNumber: anchorL2SeqNum});
        }

        // Do not allow the game to be initialized if the root claim corresponds to a block at or before the
        // configured starting block number.
        if (l2SequenceNumber() <= startingOutputRoot.l2SequenceNumber) {
            revert UnexpectedRootClaim(rootClaim());
        }

        // SPEC §6 Phase 0: batchSize derivation + integer divisibility check.
        // batchSize / numSegments must be a positive integer (= SEGMENT_SIZE).
        uint64 _batchSize = uint64(l2SequenceNumber() - startingOutputRoot.l2SequenceNumber);
        if (_batchSize % _numSegments != 0) revert InvalidBatchSize();

        // Set the root claim.
        // SPEC §8.1: proveDeadline is absolute time (never updated), unlike V1's rolling deadline.
        // ClaimData has 5 fields (V1 had 6); `counteredBy` removed (now in disputes[k]).
        claimData = ClaimData({
            prover: address(0),
            proveDeadline: Timestamp.wrap(uint64(
                block.timestamp + MAX_CHALLENGE_DURATION.raw() + MAX_PROVE_DURATION.raw()
            )),
            parentIndex: parentIndex(),
            status: ProposalStatus.Unchallenged,
            claim: rootClaim()
        });

        // Set the game as initialized.
        initialized = true;

        // Deposit the bond.
        refundModeCredit[gameCreator()] += msg.value;
        // Snapshot CREATE_BOND for use as the canonical amount in resolve()/claimCredit() bond
        // pushes — avoids aliasing refundModeCredit[creator], which would be inflated by CHAL_BOND
        // if the creator also calls challenge() (creator-as-challenger).
        createBondAmount = msg.value;

        // Set the game's starting timestamp
        createdAt = Timestamp.wrap(uint64(block.timestamp));

        // Set whether the game type was respected when the game was created.
        wasRespectedGameTypeWhenCreated =
            GameType.unwrap(ANCHOR_STATE_REGISTRY.respectedGameType()) == GameType.unwrap(GAME_TYPE);

        // SPEC §6 Phase 0 step 6+7: multi-segment field writes.
        batchSize = _batchSize;
        numSegments = _numSegments;
        // ★ Solidity default 0 would mis-trigger lazy compute as "already computed, lowest=0";
        //   explicit sentinel required. See SPEC §11 Invariant 15.
        lowestSIndex = LOWEST_S_NOT_SET;
    }

    /// @notice The L2 sequence number (block number) for which this game is proposing an output root.
    function l2SequenceNumber() public pure returns (uint256 l2SequenceNumber_) {
        l2SequenceNumber_ = _getArgUint256(0x54);
    }

    /// @notice The L2 block number for which this game is proposing an output root.
    /// @dev Alias for l2SequenceNumber() for backward compatibility.
    function l2BlockNumber() public pure returns (uint256 l2BlockNumber_) {
        l2BlockNumber_ = l2SequenceNumber();
    }

    /// @notice The parent index of the game.
    function parentIndex() public pure returns (uint32 parentIndex_) {
        parentIndex_ = _getArgUint32(0x74);
    }

    /// @notice Only the starting block number of the game.
    function startingBlockNumber() external view returns (uint256 startingBlockNumber_) {
        startingBlockNumber_ = startingOutputRoot.l2SequenceNumber;
    }

    /// @notice Starting output root of the game.
    function startingRootHash() external view returns (Hash startingRootHash_) {
        startingRootHash_ = startingOutputRoot.root;
    }

    ////////////////////////////////////////////////////////////////
    //                    `IDisputeGame` impl                     //
    ////////////////////////////////////////////////////////////////

    /// @notice The challenge window deadline (immutable-derived view; not stored).
    /// @dev    SPEC §8.1: replaces V1's rolling `claimData.deadline`; absolute time anchored at createdAt.
    ///         Returns `createdAt + MAX_CHALLENGE_DURATION`.
    function challengeEnd() public view returns (Timestamp challengeEnd_) {
        challengeEnd_ = Timestamp.wrap(
            uint64(Timestamp.unwrap(createdAt) + Duration.unwrap(MAX_CHALLENGE_DURATION))
        );
    }

    /// @notice Counter segment `k` (multi-challenger, per-segment dispute mode).
    /// @dev    SPEC §6 Phase 1: each address may counter at most one segment; each segment may be
    ///         countered by at most one address. Bond deposit goes to refundModeCredit; settle
    ///         outcome decided at claimCredit() time (lazy S-path).
    /// @param  k segment index to counter, in `[0, numSegments)`
    function challenge(uint64 k) external payable returns (ProposalStatus) {
        // First-check (SPEC §11.9 Invariant 31): always reject Resolved game with a clear error
        // before considering claimData.status sub-states, so SDK gets unambiguous signal.
        if (status != GameStatus.IN_PROGRESS) revert GameAlreadyResolved();

        // INVARIANT: Cannot counter a game already in FullProved (SPEC §6 Phase 3.5 mutex).
        //   Distinct from ClaimAlreadyChallenged: tells SDK "give up this game" vs "try another segment".
        if (claimData.status == ProposalStatus.FullProved) revert AlreadyFullProved();
        // After first-check (Resolved rejected) + FullProved branch, claimData.status ∈ {Unchallenged, Challenged};
        // both are valid to add another challenger on a different segment.

        // INVARIANT: Must be within the challenge window.
        //   SPEC §8.1: challengeEnd is derived view (createdAt + MAX_CHAL_DUR), not stored.
        if (block.timestamp >= Timestamp.unwrap(challengeEnd())) revert ClockTimeExceeded();

        // INVARIANT: The challenger must be whitelisted.
        if (!ACCESS_MANAGER.isAllowedChallenger(msg.sender)) revert BadAuth();

        // If the required bond is not met, revert.
        if (msg.value != CHALLENGER_BOND) revert IncorrectBondAmount();

        // INVARIANT (SPEC §6 Phase 1): each address may counter at most one segment per game.
        if (challengers[msg.sender].countered) revert AlreadyCountered();

        // INVARIANT: segment index must be in range.
        if (k >= numSegments) revert IndexOutOfRange();

        // INVARIANT (SPEC §6 Phase 1): each segment may be countered by at most one address (index dedup).
        if (disputes[k].counteredBy != address(0)) revert ClaimAlreadyChallenged();

        // Effects: per-address registry, per-segment registry, deposit ledger, counter, status advance.
        challengers[msg.sender] = ChallengerInfo({
            bond: CHALLENGER_BOND,
            countered: true,
            counteredIndex: k
        });

        // Only write the non-zero field; `proved`, `claimed`, `provedBy` stay at their slot-zero
        // defaults (struct-literal init would force a second SSTORE on the still-zero second slot).
        disputes[k].counteredBy = msg.sender;

        refundModeCredit[msg.sender] += msg.value;
        totalCountered += 1;

        // Status advance (idempotent within multi-challenger): first challenger flips Unchallenged → Challenged;
        // subsequent ones leave it Challenged.
        if (claimData.status == ProposalStatus.Unchallenged) {
            claimData.status = ProposalStatus.Challenged;
        }

        // Note: V1 wrote `claimData.deadline = block.timestamp + MAX_PROVE_DURATION` here (rolling).
        // SPEC §8.1: proveDeadline is absolute, set once at initialize; challenge() never updates it.

        emit Challenged(msg.sender, k);

        return claimData.status;
    }

    /// @notice Prove a single segment k (per-segment SP1 STF proof). SPEC §6 Phase 2.
    /// @dev    Permissionless prover. msg.sender is committed to the SP1 public input as
    ///         `proverAddress` (frontrun protection — replaying another prover's proof bytes
    ///         with a different msg.sender fails SP1 verify). L bond (CHALLENGER_BOND) is
    ///         immediately pushed to msg.sender's normalModeCredit at Step 4.
    /// @param  k          segment index, must satisfy `disputes[k].counteredBy != 0 ∧ !proved`
    /// @param  proofBytes SP1 aggregation proof bytes (raw, not abi-encoded struct)
    function prove(uint64 k, bytes calldata proofBytes) external returns (ProposalStatus) {
        // First-check (SPEC §11.9 Invariant 31).
        if (status != GameStatus.IN_PROGRESS) revert GameAlreadyResolved();

        // FullProved gets a specific revert (clarity for SDKs); Unchallenged falls through to
        // the per-segment `disputes[k].counteredBy == 0` check below, which returns the same
        // IndexNotCountered error.
        if (claimData.status == ProposalStatus.FullProved) revert AlreadyFullProved();

        // INVARIANT: Must be within the prove window.
        if (block.timestamp >= Timestamp.unwrap(claimData.proveDeadline)) revert ClockTimeExceeded();

        // INVARIANT: segment index in range.
        if (k >= numSegments) revert IndexOutOfRange();

        // INVARIANT: segment must have a challenger to be provable.
        DisputeEntry storage d = disputes[k];
        if (d.counteredBy == address(0)) revert IndexNotCountered();

        // INVARIANT: segment not yet proven (defends against double L-bond push).
        if (d.proved) revert AlreadyProved();

        // Step 1 — derive claimPre = boundary[k].
        //   SPEC §7: intermediateRoot(i) = boundary[i+1] for i ∈ [0, N-2];
        //   boundary[0] = startingOutputRoot.root; boundary[N] = rootClaim().
        bytes32 claimPre;
        if (k == 0) {
            claimPre = Hash.unwrap(startingOutputRoot.root);
        } else {
            claimPre = intermediateRoot(k - 1);
        }

        // Step 2 — derive claimPost = boundary[k+1].
        bytes32 claimPost;
        if (k == numSegments - 1) {
            claimPost = Claim.unwrap(rootClaim());
        } else {
            claimPost = intermediateRoot(k);
        }

        // Step 3 — verify the SP1 aggregation proof against derived public input.
        //   claimBlockNum = startingOutputRoot.l2SequenceNumber + SEGMENT_SIZE * (k + 1)
        //   where SEGMENT_SIZE = batchSize / numSegments (derived per call; cheap uint64 div).
        uint64 _segSize = batchSize / numSegments;
        AggregationOutputs memory publicValues = AggregationOutputs({
            l1Head: bytes32(0), // TZ: no L1 derivation; sp1-range-program hardcodes 0
            l2PreRoot: claimPre,
            claimRoot: claimPost,
            claimBlockNum: uint256(uint64(startingOutputRoot.l2SequenceNumber) + _segSize * (k + 1)),
            rollupConfigHash: ROLLUP_CONFIG_HASH,
            rangeVkeyCommitment: RANGE_VKEY_COMMITMENT,
            proverAddress: msg.sender
        });
        SP1_VERIFIER.verifyProof(AGGREGATION_VKEY, abi.encode(publicValues), proofBytes);

        // Step 4 — mark proved + push L bond immediately to msg.sender (SPEC §6 Phase 2 Step 4).
        //   Note: only clear challengers[challenger].bond field — keep `countered` flag so
        //   challenger cannot re-challenge another segment.
        d.proved = true;
        d.provedBy = msg.sender;
        totalProved += 1;

        address challenger = d.counteredBy;
        uint256 lBond = challengers[challenger].bond;
        challengers[challenger].bond = 0;
        normalModeCredit[msg.sender] += lBond;

        emit Proved(msg.sender, k);

        return claimData.status;
    }

    /// @notice Optional early-finalize: prove the entire batch in one SP1 proof. SPEC §6 Phase 3.5.
    /// @dev    Solidity overload of `prove`; selector `prove(bytes)` matches V1 exactly so tools
    ///         (etherscan, debug tracers) render this as V1's well-known prove call. Semantically
    ///         equivalent to V1's "prove (Unchallenged → U+VP)" branch but only fires when no
    ///         challenger has appeared.
    ///
    ///         2-step pattern (like V1 and Base): this call only verifies the proof and marks
    ///         `claimData.status = FullProved`; subsequent `resolve()` consumes the marker.
    ///
    ///         Permissionless caller. NO bond required. NO on-chain reward (motivation is
    ///         downstream finality speed; see SPEC §6.1.3).
    /// @param  proofBytes SP1 aggregation proof over the entire batch (claimBlockNum = startingSeq + batchSize)
    function prove(bytes calldata proofBytes) external {
        // First-check (SPEC §11.9 Invariant 31).
        if (status != GameStatus.IN_PROGRESS) revert GameAlreadyResolved();

        // Per-state revert mapping (SPEC §6 Phase 3.5). After these checks, status is
        // necessarily Unchallenged (Resolved already caught by first-check above), which by
        // Invariant 11 implies totalCountered == 0 — no defensive recheck needed.
        if (claimData.status == ProposalStatus.FullProved) revert AlreadyFullProved();
        if (claimData.status == ProposalStatus.Challenged) revert NotUnchallenged();

        if (block.timestamp >= Timestamp.unwrap(challengeEnd())) revert ChallengeWindowEnded();

        // Parent-CHW preflight (SPEC §6 Phase 3.5 M3): if parent already resolved CHW, this
        // game is doomed to burn via §9.4.b; reject the proveFull tx so off-chain SP1 work
        // isn't wasted on a guaranteed-lose game. (Does not protect against race where
        // proveFull lands first then parent CHW lands second.)
        if (getParentGameStatus() == GameStatus.CHALLENGER_WINS) revert ParentAlreadyLost();

        // Step 1 — derive full-batch public input. claimBlockNum = startingSeq + batchSize.
        AggregationOutputs memory publicValues = AggregationOutputs({
            l1Head: bytes32(0), // TZ: no L1 derivation
            l2PreRoot: Hash.unwrap(startingOutputRoot.root),
            claimRoot: Claim.unwrap(rootClaim()),
            claimBlockNum: uint256(uint64(startingOutputRoot.l2SequenceNumber) + batchSize),
            rollupConfigHash: ROLLUP_CONFIG_HASH,
            rangeVkeyCommitment: RANGE_VKEY_COMMITMENT,
            proverAddress: msg.sender
        });
        SP1_VERIFIER.verifyProof(AGGREGATION_VKEY, abi.encode(publicValues), proofBytes);

        // Step 2 — mark FullProved. Does NOT touch `status` (GameStatus); resolve() does that.
        claimData.status = ProposalStatus.FullProved;
        claimData.prover = msg.sender;

        emit FullProved(msg.sender);
    }

    /// @notice Returns the status of the parent game.
    /// @dev If the parent game index is `uint32.max`, then the parent game's status is considered as `DEFENDER_WINS`.
    function getParentGameStatus() private view returns (GameStatus) {
        if (parentIndex() != type(uint32).max) {
            (,, IDisputeGame parentGame) = DISPUTE_GAME_FACTORY.gameAtIndex(parentIndex());
            return parentGame.status();
        } else {
            // If this is the first dispute game (i.e. parent game index is `uint32.max`), then the
            // parent game's status is considered as `DEFENDER_WINS`.
            return GameStatus.DEFENDER_WINS;
        }
    }

    /// @notice Resolves the game per SPEC §6 Phase 3 — 4-state machine + parent-CHW propagation.
    /// @dev    Bond push at resolve:
    ///           - DW path (3 sub-states converge): proposer gets CREATE_BOND back to normalModeCredit.
    ///             L-bonds are NOT pushed here — they were already credited to provers in prove() Step 4.
    ///           - CHW path (clock-CHW): no immediate push; CREATE_BOND + non-lowest S-bonds settled
    ///             lazily in claimCredit() (SPEC §6.4.2, §9.5).
    ///           - parent-CHW path + totalCountered == 0: CREATE_BOND burned to address(0), flag set
    ///             to suppress duplicate distribution in claimCredit (SPEC §9.4.b).
    ///           - parent-CHW path + totalCountered > 0: no immediate push; CREATE_BOND goes to
    ///             lowest-S challenger via lazy claimCredit (same as clock-CHW).
    function resolve() external returns (GameStatus) {
        // First-check (SPEC §11.9 Inv 31): resolve uses V1's ClaimAlreadyResolved alias here,
        // not the new GameAlreadyResolved error used by challenge/prove (deliberate V1 alignment).
        if (status != GameStatus.IN_PROGRESS) revert ClaimAlreadyResolved();

        // Parent integrity (UNCHANGED from V1):
        //   parent IN_PROGRESS → revert (must wait); CHW → propagate; DW → normal path.
        GameStatus parentGameStatus = getParentGameStatus();
        if (parentGameStatus == GameStatus.IN_PROGRESS) revert ParentGameNotResolved();

        if (parentGameStatus == GameStatus.CHALLENGER_WINS) {
            // SPEC §9.4.b parent-forced CHW:
            //   This game's startingOutputRoot derives from an invalid parent chain → game is doomed.
            //   Override outcome to CHW regardless of internal state (incl. FullProved); bypass gameOver().
            status = GameStatus.CHALLENGER_WINS;

            // CREATE_BOND disposal under parent-CHW. Two burn sub-cases collapse to the single
            // condition `totalProved == totalCountered` (covers 0==0 and N==N for N>0):
            //   - totalCountered == 0 (Unchallenged / FullProved): no challenger to receive it
            //     (SPEC §9.4.b original burn case).
            //   - totalCountered > 0 && totalProved == totalCountered (S == ∅): the claimCredit
            //     lazy lowest-S compute would never run (it's gated on `!d.proved`), so the
            //     non-burn fallthrough would strand CREATE_BOND forever. Extend §9.4.b to burn
            //     here too — spec didn't anticipate this case, code-review #2 finding.
            // Else (totalCountered > 0 && totalProved < totalCountered, S != ∅): lazy compute
            // will pick lowest-S winner in claimCredit (SPEC §9.4.a fallthrough).
            //
            // NOTE: we do NOT zero refundModeCredit[gameCreator()] here. The burn lands in
            // normalModeCredit[address(0)] which is only paid out under NORMAL mode (nobody can
            // claim from address(0) → effective burn). Under REFUND mode (ASR.isGameProper=false,
            // governance override), all original deposits return to depositors regardless of
            // resolve outcome — this matches V1 baseline behavior and the REFUND-mode-as-
            // emergency-rollback semantics. See SPEC §9.4.b NOTE on REFUND-mode override.
            if (totalProved == totalCountered) {
                normalModeCredit[address(0)] += createBondAmount;
                createBondPushedAtResolve = true;
            }

            resolvedAt = Timestamp.wrap(uint64(block.timestamp));
            claimData.status = ProposalStatus.Resolved;
            emit Resolved(GameStatus.CHALLENGER_WINS);
            return GameStatus.CHALLENGER_WINS;
        }

        // Parent DEFENDER_WINS → normal path. Game must be over (challenge/prove phase closed).
        if (!gameOver()) revert GameNotOver();

        // SPEC §6 Phase 3: 4-state branch on claimData.status. CREATE_BOND amount captured in
        // initialize and stored in `createBondAmount` (NOT read from refundModeCredit[creator],
        // which is +=ed by challenge() under creator-as-challenger).
        address creator = gameCreator();
        TZOPSuccinctFaultDisputeGame.ProposalStatus s = claimData.status;
        uint256 createBond = createBondAmount;

        // Unchallenged + FullProved converge to the same DW bond flow:
        //   Unchallenged: gameOver() ensured block.timestamp >= challengeEnd() (clock-expiry)
        //   FullProved:   gameOver() short-circuit gave eligibility before challengeEnd
        // Either way: no challenger → CREATE_BOND back to proposer; no L-bonds (none pushed).
        if (s == ProposalStatus.Unchallenged || s == ProposalStatus.FullProved) {
            status = GameStatus.DEFENDER_WINS;
            normalModeCredit[creator] += createBond;
        } else if (s == ProposalStatus.Challenged) {
            // gameOver() ensured block.timestamp >= proveDeadline.
            if (totalProved == totalCountered) {
                // All challenged segments proved → DW; CREATE_BOND to proposer.
                // L-bonds already pushed to provers in prove() Step 4.
                status = GameStatus.DEFENDER_WINS;
                normalModeCredit[creator] += createBond;
            } else {
                // ≥1 unproved → CHW. CREATE_BOND held in contract until claimCredit() lazy compute
                // picks the lowest-S challenger (SPEC §6.4.2, §9.4.a winner-takes-all).
                status = GameStatus.CHALLENGER_WINS;
            }
        } else {
            // Resolved status is impossible here (first-check already rejected); sanity revert.
            revert InvalidProposalStatus();
        }

        // Mark the game as resolved (final state).
        claimData.status = ProposalStatus.Resolved;
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));
        emit Resolved(status);

        return status;
    }

    /// @notice Unified claim-credit entry for all roles. SPEC §6.4.2.
    /// @dev    Roles & behavior:
    ///           - proposer:    skips settle block; reads normalModeCredit[gameCreator()] populated by resolve() DW
    ///           - S challenger (lowest, CHW): settle block pushes CHAL_BOND + CREATE_BOND; lazy compute lowestSIndex on first invocation
    ///           - S challenger (non-lowest, CHW): settle block pushes only CHAL_BOND
    ///           - L challenger (proved):  settle block detects d.proved == true and is a no-op (L bond was already pushed to provedBy in prove())
    ///           - pure prover (non-challenger): skips settle block; reads accumulated L bonds pushed in prove() Step 4
    ///           - REFUND mode: all roles read refundModeCredit (original deposit) and bypass settle block entirely
    ///
    ///         CEI ordering: all ledger writes (settle block + zero-out) precede the external `_transfer` call.
    ///         Reentrancy on the same recipient is safe because normalModeCredit[_recipient] is zeroed
    ///         before _transfer, so a recursive call hits NoCreditToClaim.
    /// @param _recipient The owner of the credit to be paid out.
    function claimCredit(address _recipient) external {
        // Lazy mode gating: idempotent — already-closed games short-circuit inside closeGame().
        closeGame();

        // REFUND mode: simple path, no settle. Refund original deposit.
        // Zero BOTH ledgers (matches V1 OPSuccinctFaultDisputeGame.sol:521-522) — `normalModeCredit`
        // may be non-zero in REFUND mode (e.g., prove() Step 4 push or resolve() DW credit landed
        // before closeGame() decided REFUND). Clearing the ghost entry keeps ledger views consistent
        // for audits / off-chain indexers, and aligns with the SPEC §9.4.b principle that all
        // NORMAL-mode ledger writes are invalidated under REFUND-mode override.
        if (bondDistributionMode == BondDistributionMode.REFUND) {
            uint256 refund = refundModeCredit[_recipient];
            if (refund == 0) revert NoCreditToClaim();
            refundModeCredit[_recipient] = 0;
            normalModeCredit[_recipient] = 0;
            (bool ok,) = _recipient.call{value: refund}(hex"");
            if (!ok) revert BondTransferFailed();
            return;
        }

        // NORMAL mode (proper game). If recipient is an S-path challenger whose segment hasn't been
        // proved AND hasn't been settled yet, lazily push CHAL_BOND back + (if winner) CREATE_BOND.
        // Use storage pointer to amortize ChallengerInfo SLOADs.
        ChallengerInfo storage ci = challengers[_recipient];
        if (ci.countered) {
            uint64 k = ci.counteredIndex;
            DisputeEntry storage d = disputes[k];
            if (!d.proved && !d.claimed) {
                d.claimed = true;
                uint256 selfBond = ci.bond;
                ci.bond = 0;
                normalModeCredit[_recipient] += selfBond;

                // CHW + not already burned → push CREATE_BOND to the lowest-S challenger (winner-takes-all).
                // SPEC §9.4.b burn case sets createBondPushedAtResolve in resolve(); skip here.
                if (status == GameStatus.CHALLENGER_WINS && !createBondPushedAtResolve) {
                    // Lazy compute lowestSIndex on the first S-path claimCredit invocation.
                    // Bounded by numSegments ≤ MAX_NUM_SEGMENTS = 256; worst-case ~540k gas.
                    if (lowestSIndex == LOWEST_S_NOT_SET) {
                        uint64 n = numSegments; // hoist out of loop to avoid per-iter SLOAD
                        uint64 found = LOWEST_S_NOT_SET;
                        for (uint64 j = 0; j < n; j++) {
                            DisputeEntry storage dj = disputes[j];
                            if (dj.counteredBy != address(0) && !dj.proved) {
                                found = j;
                                break;
                            }
                        }
                        // S = ∅ && CHW is unreachable (resolve() CHW path requires totalProved < totalCountered).
                        // Use assert: surfaces as Panic, distinguishes implementation bug from user error.
                        assert(found != LOWEST_S_NOT_SET);
                        lowestSIndex = found;
                    }
                    if (k == lowestSIndex) {
                        // CREATE_BOND amount captured in initialize. Must NOT read
                        // refundModeCredit[gameCreator()] (inflated by CHAL_BOND under
                        // creator-as-challenger — see createBondAmount natspec).
                        normalModeCredit[_recipient] += createBondAmount;
                    }
                }
            }
            // L-path (d.proved) or already-settled (d.claimed) → no-op; transfer below picks up
            // whatever was pushed elsewhere (L bond push happened in prove() Step 4 if applicable).
        }

        // Final transfer (matches V1's local var name to avoid shadowing the `credit()` view).
        uint256 recipientCredit = normalModeCredit[_recipient];
        if (recipientCredit == 0) revert NoCreditToClaim();
        refundModeCredit[_recipient] = 0;
        normalModeCredit[_recipient] = 0;
        (bool success,) = _recipient.call{value: recipientCredit}(hex"");
        if (!success) revert BondTransferFailed();
    }

    /// @notice Closes out the game, determines the bond distribution mode, attempts to register
    ///         the game as the anchor game, and emits an event.
    function closeGame() public {
        // If the bond distribution mode has already been determined, we can return early.
        if (bondDistributionMode == BondDistributionMode.REFUND || bondDistributionMode == BondDistributionMode.NORMAL)
        {
            // We can't revert or we'd break claimCredit().
            return;
        } else if (bondDistributionMode != BondDistributionMode.UNDECIDED) {
            // We shouldn't get here, but sanity check just in case.
            revert InvalidBondDistributionMode();
        }

        // Game must be finalized according to the AnchorStateRegistry.
        bool finalized = ANCHOR_STATE_REGISTRY.isGameFinalized(IDisputeGame(address(this)));
        if (!finalized) {
            revert GameNotFinalized();
        }

        // Try to update the anchor game first. Won't always succeed because delays can lead
        // to situations in which this game might not be eligible to be a new anchor game.
        try ANCHOR_STATE_REGISTRY.setAnchorState(IDisputeGame(address(this))) {} catch {}

        // Check if the game is a proper game, which will determine the bond distribution mode.
        bool properGame = ANCHOR_STATE_REGISTRY.isGameProper(IDisputeGame(address(this)));

        // If the game is a proper game, the bonds should be distributed normally. Otherwise, go
        // into refund mode and distribute bonds back to their original depositors.
        if (properGame) {
            bondDistributionMode = BondDistributionMode.NORMAL;
        } else {
            bondDistributionMode = BondDistributionMode.REFUND;
        }

        // Emit an event to signal that the game has been closed.
        emit GameClosed(bondDistributionMode);
    }

    /// @notice Determines if the game's challenge/prove phase is closed (mutators may no longer be called).
    /// @dev    SPEC §12.6.1: 4-state machine; positive enumeration. Does NOT imply final outcome —
    ///         that is determined by resolve(). Used as gate by resolve()'s !gameOver() check and
    ///         as the V1-compatible "phase closed" signal.
    /// @return True iff Resolved (terminal), FullProved (early-finalize marker), or relevant clock expired.
    function gameOver() public view returns (bool) {
        ProposalStatus s = claimData.status;
        if (s == ProposalStatus.Resolved) return true;
        if (s == ProposalStatus.FullProved) return true; // SPEC §6 Phase 3.5 short-circuit
        if (s == ProposalStatus.Unchallenged) {
            // No challenger landed: phase closes at challengeEnd (immutable-derived view).
            return block.timestamp >= Timestamp.unwrap(challengeEnd());
        }
        // s == Challenged: two terminal triggers
        //   (a) Early-finalize: challengeEnd passed (no new challengers possible) AND
        //       all challenged segments proved (totalProved == totalCountered). Saves up to
        //       MAX_PROVE_DURATION of waiting when defense is complete.
        //       ⚠ challengeEnd guard is MANDATORY: without it, an early `totalProved ==
        //       totalCountered` window in [challenge window] would let resolve() race ahead
        //       and revoke other challengers' right to counter further segments.
        //   (b) Normal timeout: proveDeadline reached (some segments unproved → CHW path).
        if (block.timestamp >= Timestamp.unwrap(challengeEnd()) && totalProved == totalCountered) {
            return true;
        }
        return block.timestamp >= Timestamp.unwrap(claimData.proveDeadline);
    }

    /// @notice Getter for the game type.
    /// @dev The reference impl should be entirely different depending on the type (fault, validity)
    ///      i.e. The game type should indicate the security model.
    /// @return gameType_ The type of proof system being used.
    function gameType() public view returns (GameType gameType_) {
        gameType_ = GAME_TYPE;
    }

    /// @notice Getter for the creator of the dispute game.
    /// @dev `clones-with-immutable-args` argument #1
    /// @return creator_ The creator of the dispute game.
    function gameCreator() public pure returns (address creator_) {
        creator_ = _getArgAddress(0x00);
    }

    /// @notice Getter for the root claim.
    /// @dev `clones-with-immutable-args` argument #2
    /// @return rootClaim_ The root claim of the DisputeGame.
    function rootClaim() public pure returns (Claim rootClaim_) {
        rootClaim_ = Claim.wrap(_getArgBytes32(0x14));
    }

    /// @notice Getter for the parent hash of the L1 block when the dispute game was created.
    /// @dev `clones-with-immutable-args` argument #3
    /// @return l1Head_ The parent hash of the L1 block when the dispute game was created.
    function l1Head() public pure returns (Hash l1Head_) {
        l1Head_ = Hash.wrap(_getArgBytes32(0x34));
    }

    /// @notice Getter for the extra data.
    /// @dev `clones-with-immutable-args` argument #4
    /// @dev SPEC §3.4: total extraData length is `0x24 + 0x20 × (numSegments - 1)` — a fixed
    ///      36-byte header (l2SequenceNumber + parentIndex) followed by `numSegments - 1`
    ///      intermediate roots (32 bytes each).
    ///
    ///      Kept `pure` (matches IDisputeGame interface) by deriving length from `calldatasize()`
    ///      rather than storage `numSegments`. Layout:
    ///        calldatasize = 4 (selector) + 0x78 (fixed CWIA args) + 0x20 × (N-1) (intermediates) + 2 (CWIA suffix)
    ///        extraData length = calldatasize - 4 - 2 - 0x54 = calldatasize - 0x5A
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function extraData() public pure returns (bytes memory extraData_) {
        uint256 cz;
        assembly { cz := calldatasize() }
        extraData_ = _getArgBytes(0x54, cz - 0x5A);
    }

    /// @notice Read the k-th intermediate boundary root from CWIA calldata (0-indexed).
    /// @dev    SPEC §3.4 / §7: `intermediateRoot(i) = boundary[i+1]` for i ∈ [0, numSegments-2].
    ///         Endpoints excluded: boundary[0] = startingOutputRoot.root (storage),
    ///         boundary[numSegments] = rootClaim() (CWIA standard arg #2). View (not pure) because
    ///         bound check reads storage `numSegments`.
    /// @param  k 0-indexed intermediate root, must satisfy `k < numSegments - 1`
    function intermediateRoot(uint64 k) public view returns (bytes32 root_) {
        // Invariant: numSegments >= 1 by initialize() check. When numSegments == 1, this always reverts.
        if (k >= numSegments - 1) revert IndexOutOfRange();
        // CWIA layout: intermediate roots start at offset 0x78 (after creator+rootClaim+l1Head+l2SeqNum+parentIndex).
        // Each root is 32 bytes; k-th root sits at 0x78 + 0x20 * k.
        root_ = _getArgBytes32(0x78 + 0x20 * uint256(k));
    }

    /// @notice Bulk read all intermediate boundary roots in a single call.
    /// @dev    SPEC §3.4: returns `numSegments - 1` 32-byte roots packed; empty bytes when numSegments == 1.
    ///         Off-chain SDKs prefer this over repeated `intermediateRoot(k)` calls to save RPC round-trips.
    /// @return roots_ Concatenated 32-byte intermediate roots in 0-indexed order.
    function intermediateRoots() external view returns (bytes memory roots_) {
        if (numSegments <= 1) return new bytes(0);
        roots_ = _getArgBytes(0x78, 0x20 * (uint256(numSegments) - 1));
    }

    /// @notice Segment size derived from per-game `batchSize` and `numSegments`.
    /// @dev    SPEC §3: not stored; computed lazily. By initialize() invariants this is always
    ///         a positive integer (batchSize % numSegments == 0; batchSize >= numSegments).
    function segmentSize() external view returns (uint64 segmentSize_) {
        segmentSize_ = batchSize / numSegments;
    }

    /// @notice A compliant implementation of this interface should return the components of the
    ///         game UUID's preimage provided in the cwia payload. The preimage of the UUID is
    ///         constructed as `keccak256(gameType . rootClaim . extraData)` where `.` denotes
    ///         concatenation.
    /// @return gameType_ The type of proof system being used.
    /// @return rootClaim_ The root claim of the DisputeGame.
    /// @return extraData_ Any extra data supplied to the dispute game contract by the creator.
    function gameData() external view returns (GameType gameType_, Claim rootClaim_, bytes memory extraData_) {
        gameType_ = gameType();
        rootClaim_ = rootClaim();
        extraData_ = extraData();
    }

    ////////////////////////////////////////////////////////////////
    //                       MISC EXTERNAL                        //
    ////////////////////////////////////////////////////////////////

    /// @notice Returns the credit balance of a given recipient.
    /// @param _recipient The recipient of the credit.
    /// @return credit_ The credit balance of the recipient.
    function credit(address _recipient) external view returns (uint256 credit_) {
        if (bondDistributionMode == BondDistributionMode.REFUND) {
            credit_ = refundModeCredit[_recipient];
        } else {
            // Always return normal credit balance by default unless in refund mode.
            credit_ = normalModeCredit[_recipient];
        }
    }

    ////////////////////////////////////////////////////////////////
    //                     IMMUTABLE GETTERS                      //
    ////////////////////////////////////////////////////////////////

    /// @notice Returns the max challenge duration.
    function maxChallengeDuration() external view returns (Duration maxChallengeDuration_) {
        maxChallengeDuration_ = MAX_CHALLENGE_DURATION;
    }

    /// @notice Returns the max clock duration.
    /// @dev Compatibility alias for maxChallengeDuration to match the standard FaultDisputeGame interface.
    function maxClockDuration() external view returns (Duration maxClockDuration_) {
        maxClockDuration_ = MAX_CHALLENGE_DURATION;
    }

    /// @notice Returns the max prove duration.
    function maxProveDuration() external view returns (Duration maxProveDuration_) {
        maxProveDuration_ = MAX_PROVE_DURATION;
    }

    /// @notice Returns the dispute game factory.
    function disputeGameFactory() external view returns (IDisputeGameFactory disputeGameFactory_) {
        disputeGameFactory_ = DISPUTE_GAME_FACTORY;
    }

    /// @notice Returns the SP1 verifier contract.
    function sp1Verifier() external view returns (ISP1Verifier verifier_) {
        verifier_ = SP1_VERIFIER;
    }

    /// @notice Returns the rollup config hash.
    function rollupConfigHash() external view returns (bytes32 rollupConfigHash_) {
        rollupConfigHash_ = ROLLUP_CONFIG_HASH;
    }

    /// @notice Returns the aggregation vkey.
    function aggregationVkey() external view returns (bytes32 aggregationVkey_) {
        aggregationVkey_ = AGGREGATION_VKEY;
    }

    /// @notice Returns the range vkey commitment.
    function rangeVkeyCommitment() external view returns (bytes32 rangeVkeyCommitment_) {
        rangeVkeyCommitment_ = RANGE_VKEY_COMMITMENT;
    }

    /// @notice Returns the challenger bond amount.
    function challengerBond() external view returns (uint256 challengerBond_) {
        challengerBond_ = CHALLENGER_BOND;
    }

    /// @notice Returns the anchor state registry contract.
    function anchorStateRegistry() external view returns (IAnchorStateRegistry registry_) {
        registry_ = ANCHOR_STATE_REGISTRY;
    }

    /// @notice Returns the access manager contract.
    function accessManager() external view returns (AccessManager accessManager_) {
        accessManager_ = ACCESS_MANAGER;
    }
}
