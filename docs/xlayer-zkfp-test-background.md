# X Layer Testnet ZK Fault Proof Upgrade — Test Background and Requirements

## 1. Project Background

X Layer testnet has completed the upgrade from the standard OP Stack Cannon interactive fraud proof to OP Succinct ZK fault proof. Core changes:

- **Before**: When challenged, disputes were resolved on L1 through Cannon interactive proofs (multi-round bisection)
- **After**: When challenged, SP1 ZKVM generates a Groth16 SNARK proof, which is verified on L1 in a single step

The upgrade scope only replaced the game implementation registered in DisputeGameFactory (type 42), **without replacing the Factory itself**. The old Cannon game type (type 1) is still preserved in the Factory, with impl address `0x34f0482A8F7B91F8C9346A9cCA705Ba8aC9A1CE3`.

## 2. Architecture Overview

```
Proposer Service                 Challenger Service
    |                                |
    | Creates game every 3600 blocks | Monitors game validity
    v                                v
DisputeGameFactory --creates--> OPSuccinctFaultDisputeGame
                                     |
                          +----------+----------+
                          |                     |
                     When challenged         No challenge
                          |                     |
                          v                     v
                   SP1 Prover Network      Wait for deadline to expire (1hr)
                   Generates Groth16 proof      |
                          |                     v
                          v               resolve() --> DEFENDER_WINS
                   prove() --> SP1Verifier           |
                   On-chain proof verification       v
                          |               closeGame() --> claimCredit()
                          v
                   resolve() --> Distribute bond based on result
                          |
                          v
                   closeGame() --> claimCredit()
```

**resolve() precondition**: The parent game must already be resolved (otherwise reverts with `ParentGameNotResolved`). If the parent game's result is `CHALLENGER_WINS`, the current game will cascade-fail.

## 3. Contract Addresses (Sepolia)

| Contract | Address | Description |
|----------|---------|-------------|
| OptimismPortal2 | `0x1529a34331d7d85c8868fc88ec730ae56d3ec9c0` | L1 portal, manages withdrawal and respectedGameType |
| DisputeGameFactory | `0x80388586ab4580936BCb409Cc2dC6BC0221e1B6F` | Creates game instances, reuses existing ones |
| AnchorStateRegistry | `0x1A8DFc1d6ccfB3bE886b2539823539a9DC0956a5` | Tracks finalized anchor state |
| Game Implementation | `0xfDF25E39F0c0C131905e4b72Dd65620a88F19236` | OPSuccinctFaultDisputeGame v2.0.0 |
| SP1Verifier | `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B` | Real Groth16 verifier |
| AccessManager | `0x33D211daB418F65Ca71035055bCF557808aCa13f` | Manages proposer/challenger whitelist |
| SystemConfig | `0x06BE4b4A9a28fF8EED6da09447Bc5DAA676efac3` | L2 rollup system configuration |

### Permissions and Management Addresses

| Role | Address |
|------|---------|
| AccessManager Owner | `0xA14a8bFf55bC15A64961393a0CdE1F90D1aF5B5A` |
| Guardian / Deployer | `0x11CAA37c9e9Da2621bB45Af77cB7debEE3881d2E` |
| Factory Owner (Transactor) | `0xaFf1B5870f6444eEeCcC5044dD78D8617d1c8e50` |
| Proposer (whitelisted) | `0x829D57F38D2A94514a3dbA2297fDD1Bc52bB1938` |
| Challenger (whitelisted) | `0x7c3787bf0d78a9e2f802916110e4ddd6e3ed262c` |

## 4. Key Contract Parameters (On-chain Verified)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Game Type | 42 (`OP_SUCCINCT_FAULT_DISPUTE_GAME_TYPE`) | Game type registered in Factory |
| MAX_CHALLENGE_DURATION | 3600 seconds (1 hour) | Challenge window: after game creation, challenger can initiate a challenge within this period |
| MAX_PROVE_DURATION | 604800 seconds (7 days) | After being challenged, proposer must submit ZK proof within this period |
| CHALLENGER_BOND | 10 Gwei (1e10 wei) | Bond required from the challenger |
| Proposer InitBond | 10 Gwei (1e10 wei) | Bond required from the proposer when creating a game (Factory configuration) |
| FALLBACK_TIMEOUT | 604800 seconds (7 days) | After timeout, enters permissionless propose mode |
| disputeGameFinalityDelaySeconds | 12600 seconds (3.5 hours) | After resolve, must wait this duration before finalization, then closeGame/claimCredit becomes possible |
| proofMaturityDelaySeconds | 25200 seconds (7 hours) | Portal withdrawal proof maturity delay |
| PROPOSAL_INTERVAL_IN_BLOCKS | 3600 | Proposer service submission interval (L2 blocks) |
| Fast Finality Mode | Off | Proposer service configuration, currently not enabled |
| DA Layer | Ethereum (Blob) | Range Program uses ethereum variant |
| respectedGameType | 42 | Both Portal and ASR are set to 42 (ZK fault proof) |

### Verification Keys (On-chain Verified)

| Parameter | Value |
|-----------|-------|
| aggregationVkey | `0x00a5efc95e5805e27488095a6aae484ec66cd67ca32f32e7f3c2fb744daeff1b` |
| rangeVkeyCommitment | `0x773d89f231d4c62d6ab68d171777f72a28c056e8366e07694d91c99530dceaab` |
| rollupConfigHash | `0x3ed3598c92b6cd8bc44d3dba15ab51beb45bfd0093dcaf998a659a9ad1dcc851` |

### Current On-chain State (As of 2026-03-31 Query)

| Item | Value |
|------|-------|
| Factory gameCount | 3958 |
| Current anchor state l2Block | 26458740 |
| Latest game (index 3957) | IN_PROGRESS, l2Block=26476740 |

**Note**: The Factory also contains old game implementation records (e.g., `0x7aCa261a...`), which are versions deployed before the upgrade with different parameters (e.g., MAX_CHALLENGE_DURATION=24h, CHALLENGER_BOND=0.1ETH). The currently active impl is `0xfDF25E...`.

## 5. Permission Model

Currently in **whitelist mode** (permissionlessMode = false):

- **Proposer**: Only whitelisted addresses can create games through the Factory. Current whitelist: `0x829D...`
- **Challenger**: Only whitelisted addresses can call `challenge()`. Current whitelist: `0x7c37...`
- **Permissionless Fallback (Proposer only)**: If no new proposal is made for more than FALLBACK_TIMEOUT (7 days), any address can propose. There is no fallback mechanism for Challenger.
  - Logic: `AccessManager.getLastProposalTimestamp()` searches backward through the Factory for the creation time of the most recent type 42 game. Only type 42 games reset the timer; other types have no effect.
- **Prover**: `prove()` has no ACL permission check, but has **cryptographic constraints** -- the proof encodes `proverAddress = msg.sender`, and SP1Verifier verifies the binding between the proof and msg.sender. Therefore, others cannot replay your proof and must generate their own.

Since the current mode is permissioned, external users cannot challenge. Challenge operations in testing must be triggered by testers using whitelisted addresses.

## 6. Game Lifecycle

### 6.1 State Machine

```
ProposalStatus:
  0 - Unchallenged          (initial state)
  1 - Challenged            (challenged)
  2 - UnchallengedAndValidProofProvided  (not challenged but proof submitted)
  3 - ChallengedAndValidProofProvided    (challenged and valid proof submitted)
  4 - Resolved              (settled)
```

### 6.2 Complete Flow Diagram

```
Factory.create() + InitBond
        |
        v
   initialize()
   - Verify proposer whitelist (BadAuth)
   - Verify calldatasize == 0x7E (BadExtraData)
   - Verify parent game validity (InvalidParentGame):
     - isGameRespected, not blacklisted, not retired
     - Parent status != CHALLENGER_WINS
     - Parent l2SeqNum > anchor l2SeqNum (prevents duplicate games)
   - Verify l2SequenceNumber > parent's (UnexpectedRootClaim)
   - Set deadline = now + MAX_CHALLENGE_DURATION (1hr)
   - Set startingOutputRoot (from parent game or anchor state)
        |
        v
   Unchallenged -----+
        |             |
        |  deadline    | challenge() + CHALLENGER_BOND
        |  expires     |  - Verify challenger whitelist (BadAuth)
        |  (1hr)      |  - Verify not already challenged (ClaimAlreadyChallenged)
        |             |  - Verify game not ended (GameOver)
        |             |  - New deadline = now + MAX_PROVE_DURATION (7 days)
        v             v
   [can resolve]   Challenged ------+
        |             |              |
        |  prove()    | deadline     | prove(proofBytes)
        |  (optional) | expires      |  - SP1Verifier.verifyProof()
        v             | (7 days)     v
   Unchallenged     v              Challenged
   AndValidProof  [can resolve]    AndValidProof
        |             |              |
        v             v              v
   -------- resolve() (requires parent already resolved) --------
        |
        +-- Unchallenged          --> DEFENDER_WINS (proposer takes all)
        +-- Challenged (timed out) --> CHALLENGER_WINS (challenger takes all)
        +-- UnchallengedAndProved --> DEFENDER_WINS (proposer takes all, prover gets no reward)
        +-- ChallengedAndProved   --> DEFENDER_WINS (prover takes CHALLENGER_BOND, proposer takes remainder)
        +-- parent CHALLENGER_WINS --> CHALLENGER_WINS (cascade: challenger takes all, or no one claims)
        |
        v
   closeGame() (can be triggered internally by claimCredit)
   - Check isGameFinalized() (after resolve, must wait disputeGameFinalityDelaySeconds = 3.5hr)
   - Attempt setAnchorState() (if successful, advances the anchor)
   - Determine isGameProper() --> NORMAL or REFUND mode
        |
        v
   claimCredit(recipient)
   - NORMAL: Distribute based on resolve result (normalModeCredit)
   - REFUND: Each party gets back their deposited bond (refundModeCredit)
```

### 6.3 gameOver Determination

`gameOver()` returns true when: `deadline.raw() < block.timestamp` (strictly less than, not <=) or `prover != address(0)` (someone has submitted a valid proof).

**Important timing characteristics**:
- After a successful `prove()`, `gameOver()` immediately returns true -- no need to wait for deadline expiry, and `resolve()` can be called directly
- When parent is `CHALLENGER_WINS`, the child's `resolve()` bypasses the local `gameOver()` check and can immediately resolve to `CHALLENGER_WINS`
- `isGameFinalized()` uses `<=` comparison: when `block.timestamp - resolvedAt <= FINALITY_DELAY` it returns false, meaning it requires **strictly exceeding** the finality delay

### 6.4 Fast Finality Mode

Fast Finality Mode is a **proposer service** (not contract) configuration (`FAST_FINALITY_MODE` environment variable). When enabled:
- Proposer **immediately triggers SP1 proof generation** after creating a game, rather than waiting to be challenged
- Uses `FAST_FINALITY_PROVING_LIMIT` to cap concurrent proving tasks; pauses creating new games when the limit is reached
- Purpose: Reduce finalization time, since pre-generated proofs can be submitted immediately when challenged
- Current status: **Off**

### 6.5 extraData Format

The `extraData` when creating a game = `l2BlockNumber` (32 bytes) + `parentIndex` (4 bytes). The contract validates `calldatasize() == 0x7E` via assembly; incorrect format will revert with `BadExtraData`.

**Key rules**:
- The first game (no parent, starting from anchor state) must set `parentIndex = type(uint32).max` (i.e., `0xFFFFFFFF`). Subsequent games use the parent game's index in the Factory as `parentIndex`. If deploying on a devnet or fresh environment, the first game must use `0xFFFFFFFF` as parentIndex, otherwise initialize will attempt to read a non-existent game from the Factory and revert.
- **Parent must be ahead of anchor** (added in PR #839): When using a parent game by index, the parent game's `l2SequenceNumber` must be strictly greater than the anchor state's `l2SequenceNumber`. This prevents duplicate games when a finalized game becomes the anchor. Implication: once a parent game is finalized via `closeGame()` and becomes the anchor, it can no longer be used as a parent by index — the proposer must use `uint32.max` (anchor path) instead.

## 7. Bond Distribution Rules

### 7.1 Distribution Matrix

| Scenario | GameStatus | Proposer | Challenger | Prover |
|----------|-----------|----------|------------|--------|
| No challenge, deadline expires | DEFENDER_WINS | Gets back full bond | - | - |
| Challenged, timed out without proof | CHALLENGER_WINS | Loses bond | Takes all (proposer bond + challenger bond) | - |
| Challenged, proposer proves themselves | DEFENDER_WINS | Takes all (own bond + challenger bond) | Loses bond | = proposer |
| Challenged, third party proves | DEFENDER_WINS | Gets back own bond | Loses bond | Receives CHALLENGER_BOND |
| No challenge, proactive prove | DEFENDER_WINS | Gets back full bond | - | No extra reward |
| Parent fails, has challenger | CHALLENGER_WINS | Loses bond | Takes all | - |
| Parent fails, no challenger | CHALLENGER_WINS | Loses bond (locked in contract) | No one to claim | - |

**Note**: In the "parent fails, no challenger" scenario, `normalModeCredit[address(0)]` is assigned the contract's entire balance. `claimCredit(address(0))` can be called and will succeed — ETH is transferred to address(0), which is practically irrecoverable (not burned, but equivalently non-withdrawable).

### 7.2 "No Challenge but Proactive Prove" Scenario Explanation

Although there is no economic incentive for proactive proving without a challenge (the prover receives no extra reward), this is a legitimate code path allowed by the contract. Possible motivation: the proposer wants to confirm in advance that a proof can be generated, enhancing the credibility of the output root.

### 7.3 BondDistributionMode

`closeGame()` calls `AnchorStateRegistry.isGameProper()` to determine the bond distribution mode.

**`isGameProper()` checks** (note: **does not check respectedGameType**):
1. `isGameRegistered()` -- game must be registered in Factory
2. `!isGameBlacklisted()` -- game is not blacklisted
3. `!isGameRetired()` -- game creation time is after retirementTimestamp
4. `!paused()` -- AnchorStateRegistry is not paused

- **NORMAL**: When all conditions above are met, bonds are distributed based on the resolve result
- **REFUND**: When any condition is not met, each party gets back their deposited bond (proposer gets back InitBond, challenger gets back CHALLENGER_BOND)
- **Determination timing**: Evaluated at `closeGame()` time; `closeGame()` is automatically called within `claimCredit()`

**Important**: Switching `respectedGameType` **does not** cause existing games to enter REFUND mode. To force REFUND, use `blacklist` or set `retirementTimestamp`. This directly impacts rollback strategy design.

## 8. SP1 Proof Generation Flow

```
L2 Block Range (startingBlock --> claimBlock)
        |
        v
   Host generates Witness data
        |
        v
   Range Program (SP1 ZKVM, ethereum variant)
   -- Can be split into multiple range segments in parallel --
        |
        v
   Aggregation Program (SP1 ZKVM)
   -- Aggregates multiple range proofs --
        |
        v
   Groth16 Proof (final SNARK)
        |
        v
   Submit to contract prove() --> SP1Verifier.verifyProof()
```

### Proof Public Values (AggregationOutputs)

The proof encodes the following public values, and SP1Verifier validates their consistency with the actual state:

| Field | Meaning | Source |
|-------|---------|--------|
| `l1Head` | L1 parent block hash at game creation time | `game.l1Head()` |
| `l2PreRoot` | Starting L2 output root | `game.startingOutputRoot.root` (parent game's claim or anchor state) |
| `claimRoot` | L2 output root proposed by this game | `game.rootClaim()` |
| `claimBlockNum` | L2 block number | `game.l2SequenceNumber()` |
| `rollupConfigHash` | L2 rollup configuration hash | Contract immutable parameter |
| `rangeVkeyCommitment` | Range program verification key commitment | Contract immutable parameter |
| `proverAddress` | Address submitting the proof | `msg.sender` (cryptographically bound, not ACL) |

## 9. OptimismPortal2 Integration

Portal is the entry point for users to initiate L2 -> L1 withdrawals. Key parameters (on-chain verified):

| Parameter | Value | Description |
|-----------|-------|-------------|
| respectedGameType | 42 | Already switched to ZK fault proof |
| disputeGameFinalityDelaySeconds | 12600 (3.5hr) | Wait time required after game resolve |
| proofMaturityDelaySeconds | 25200 (7hr) | Withdrawal proof maturity delay |

The withdrawal flow depends on game validity. `AnchorStateRegistry.isGameClaimValid()` requires the game to satisfy all of:
1. `isGameProper()` -- registered + not blacklisted + not retired + not paused
2. `isGameFinalized()` -- resolved + exceeded finality delay
3. `isGameRespected()` -- `wasRespectedGameTypeWhenCreated` is true
4. `status == DEFENDER_WINS`

Only output roots from games satisfying all the above can be used for withdrawal proving.

**Impact of rollback on withdrawals**: After switching `respectedGameType` back to type 1:
- New withdrawals must be based on Cannon game (type 1) output roots
- Withdrawals already proved based on ZK game (type 42) but not yet finalized: the impact depends on OptimismPortal2's specific validation logic (not within the verification scope of this document; requires actual testing to confirm)
- Already finalized withdrawals are not affected (ETH has already been transferred out)

## 10. Contract Error Types Reference

| Error | Trigger Condition |
|-------|-------------------|
| `BadAuth` | Non-whitelisted address attempts to propose or challenge |
| `AlreadyInitialized` | Game re-initialization |
| `IncorrectDisputeGameFactory` | Non-Factory calls initialize |
| `BadExtraData` | calldatasize != 0x7E |
| `InvalidParentGame` | Parent game is invalid (not respected / blacklisted / retired / CHALLENGER_WINS / parent l2SeqNum <= anchor l2SeqNum) |
| `UnexpectedRootClaim` | l2SequenceNumber <= parent's l2SequenceNumber |
| `ClaimAlreadyChallenged` | Duplicate challenge, or challenge after prove (since status is no longer Unchallenged, this check fires before GameOver) |
| `GameOver` | Attempting to challenge/prove after deadline expires (note: challenge after prove will first hit ClaimAlreadyChallenged or status check) |
| `GameNotOver` | Attempting to resolve when game has not ended |
| `ParentGameNotResolved` | Parent game is still IN_PROGRESS when resolving |
| `ClaimAlreadyResolved` | Duplicate resolve |
| `IncorrectBondAmount` | msg.value != CHALLENGER_BOND when challenging |
| `GameNotFinalized` | closeGame when game has not yet finalized (finality delay not elapsed) |
| `NoCreditToClaim` | Balance is 0 when calling claimCredit |
| `BondTransferFailed` | ETH transfer failed |
| `InvalidBondDistributionMode` | Unexpected bondDistributionMode state (should not occur) |
| `InvalidProposalStatus` | Unexpected proposalStatus state (should not occur) |

## 11. Test Requirements

### 11.1 Test Objectives

Verify the X Layer testnet upgrade from Cannon fraud proof to OP Succinct ZK fault proof:
- Functional correctness
- Security
- Economic model
- Service stability
- Rollback feasibility

### 11.2 Test Approach

- **Manual testing** is primary, executed on Sepolia testnet
- Devnet can be used as a supplement for rapid iteration and validation
- Testers trigger challenges using whitelisted addresses (constrained by whitelist permission mode)
- Use the challenger service's `MALICIOUS_CHALLENGE_PERCENTAGE` configuration for automated integration testing
  - This parameter controls the probability that the honest challenger randomly challenges valid games (0.0 = honest mode, 100.0 = challenge all games)
  - Configured via the challenger service's environment variables

### 11.3 Test Scope

1. Contract deployment and parameter verification
2. Complete game lifecycle (all state paths)
3. End-to-end SP1 proof generation and on-chain verification
4. Parent-child game chain relationships and cascade failure
5. Permission control and security boundaries
6. Bond economic model (all distribution scenarios)
7. Proposer / Challenger service automated behavior
8. Gas consumption baseline
9. Exceptions and edge cases
10. OptimismPortal2 withdrawal integration
11. Rollback plan verification

### 11.4 Test Constraints

- SP1 Prover Network proof generation has latency (potentially minutes to hours), MAX_PROVE_DURATION = 7 days
- MAX_CHALLENGE_DURATION = 1 hour; some tests require waiting for the time window to expire
- disputeGameFinalityDelaySeconds = 3.5 hours; after resolve, must wait before claimCredit
- Only testers can trigger challenges under whitelist mode
- Real Groth16 verifier means higher gas for proof verification; this warrants attention
- Both Proposer InitBond and CHALLENGER_BOND are 10 Gwei; tests require sufficient Sepolia ETH

### 11.5 Risk Areas of Concern

- Proof generation failure or timeout causing proposer to be penalized (bond taken by challenger), especially when SP1 Network is unavailable
- SP1 Prover Network availability issues (SLA is completion within 7 days)
- Contract parameter misconfiguration leading to security vulnerabilities (note old impl records exist in Factory)
- Whether Groth16 verification gas consumption is within acceptable range
- Whether a malicious proposer submitting an incorrect output root can be properly challenged and blocked
- Whether parent game failure cascade effects propagate correctly
- Coexistence compatibility of old Cannon game (type 1) and new ZK game (type 42) in the Factory
- State handling of existing ZK games when rolling back to Cannon, and impact on withdrawals
- Discrepancy between disputeGameFinalityDelaySeconds (3.5hr) and config file (7 days); confirm whether this is an intentional testnet configuration

## 12. Rollback Strategy Notes

Since `isGameProper()` does not check `respectedGameType`, merely switching respectedGameType during rollback is insufficient to put existing ZK games into REFUND mode. Effective rollback methods:

| Operation | Effect | Scope of Impact |
|-----------|--------|-----------------|
| Switch `respectedGameType` back to type 1 | New withdrawals can only use Cannon game output roots | Portal/withdrawal layer |
| `Factory.setImplementation(42, address(0))` | Cannot create new ZK games | New game creation |
| `AnchorStateRegistry.updateRetirementTimestamp()` | Games created before the specified time are not proper --> REFUND | Bond distribution for existing games |
| `AnchorStateRegistry.blacklistDisputeGame(game)` | Specific game is not proper --> REFUND | Specific game |

**Rollback permission chain**:
- AnchorStateRegistry operations: Guardian (`0x11CAA37c...`)
- Factory operations: Factory Owner/Transactor (`0xaFf1B587...`)
- AccessManager operations: AccessManager Owner (`0xA14a8bFf...`)

### Cascade Test Method

Refer to existing Foundry tests (`contracts/test/fp/OPSuccinctFaultDisputeGame.t.sol`):
1. Create Game A (can submit any root claim; the contract does not validate claim correctness)
2. Create Game B (parentIndex points to Game A)
3. Challenge Game A
4. Wait for MAX_PROVE_DURATION to expire without submitting proof
5. Resolve Game A --> CHALLENGER_WINS
6. Resolve Game B --> Cascades to CHALLENGER_WINS

## 13. SP1 Prover Network Configuration

SP1 Prover Network uses Succinct's official mainnet service, authenticated via the `NETWORK_PRIVATE_KEY` environment variable (wallet private key signature).

### Proposer Key Runtime Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| RANGE_PROOF_STRATEGY | auction | Auction mode |
| AGG_PROOF_STRATEGY | auction | Auction mode |
| AGG_PROOF_MODE | groth16 | Final proof format |
| PROPOSAL_INTERVAL_IN_BLOCKS | 3600 | = 3600 seconds = 1 hour (L2 block time 1s) |
| FETCH_INTERVAL | 10 seconds | Check interval |
| MAX_CONCURRENT_DEFENSE_TASKS | 8 | Max concurrent defense tasks |
| SAFE_DB_FALLBACK | true | Falls back to timestamp-estimated L1 head |
| MAX_PRICE_PER_PGU | 600000000 | 0.6 PROVE/billion PGU |
| MIN_AUCTION_PERIOD | 20 seconds | Minimum auction period |
| TIMEOUT | 14400 seconds (4hr) | Single proving timeout |
| RANGE_SPLIT_COUNT | 1 | No range splitting |
| MAX_CONCURRENT_RANGE_PROOFS | 1 | Serial range proof |
| AGG_GAS_LIMIT | 12000000 | Aggregation gas limit |

## 14. Supplementary Notes

### 14.1 L2 Block Time

X Layer testnet L2 block time is **1 second**. Therefore:
- PROPOSAL_INTERVAL_IN_BLOCKS = 3600 blocks = **1 hour**
- The proposer creates approximately one new game per hour

### 14.2 Querying Dispute Games

Dispute games can be viewed through the following methods:
- **Sepolia block explorer**: Search for proposer address `0x829D57F38D2A94514a3dbA2297fDD1Bc52bB1938` to see all created games
- **cast commands**: Query through the DisputeGameFactory contract
  ```bash
  # Query total game count
  cast call 0x80388586ab4580936BCb409Cc2dC6BC0221e1B6F "gameCount()(uint256)" -r $L1_RPC_URL

  # Query game at a specific index
  cast call 0x80388586ab4580936BCb409Cc2dC6BC0221e1B6F "gameAtIndex(uint256)(uint32,uint64,address)" <index> -r $L1_RPC_URL

  # Query game status
  cast call <game_address> "status()(uint8)" -r $L1_RPC_URL
  cast call <game_address> "claimData()(uint32,address,address,bytes32,uint8,uint64)" -r $L1_RPC_URL
  ```

### 14.3 Rollback Operation Permissions

Rollback operations can be executed through the company's contract management platform. Guardian/Deployer `0x11CAA37c9e9Da2621bB45Af77cB7debEE3881d2E` can be used for testing.
