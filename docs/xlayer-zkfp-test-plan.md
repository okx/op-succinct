# X Layer Testnet ZK Fault Proof Upgrade -- Test Plan

> For background and requirements, see [xlayer-zkfp-test-background.md](./xlayer-zkfp-test-background.md)

## Test Layers

| Layer | Environment | Format | Objective |
|-------|-------------|--------|-----------|
| **Sepolia Testnet** | Deployed real contracts + real SP1 Network | cast scripts + server runtime observation | Verify deployment correctness, real proof end-to-end, service coordination |
| **Devnet E2E** | Locally deployed contracts with short parameters | Foundry test (`forge test`) | Verify contract logic completeness, reproducible runs, CI integration |

## Common Addresses and Parameter Quick Reference (Sepolia)

| Item | Value |
|------|-------|
| Factory | `0x80388586ab4580936BCb409Cc2dC6BC0221e1B6F` |
| Game Impl | `0xfDF25E39F0c0C131905e4b72Dd65620a88F19236` |
| AccessManager | `0x33D211daB418F65Ca71035055bCF557808aCa13f` |
| AnchorStateRegistry | `0x1A8DFc1d6ccfB3bE886b2539823539a9DC0956a5` |
| SP1Verifier | `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B` |
| OptimismPortal2 | `0x1529a34331d7d85c8868fc88ec730ae56d3ec9c0` |
| Proposer | `0x829D57F38D2A94514a3dbA2297fDD1Bc52bB1938` |
| Challenger | `0x7c3787bf0d78a9e2f802916110e4ddd6e3ed262c` |
| Game Type | 42 |
| Legacy Cannon Type | 1 (impl: `0x34f0482A8F7B91F8C9346A9cCA705Ba8aC9A1CE3`) |
| MAX_CHALLENGE_DURATION | 3600s (1hr) |
| MAX_PROVE_DURATION | 604800s (7d) |
| CHALLENGER_BOND | 10 Gwei (1e10 wei) |
| Proposer InitBond | 10 Gwei (1e10 wei) |
| disputeGameFinalityDelaySeconds | 12600s (3.5hr) |
| proofMaturityDelaySeconds | 25200s (7hr) |
| FALLBACK_TIMEOUT | 604800s (7d) |
| L2 Block Time | 1s |
| PROPOSAL_INTERVAL | 3600 blocks = 1hr |

---

# Part 1: Sepolia Testnet

> Test core logic only: deployment verification + real proof end-to-end + service integration + withdrawal

## S1: Contract Deployment Verification [P0]

> Script: [`scripts/verify-sepolia-deployment.sh`](./scripts/verify-sepolia-deployment.sh)

```bash
./tests/scripts/verify-sepolia-deployment.sh [RPC_URL]
```

21 automated checks: Game Impl parameters (7 items), Factory registration (2 items), AccessManager permissions (5 items), ASR + Portal state (5 items), SP1Verifier existence (1 item), legacy Cannon coexistence (1 item).

Verified: **21/21 PASS**

---

## S2: Core Integration Test -- Malicious Challenge + Auto Prove [P0]

> Estimated duration: depends on SP1 proof generation (minutes to hours) + finality delay
> This is the core E2E test on Sepolia

**Steps**:

1. Start the proposer service
2. Start the malicious challenger (`MALICIOUS_CHALLENGE_PERCENTAGE=100`)
3. Observe the full cycle:
   - Proposer creates a game
   - Challenger automatically challenges (with 10 Gwei bond)
   - Proposer detects `Challenged` event -> requests SP1 proof (auction mode)
   - Monitor proof generation: record duration for each stage (queued -> proving -> completed)
   - Proof completed -> proposer submits `prove()` transaction
   - `gameOver()` immediately returns true
   - Proposer auto-resolves -> `DEFENDER_WINS`
   - Wait for finality delay (3.5hr) then auto-claim credit
4. **Run at least 3 full cycles**
5. Verify each cycle:
   - Game final state: `DEFENDER_WINS` + `ChallengedAndValidProofProvided`
   - Bond distribution: proposer receives all 20 Gwei (when proposer == prover)
   - Proof bytes are valid, gas is reasonable

**Recorded Data**:

| Metric | Cycle 1 | Cycle 2 | Cycle 3 |
|--------|---------|---------|---------|
| SP1 proof generation time | | | |
| Proof bytes size | | | |
| prove() gas | | | |
| challenge -> resolve end-to-end time | | | |
| Proposer challenge detection latency | | | |
| Factory.create() gas | | | |

**Pass criteria**: All 3 rounds of challenge -> prove -> resolve -> claim succeed without manual intervention

---

## Sepolia Execution Order

```
Step 1: Run S1 deployment verification script (5min)
Step 2: Start proposer + malicious challenger, run S2 (several hours)
```

## Sepolia Test Results

| ID | Date | Result | Notes |
|----|------|--------|-------|
| S1.1-S1.6 | | PASS/FAIL | |
| S2 Cycle 1 | | PASS/FAIL | proof time: / prove gas: |
| S2 Cycle 2 | | PASS/FAIL | |
| S2 Cycle 3 | | PASS/FAIL | |

---

# Part 2: Devnet Foundry E2E Tests

> Deploy contracts with short parameters, reproducible Foundry tests
>
> **Suggested Devnet parameters**: MAX_CHALLENGE_DURATION=60s, MAX_PROVE_DURATION=120s, disputeGameFinalityDelaySeconds=30s, FALLBACK_TIMEOUT=60s

## 1. Core Lifecycle

### TC1: Happy Path -- No Challenge, Normal Resolve

1. Create a new game via Factory (with InitBond)
2. Verify initial state:
   - `status()` == 0 (IN_PROGRESS)
   - `claimData().status` == 0 (Unchallenged)
   - `claimData().deadline` == `createdAt + MAX_CHALLENGE_DURATION`
   - `gameCreator()` == proposer address
   - `rootClaim()` matches the submitted claim
   - `l2BlockNumber()` matches the submitted block number
   - `startingOutputRoot` matches parent game claim or anchor state
3. Wait for challenge deadline to expire
   - `gameOver()` uses strict `<`, i.e., `deadline < block.timestamp`
4. `gameOver()` == true
5. Confirm parent game is resolved (if parentIndex != uint32.max)
6. `resolve()` -> `DEFENDER_WINS` + event `Resolved(GameStatus.DEFENDER_WINS)`
7. Wait for finality delay to expire (strict `>`)
8. `claimCredit(proposer)` -> internally triggers `closeGame()` -> NORMAL mode -> proposer reclaims bond

### TC2: Challenge + Successful Third-Party Prove

1. Create game
2. Challenger calls `challenge{value: CHALLENGER_BOND}()`
   - `claimData().status` == Challenged
   - `claimData().counteredBy` == challenger
   - `claimData().deadline` == challenge time + MAX_PROVE_DURATION
   - game balance == InitBond + CHALLENGER_BOND
3. **Third-party address** (not the proposer) calls `prove(proofBytes)`
   - `claimData().status` == ChallengedAndValidProofProvided
   - `claimData().prover` == third-party address
   - `gameOver()` **immediately** true
4. Immediately `resolve()` -> `DEFENDER_WINS`
5. Wait for finality delay, `claimCredit()`
6. Bond verification (**assert after resolve() but before claimCredit()**):
   - `normalModeCredit[prover]` == CHALLENGER_BOND
   - `normalModeCredit[proposer]` == InitBond (i.e., balance at resolve time - CHALLENGER_BOND)
   - `normalModeCredit[challenger]` == 0
   - After calling `claimCredit(prover)` + `claimCredit(proposer)`, game balance == 0

### TC3: Challenge + Prove Timeout -- Challenger Wins

1. Create game, challenger challenges
2. **Do not submit proof**
3. Wait for MAX_PROVE_DURATION to expire -> `gameOver()` == true
4. `resolve()` -> `CHALLENGER_WINS`
5. Wait for finality delay
6. `normalModeCredit[challenger]` == total balance
7. Challenger `claimCredit()` -> success
8. Proposer `claimCredit()` -> revert `NoCreditToClaim`

### TC4: No Challenge + Proactive Prove

1. Create game, call `prove(proofBytes)` while unchallenged
2. `claimData().status` == UnchallengedAndValidProofProvided
3. `gameOver()` **immediately** true (shortens challenge window, basis for Fast Finality)
4. Immediately `resolve()` -> `DEFENDER_WINS`
5. `normalModeCredit[gameCreator]` == total balance
6. If prover != proposer: `normalModeCredit[prover]` == 0 (no extra reward)

---

## 2. Parent-Child Chain Verification

### TC5: Normal Parent-Child Chain

1. Create Game A (`parentIndex = 0xFFFFFFFF`)
2. Wait for Game A deadline to expire, resolve -> `DEFENDER_WINS`
3. Create Game B (parentIndex = Game A index)
   - `startingOutputRoot.root` == Game A's `rootClaim()`
   - `startingOutputRoot.l2SequenceNumber` == Game A's `l2SequenceNumber()`
   - Game B's `l2SequenceNumber` > Game A's
4. Game B resolves normally

**Note**: In `initialize()`, parent validation only rejects `CHALLENGER_WINS` (L273); `IN_PROGRESS` parents also allow child creation. TC5 resolves first to test the happy path.

### TC6: Cascade Effect of Parent Failure

**Scenario A -- child has no challenger**:
1. Create Game A, create Game B (parent = Game A)
2. Challenge Game A, do not submit proof
3. Wait for Game A prove deadline to expire, resolve -> `CHALLENGER_WINS`
4. Verify Game B `claimData.counteredBy == address(0)`
5. Immediately resolve Game B -> `CHALLENGER_WINS` (cascaded)
6. Assert `bondDistributionMode == BondDistributionMode.NORMAL`
7. `normalModeCredit[address(0)]` == balance (funds locked permanently)
8. `refundModeCredit[address(0)]` == 0 (confirm funds are not misclassified to the REFUND channel)
9. Proposer `claimCredit()` -> revert `NoCreditToClaim`

**Scenario B -- child has a challenger**:
1-3 same as Scenario A, but challenge Game B before step 3
4. Resolve Game B -> `CHALLENGER_WINS` (cascaded)
5. `normalModeCredit[Game B challenger]` == total balance
6. Challenger `claimCredit()` -> success

**Scenario C -- child cannot resolve while parent is unresolved**:
1. Create Game A (keep IN_PROGRESS), create Game B (parent = Game A)
2. Wait for Game B deadline to expire
3. `resolve()` Game B -> revert `ParentGameNotResolved`

### TC7: InvalidParentGame -- Creating Child with Ineligible Parent

**Scenario A -- blacklisted parent**:
1. Create Game A, resolve (DEFENDER_WINS)
2. Guardian calls `blacklistDisputeGame(Game A)`
3. Create Game B (parentIndex = Game A) -> revert `InvalidParentGame`

**Scenario B -- retired parent**:
1. Create Game A
2. Guardian calls `updateRetirementTimestamp()` -- Game A's `createdAt <= retirementTimestamp`
3. Create Game B (parentIndex = Game A) -> revert `InvalidParentGame`

**Scenario C -- CHALLENGER_WINS parent**:
1. Create Game A, challenge, timeout -> resolve `CHALLENGER_WINS`
2. Create Game B (parentIndex = Game A) -> revert `InvalidParentGame` (L273)

### TC8: Cross Game Type Parent Chain

1. Create Cannon game (type 1)
2. Create ZK game (type 42, parentIndex pointing to Cannon game)
3. -> revert `InvalidParentGame` (`isGameRespected()` -- type 1 is not respected)

### TC9: Multi-Level Cascade Failure (5-Game Chain)

1. Create Game A -> B -> C -> D -> E (each parent pointing to the previous one)
2. Challenge Game A, timeout without proving
3. Resolve A -> CHALLENGER_WINS
4. Resolve B -> C -> D -> E in order, each cascades to CHALLENGER_WINS
5. Verify bond distribution at each level (goes to challenger if one exists, goes to address(0) otherwise)

---

## 3. Permissions and Security

### TC10: Non-Whitelisted Address Proposes

1. Non-whitelisted address calls Factory.create(42, ...) -> revert `BadAuth`

### TC11: Non-Whitelisted Address Challenges

1. Create game
2. Non-whitelisted address calls `challenge()` -> revert `BadAuth`

### TC12: Permissionless Fallback

1. `isProposalPermissionlessMode()` == false (proposer is active)
2. Simulate FALLBACK_TIMEOUT expiration (devnet short parameters)
3. Any address can propose
4. **Verify challenger has no fallback**: non-whitelisted address still cannot call `challenge()` -> revert `BadAuth`

### TC13: Bond Amount Validation

1. `challenge{value: CHALLENGER_BOND - 1}()` -> revert `IncorrectBondAmount`
2. `challenge{value: CHALLENGER_BOND + 1}()` -> revert `IncorrectBondAmount`
3. `challenge{value: 0}()` -> revert `IncorrectBondAmount`

### TC14: Duplicate Challenge

1. Challenger A challenges
2. Call `challenge()` again -> revert `ClaimAlreadyChallenged`

### TC15: Operations After Expiry/Completion

**Scenario A -- after deadline expiry**:
1. Wait for challenge deadline to expire
2. `challenge()` -> revert `GameOver`
3. `prove()` -> revert `GameOver`

**Scenario B -- after prove succeeds without challenge**:
1. Submit valid proof -> `claimData.status` == `UnchallengedAndValidProofProvided`
2. `challenge()` -> revert `ClaimAlreadyChallenged` (L343 status check precedes L349 gameOver check)
3. Call `prove()` again -> revert `GameOver` (prover != address(0))

**Scenario C -- after resolve**:
1. `resolve()` -> revert `ClaimAlreadyResolved`

### TC16: address(0) Toggle -- Fully Open/Close Propose

1. Owner calls `setProposer(address(0), true)`
2. `isProposalPermissionlessMode()` == true (**immediately**, bypasses FALLBACK_TIMEOUT)
3. Any address can propose
4. Owner calls `setProposer(address(0), false)`
5. Non-whitelisted address proposes -> revert `BadAuth`

### TC17: address(0) Toggle -- Fully Open/Close Challenge

1. Owner calls `setChallenger(address(0), true)` -> anyone can challenge
2. Owner calls `setChallenger(address(0), false)` -> non-whitelisted `challenge()` -> revert `BadAuth`

---

## 4. SP1 Proof Verification (Devnet Mock Verifier)

> Devnet uses MockVerifier to test proof logic; real SP1 proof is verified in Sepolia S2

### TC18: Invalid Proof Rejection

1. `prove(0xdeadbeef...)` -> revert
2. **Cross-sender replay**: Address A's proof called via `prove()` from address B -> revert (proverAddress mismatch, verifying front-run protection)
   - **Note**: Coverage depends on whether MockVerifier validates the proverAddress in publicValues. If MockVerifier is in passthrough mode (always success), this test provides no security coverage and must rely on real SP1 verification in Sepolia S2

---

## 5. Bond Economic Model

### Bond Distribution Reference Matrix

> Bond verification is spread across various TCs; this table is for reference only

| Scenario | Covered by TC | Result | Distribution |
|----------|---------------|--------|--------------|
| No challenge | TC1 | DEFENDER_WINS | proposer = InitBond |
| Challenge + timeout | TC3 | CHALLENGER_WINS | challenger = all |
| Challenge + proposer proves | TC2 (variant) | DEFENDER_WINS | proposer = all |
| Challenge + third-party proves | TC2 | DEFENDER_WINS | prover = CHALLENGER_BOND, proposer = remainder |
| Cascade failure + has challenger | TC6b | CHALLENGER_WINS | challenger = all |
| Cascade failure + no challenger | TC6a | CHALLENGER_WINS | address(0) = all (locked permanently) |

### TC19: BondDistributionMode (NORMAL vs REFUND)

**NORMAL mode**:
1. Game resolve + finality delay -> `closeGame()` -> `isGameProper()` == true -> NORMAL

**REFUND mode**:
1. Guardian calls `updateRetirementTimestamp()` or `blacklistDisputeGame(game)`
2. `closeGame()` -> `isGameProper()` == false -> REFUND
3. `claimCredit(proposer)` -> proposer receives InitBond
4. `claimCredit(challenger)` -> challenger receives CHALLENGER_BOND
5. Assert game balance == 0 (confirm refund is complete, no residual funds)

**Important**: Switching `respectedGameType` **does not** trigger REFUND -- need to verify whether ASR's `isGameProper()` checks the `wasRespectedGameTypeWhenCreated` field (contract L306-307 records this flag; if ASR uses this field then switching would trigger REFUND -- needs confirmation).

---

## 6. closeGame / claimCredit Edge Cases

### TC20: closeGame Before Resolve

1. Game remains IN_PROGRESS
2. `closeGame()` -> revert `GameNotFinalized()`

### TC21: claimCredit Before Finality Delay

1. Resolve -> DEFENDER_WINS
2. **Immediately** `claimCredit(proposer)` -> revert `GameNotFinalized()`
3. Requires finality delay to expire (`>` vs `>=` depends on ASR's `isGameFinalized()` implementation; confirm boundary conditions in ASR source before testing)

### TC22: claimCredit(address(0))

1. Complete a cascade-failed game with no challenger -> `normalModeCredit[address(0)]` > 0
2. `claimCredit(address(0))` -> **succeeds** (in EVM, call to address(0) returns success, ETH is permanently destroyed)
3. Verify game balance decreases and credit is zeroed out

### TC23: MaliciousRecipient Reentrancy Attack

**Attack surface A -- direct reentrancy via claimCredit**:
1. Deploy MaliciousRecipient (reenters `claimCredit` in `receive()`)
2. Complete the full game flow normally, making MaliciousRecipient the prover (call prove with that address as msg.sender)
3. `claimCredit(MaliciousRecipient)` -> reentrant call reverts with `NoCreditToClaim`
4. **Rationale**: L512-513 zeroes out credit before L516 external call, following the CEI pattern

**Attack surface B -- reentrancy via ASR through closeGame**:
5. **Trust assumption**: `ANCHOR_STATE_REGISTRY` is a CWIA immutable trusted contract. The `setAnchorState()` external call occurs before `bondDistributionMode` is set. If ASR were compromised, reentrancy could occur, but ASR is trusted in the current deployment.
6. **Optional**: Deploy MockASR on devnet (callback to game in setAnchorState) to verify whether double-payout is possible

### TC24: BondTransferFailed

1. Deploy a contract without `receive()`/`fallback()` as the recipient
2. `claimCredit(brokenContract)` -> revert `BondTransferFailed`
3. Verify credit is not zeroed out (revert rolls back the entire transaction)

---

## 7. Input Validation and Edge Cases

### TC25: l2SequenceNumber Constraint

1. `l2SequenceNumber <= startingOutputRoot.l2SequenceNumber` -> revert `UnexpectedRootClaim`

### TC26: AnchorState Advancement

1. Complete DEFENDER_WINS game full flow (resolve + finality delay + closeGame)
2. `anchors(42)` l2Block advances
3. CHALLENGER_WINS game -> closeGame does not advance anchor
4. **Anchor rollback protection**: Create Game X (block N) and Game Y (block N+1000). Resolve Y first -> anchor advances to N+1000. Then resolve X -> closeGame -> verify `anchors(42).l2SequenceNumber` remains N+1000 (no rollback)

### TC27: getLastProposalTimestamp() Gas DoS Stress Test

1. Create N non-type-42 games (forcing reverse traversal through all of them)
2. Measure gas for `Factory.create(42, ...)` at N = 100, 500, 1000, 2000
3. **Pass/Fail**: gas > 15M (50% of block gas limit) -> FAIL
4. **Mitigation**: If FAIL, recommend `proposers[address(0)] = true` or caching the timestamp

---

## 8. Rollback Plan

### TC28: Rollback to Cannon Fraud Proof

**Rollback procedure**:
```
Step 1: Factory.setImplementation(42, address(0))              -- Prevent creation of new ZK games
Step 2: AnchorStateRegistry.setRespectedGameType(1)            -- Switch ASR to Cannon
Step 3: OptimismPortal2.setRespectedGameType(1)                -- Portal must also switch
Step 4 (optional): AnchorStateRegistry.updateRetirementTimestamp()  -- No parameters, uses block.timestamp internally
```

**Notes**:
- `updateRetirementTimestamp()` **takes no parameters**; it uses `block.timestamp` internally
- Steps 2 and 3 **must both be executed**; otherwise Portal and ASR will be inconsistent
- Switching respectedGameType alone **does not** trigger REFUND; Step 4 is required for that
- Steps 2 and 3 should be completed within the shortest possible window to avoid intermediate states

**Post-rollback verification**:

| Check Item | Expected |
|------------|----------|
| Factory.create(42, ...) | revert |
| Factory.create(1, ...) | success |
| ASR respectedGameType | 1 |
| Portal respectedGameType | 1 |
| Already resolved ZK game status | unchanged |
| IN_PROGRESS ZK games | If Step 4 executed -> REFUND mode |
| New withdrawals | Must be based on Cannon games |

---

## 9. ZKVM Proof Performance and Cost Benchmark

### TC29: Proof Cost Across Different Transaction Types / TPS / Block Ranges

> Test ZKVM proof generation capability and cost under different loads

**Transaction types**: Native transfer / ERC20 transfer / Pay transaction

**TPS**: 10 / 100 / 1000 (Pay does not test 1000)

**Block Range**: 600 / 3600

**Steps**:
1. Continuously send the corresponding transaction type at the specified TPS to devnet
2. Proposer submits a game covering the specified block range
3. Trigger challenge -> prove flow, record SP1 proof generation data
4. Record cycle count, PROVE token consumption, proof generation time
5. Calculate per-transaction USD cost

**Test Matrix**:

| Transaction Type | TPS | Block Range | Total Transactions | Cycle Count | Proof Time | PROVE Consumed | Per-Tx Cost (USD) |
|-----------------|-----|-------------|-------------------|-------------|------------|----------------|-------------------|
| Native transfer | 10 | 600 | 6,000 | | | | |
| Native transfer | 10 | 3600 | 36,000 | | | | |
| Native transfer | 100 | 600 | 60,000 | | | | |
| Native transfer | 100 | 3600 | 360,000 | | | | |
| Native transfer | 1000 | 600 | 600,000 | | | | |
| Native transfer | 1000 | 3600 | 3,600,000 | | | | |
| ERC20 transfer | 10 | 600 | 6,000 | | | | |
| ERC20 transfer | 10 | 3600 | 36,000 | | | | |
| ERC20 transfer | 100 | 600 | 60,000 | | | | |
| ERC20 transfer | 100 | 3600 | 360,000 | | | | |
| ERC20 transfer | 1000 | 600 | 600,000 | | | | |
| ERC20 transfer | 1000 | 3600 | 3,600,000 | | | | |
| Pay transaction | 10 | 600 | 6,000 | | | | |
| Pay transaction | 10 | 3600 | 36,000 | | | | |
| Pay transaction | 100 | 600 | 60,000 | | | | |
| Pay transaction | 100 | 3600 | 360,000 | | | | |

**Pass criteria**: All combinations successfully generate proof and resolve

---

## Devnet Execution Order

```
Phase 1: Core Lifecycle
  TC1, TC2, TC3, TC4

Phase 2: Parent-Child + Cascade
  TC5, TC6a-c, TC7a-c, TC8, TC9

Phase 3: Permissions and Security
  TC10, TC11, TC12, TC13, TC14, TC15a-c, TC16, TC17

Phase 4: Proof Verification
  TC18

Phase 5: Bond + closeGame/claimCredit Edge Cases
  TC19, TC20, TC21, TC22, TC23, TC24

Phase 6: Input Validation + Stress Test
  TC25, TC26, TC27

Phase 7: Rollback
  TC28

Phase 8: Performance and Cost Benchmark
  TC29
```

## Devnet Test Results

| ID | Result | Gas | Notes |
|----|--------|-----|-------|
| TC1 | | | |
| TC2 | | | |
| TC3 | | | |
| TC4 | | | |
| TC5 | | | |
| TC6a-c | | | |
| TC7a-c | | | |
| TC8 | | | |
| TC9 | | | |
| TC10 | | | |
| TC11 | | | |
| TC12 | | | |
| TC13 | | | |
| TC14 | | | |
| TC15a-c | | | |
| TC16 | | | |
| TC17 | | | |
| TC18 | | | |
| TC19 | | | |
| TC20 | | | |
| TC21 | | | |
| TC22 | | | |
| TC23 | | | |
| TC24 | | | |
| TC25 | | | |
| TC26 | | | |
| TC27 | | | N=100/500/1000/2000 gas: |
| TC28 | | | |
| TC29 | | | See test matrix for details |
