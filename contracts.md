```
AnchorStateRegistry
  current anchor:
    root = R0
    l2SequenceNumber = 1000
          |
          | parentIndex = uint32.max
          v
  +----------------------+
  | Game[0]              |
  | starts from R0 @1000 |
  | proposes R1 @1100    |
  +----------------------+
          |
          | parentIndex = 0
          v
  +----------------------+
  | Game[3]              |
  | starts from R1 @1100 |
  | proposes R4 @1400    |
  +----------------------+

  Multiple games can start from the same anchor:

  Anchor R0 @1000
     |
     | parentIndex = uint32.max
     |
     +--> Game[0]: proposes R1 @1100
     |
     +--> Game[1]: proposes R2 @1200
     |
     +--> Game[2]: proposes R3 @1100

  A child game can point to an earlier game by factory index:

  Anchor R0 @1000
     |
     +--> Game[0]: R1 @1100
     |        |
     |        +--> Game[3]: R4 @1300
     |        |
     |        +--> Game[4]: R5 @1250
     |
     +--> Game[1]: R2 @1200
              |
              +--> Game[5]: R6 @1500

  Meaning:

  parentIndex = uint32.max
    -> start from current anchor root

  parentIndex = 0
    -> start from Game[0].rootClaim()

  parentIndex = 1
    -> start from Game[1].rootClaim()

  So each game has:

  startingOutputRoot = anchor root OR parent game's rootClaim
  rootClaim          = the new proposed output root
```


Many games may be created from the current anchor. Only a resolved + finalized + proper DEFENDER_WINS game can advance the anchor.
resolve() alone does not update the anchor. The game must also pass the ASR finality delay, then closeGame() must be called.
The anchor moves forward to accepted L2 sequence numbers and should not roll back.
