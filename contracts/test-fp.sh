#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Patch sp1-contracts pragma to be compatible with >=0.8.15
if [[ "$OSTYPE" == "darwin"* ]]; then
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
else
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
fi

# Run all fault proof tests
# test/fp/OPSuccinctFaultDisputeGame.t.sol       — 26 base tests (TC1-TC12, TC14, TC20-TC21, TC25, TC31-TC35)
# test/fp/OPSuccinctFaultDisputeGameExtended.t.sol — 23 extended tests (TC6b, TC7c, TC8-TC9, TC13, TC15-TC19, TC22-TC24, TC26-TC28)
# test/fp/AccessManager.t.sol                     — 14 access manager unit tests
forge test --match-path "test/fp/*" -vv "$@"
