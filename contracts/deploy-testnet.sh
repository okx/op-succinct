#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RPC_URL=$1
PRIVATE_KEY=$2

# Patch sp1-contracts pragma to be compatible with >=0.8.15
if [[ "$OSTYPE" == "darwin"* ]]; then
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
else
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
fi

forge script script/fp/DeployOPSuccinctLiteTestnet.s.sol:DeployOPSuccinctLite -vvv --private-key="$PRIVATE_KEY" --rpc-url="$RPC_URL" --broadcast