#!/usr/bin/env bash
# Shared, single definition of the normative five-field envelope assertion.
#
# This helper used to be copied into every acceptance script that needed it. The review found the
# same false pass in each copy, and a third consumer (the mutation proof) carried a weaker parser
# of its own that checked only `code`. One definition removes both failure modes: there is nothing
# left to diverge, and no second parser can admit what this one rejects.
#
# Source it, do not execute it:
#   . "$DIR/envelope_assert.sh"
#
# The Rust `assert_contract` helper in utils/signer/src/xlayer_verify_server.rs remains the
# authoritative contract; this is its shell counterpart and must keep mirroring it.

# Normative five-field envelope assertion, mirroring the Rust `assert_contract` helper in
# utils/signer/src/xlayer_verify_server.rs — that Rust helper is the authoritative contract, and
# this is its shell counterpart: existence of all five documented fields, then their exact values.
#
# Existence is asserted separately from value on purpose, because the two cheap shortcuts both
# admit a wrong envelope:
#   - a type-only check such as `.status | type == "number"` is satisfied by a wrong value (999);
#   - reading a missing key in jq yields null, so a bare `.data == null` is also true for a body
#     that omits `data` entirely.
# Neither shortcut is used below.
#
# Usage: assert_verify_fields <json> <label> <expected_status> <expected_code> <expected_msg>
# Returns the number of failed assertions (0 = every assertion passed).
assert_verify_fields() {
  if [ "$#" -ne 5 ]; then
    echo "FAIL assert_verify_fields: expected 5 arguments, got $# — a call site was not updated"
    return 1
  fi
  local json="$1" label="$2" expected_status="$3" expected_code="$4" expected_msg="$5"
  local fails=0 field actual

  if ! echo "$json" | jq -e 'type == "object"' >/dev/null 2>&1; then
    echo "FAIL $label: body is not a JSON object: $json"
    return 1
  fi

  # 1. Field existence, independent of value.
  for field in status code msg detailMsg data; do
    if ! echo "$json" | jq -e --arg f "$field" 'has($f)' >/dev/null 2>&1; then
      echo "FAIL $label: field $field is absent"
      fails=$((fails+1))
    fi
  done

  # 2. Exact protocol values.
  if ! echo "$json" | jq -e --argjson want "$expected_status" '.status == $want' >/dev/null 2>&1
  then
    actual=$(echo "$json" | jq -c '.status' 2>/dev/null)
    echo "FAIL $label: status=$actual (expected $expected_status)"
    fails=$((fails+1))
  fi
  if ! echo "$json" | jq -e --argjson want "$expected_code" '.code == $want' >/dev/null 2>&1; then
    actual=$(echo "$json" | jq -c '.code' 2>/dev/null)
    echo "FAIL $label: code=$actual (expected $expected_code)"
    fails=$((fails+1))
  fi
  if ! echo "$json" | jq -e --arg want "$expected_msg" '.msg == $want' >/dev/null 2>&1; then
    actual=$(echo "$json" | jq -c '.msg' 2>/dev/null)
    echo "FAIL $label: msg=$actual (expected \"$expected_msg\")"
    fails=$((fails+1))
  fi
  if ! echo "$json" | jq -e '.detailMsg == ""' >/dev/null 2>&1; then
    actual=$(echo "$json" | jq -c '.detailMsg' 2>/dev/null)
    echo "FAIL $label: detailMsg=$actual (expected the empty string)"
    fails=$((fails+1))
  fi
  # `has("data")` is required alongside the type check so an absent key cannot satisfy "is null".
  if ! echo "$json" | jq -e 'has("data") and (.data | type == "null")' >/dev/null 2>&1; then
    actual=$(echo "$json" | jq -c '.data' 2>/dev/null)
    echo "FAIL $label: data=$actual (expected JSON null, with the key present)"
    fails=$((fails+1))
  fi

  return $fails
}
