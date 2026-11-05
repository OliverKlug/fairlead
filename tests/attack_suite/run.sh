#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
# Named attack-suite runner. Not a second Cedar engine.
# From the repository root: ./tests/attack_suite/run.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

CASES="$ROOT/tests/attack_suite/cases.txt"
fail=0

echo "cargo test --workspace --locked"
if ! cargo test --workspace --locked -- --test-threads=1; then
  fail=1
fi

echo
echo "attack suite case IDs"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ''|\#*) continue ;;
  esac
  id=$(printf '%s\n' "$line" | awk '{print $1}')
  slug=$(printf '%s\n' "$line" | awk '{print $2}')
  filter=$(printf '%s\n' "$line" | awk '{print $3}')
  if [ "$filter" = "SKIP-P1" ]; then
    echo "CASE $id $slug ... P1 skipped"
    continue
  fi
  echo "CASE $id $slug ($filter)"
  if ! cargo test --locked -p fairlead-core --lib "$filter" -- --test-threads=1; then
    fail=1
  fi
  if [ "$id" = "14" ]; then
    echo "CASE 14 ent_unsigned_pack ... P1 Ent unsigned pack skipped"
  fi
done < "$CASES"

echo
echo "fairlead doctor"
set +e
doc_out=$(cargo run --locked -p fairlead-cli --quiet -- doctor 2>&1)
doc=$?
set -e
printf '%s\n' "$doc_out"
if [ "$doc" -ne 0 ]; then
  # Local last-armed.json pins a prior binary. Fixtures + residual still ran.
  # Pack drift is a real refuse-auto-arm; binary/hooks drift is re-arm locally.
  if printf '%s\n' "$doc_out" | grep -q "residual: prompt injection not solved" \
    && printf '%s\n' "$doc_out" | grep -q "residual: local admin can uninstall (F-BYP-10)" \
    && printf '%s\n' "$doc_out" | grep -q "doctor-pytest-allow Deny" \
    && printf '%s\n' "$doc_out" | grep -q "hash drifted; fairlead arm" \
    && ! printf '%s\n' "$doc_out" | grep -q "pack hash drifted"; then
    echo "doctor: fixtures+residual ok; last-armed binary/hooks drift (fairlead arm)"
  else
    fail=1
  fi
fi

echo
echo "CASE 13 doctor FAIRLEAD_HOOKS=hooks-missing-failclosed.json (expect refuse)"
set +e
FAIRLEAD_HOOKS="$ROOT/tests/fixtures/hooks-missing-failclosed.json" \
  cargo run --locked -p fairlead-cli --quiet -- doctor
doc13=$?
set -e
if [ "$doc13" -eq 0 ]; then
  echo "CASE 13 doctor spawn: expected refuse, got exit 0"
  fail=1
else
  echo "CASE 13 doctor spawn: refuse to arm (exit $doc13)"
fi

if [ "$fail" -ne 0 ]; then
  echo "attack suite: FAIL"
  exit 1
fi
echo "attack suite: ok"
exit 0
