#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
# Pre-ship check for the enterprise bundle. Builds a real install layout in a temp dir (binary
# and pack away from the build tree, a space in the managed hooks path), stages and rewrites the
# hooks the way README.md says, arms with FAIRLEAD_HOOKS, then runs the hook the way Cursor execs
# it (argv split on spaces, no shell, no inherited FAIRLEAD_* env). Optional real-osquery pass:
#   OSQUERYD=/path/to/osqueryd ./check-install.sh
# Needs a built binary: cargo build -p fairlead-cli (FAIRLEAD_BIN overrides the path).
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
app=$here/..
bin=${FAIRLEAD_BIN:-$app/target/debug/fairlead}
docs=$app/pack
[ -x "$bin" ] || { echo "no binary at $bin (cargo build -p fairlead-cli)" >&2; exit 1; }
T=$(mktemp -d); T=$(cd "$T" && pwd -P)
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL $*" >&2; exit 1; }
ok() { echo "ok   $*"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
h64() { grep -o "\"$1\": *\"[0-9a-f]\{64\}\"" | tail -1 | grep -o '[0-9a-f]\{64\}'; }

inst=$T/lib/fairlead; pack=$T/share/fairlead; hooks="$T/managed/Application Support/Cursor/hooks.json"
mkdir -p "$inst" "$pack/policies" "$pack/tests/doctor" "$(dirname "$hooks")"
cp "$bin" "$inst/fairlead"
cp "$docs/policies/baseline.cedar" "$docs/policies/coding-agent.cedarschema" "$pack/policies/"
cp "$docs/tests/doctor/cases.json" "$pack/tests/doctor/"
echo "// enterprise-check: pack hash must differ from the build-tree pack" >> "$pack/policies/baseline.cedar"

wrap=$inst/fairlead-hook
sed -e "s|^export FAIRLEAD_ROOT=.*|export FAIRLEAD_ROOT=$pack|" \
    -e "s|^export FAIRLEAD_HOOKS=.*|export FAIRLEAD_HOOKS=\"$hooks\"|" \
    -e "s|^exec .*|exec $inst/fairlead hook \"\$@\"|" "$here/fairlead-hook" > "$wrap"
chmod 755 "$wrap"
grep -q "^export FAIRLEAD_ROOT=$pack\$" "$wrap" || fail "wrapper FAIRLEAD_ROOT not rewritten"

# doctor/arm read Claude settings scopes: point them at empty temp dirs, not the operator's ~/.claude.
mkdir -p "$T/home"; iso="-u CLAUDE_CONFIG_DIR HOME=$T/home FAIRLEAD_CLAUDE_MANAGED_DIR=$T/no-claude-managed"

# Stage from the installed binary, point commands at the wrapper, drop at the managed path.
env -u FAIRLEAD_HOOKS -u FAIRLEAD_CLAUDE_SETTINGS FAIRLEAD_ROOT="$pack" "$inst/fairlead" install-hooks "$T/stage" >/dev/null
sed "s|FAIRLEAD_HOOKS=[^ ]* $inst/fairlead hook |$wrap |" "$T/stage/.cursor/hooks.json" > "$hooks"
! grep -q "$inst/fairlead hook " "$hooks" || fail "a hook command still calls the binary directly"
ok "managed hooks.json written; every command is the space-free wrapper path"

armed=$(env -u FAIRLEAD_CLAUDE_SETTINGS $iso FAIRLEAD_ROOT="$pack" FAIRLEAD_HOOKS="$hooks" "$inst/fairlead" arm)
a_bin=$(echo "$armed" | sed -n 's/^binary_sha256: //p'); a_pack=$(echo "$armed" | sed -n 's/^policy_pack_sha256: //p')
a_hooks=$(echo "$armed" | sed -n 's/^hooks_sha256: //p')
[ "$a_hooks" = "$(sha "$hooks")" ] || fail "hooks_sha256 is not sha256(managed file)"
[ "$a_bin" = "$(sha "$inst/fairlead")" ] || fail "binary_sha256 is not sha256(installed binary)"
env -u FAIRLEAD_CLAUDE_SETTINGS $iso FAIRLEAD_ROOT="$pack" FAIRLEAD_HOOKS="$hooks" "$inst/fairlead" doctor >/dev/null 2>&1 \
  || fail "doctor refuses the rewritten managed hooks"
ok "arm pins sha256(file) and sha256(binary); doctor accepts the rewritten file"

# Run the hook the strict way: split the command on spaces, no shell, clean env (Cursor 3.6.21 on
# macOS uses a shell, so this is the harder case; it must work either way).
body='{"conversation_id":"conv-e2e","command":"ls","cwd":"/tmp/ws","sandbox":true}'
run_cmd() { # $1 = command string split on spaces like Cursor does, receipts path in $RCPT
  set -f; set -- $1; set +f
  printf '%s\n' "$body" | env -i PATH="$PATH" HOME="$HOME" FAIRLEAD_RECEIPTS="$RCPT" FAIRLEAD_SESSION_DIR="$T/sessions" "$@" >/dev/null
}
cmd=$(sed -n 's/.*"command": "\(.*cursor shell\)".*/\1/p' "$hooks" | head -1)
[ -n "$cmd" ] || fail "no shell hook command found"
RCPT=$T/r-wrapper.jsonl; run_cmd "$cmd" || fail "hook via wrapper did not allow ls"
[ "$(h64 hooks_sha256 < "$T/r-wrapper.jsonl")" = "$a_hooks" ] || fail "receipt hooks_sha256 != pin (FAIRLEAD_HOOKS did not reach the hook)"
[ "$(h64 policy_pack_sha256 < "$T/r-wrapper.jsonl")" = "$a_pack" ] || fail "receipt pack != installed pack (FAIRLEAD_ROOT did not reach the hook)"
[ "$(h64 binary_sha256 < "$T/r-wrapper.jsonl")" = "$a_bin" ] || fail "receipt binary != pin"
ok "hook exec'd from an argv split reads the installed pack; receipt hashes equal the pin"

# Without the wrapper the same binary stamps the wrong pack and the absent-hooks hash.
RCPT=$T/r-direct.jsonl; run_cmd "$inst/fairlead hook cursor shell" || true
if [ -s "$T/r-direct.jsonl" ]; then
  [ "$(h64 hooks_sha256 < "$T/r-direct.jsonl")" != "$a_hooks" ] || fail "direct call unexpectedly carries the pin"
  [ "$(h64 policy_pack_sha256 < "$T/r-direct.jsonl")" != "$a_pack" ] || fail "direct call unexpectedly used the installed pack"
  ok "negative control: calling the binary directly stamps a different pack and hooks hash"
else
  ok "negative control: calling the binary directly writes no receipt (no pack found)"
fi

# Real osquery, if provided.
if [ -z "${OSQUERYD:-}" ] || [ ! -x "${OSQUERYD:-}" ]; then
  echo "skip real osquery (set OSQUERYD=/path/to/osqueryd)"; echo "install check: pass"; exit 0
fi
base=$(grep -v '^--' "$here/fleet-pin-policy.sql")
mkq() { printf '%s\n' "$base" | sed -e "s|@HOOKS_PATH@|$hooks|" -e "s|@HOOKS_SHA256@|$(sha "$hooks")|" \
  -e "s|@BIN_PATH@|$inst/fairlead|" -e "s|@BIN_SHA256@|$(sha "$inst/fairlead")|" \
  -e "s|@WRAP_PATH@|$wrap|" -e "s|@WRAP_SHA256@|$(sha "$wrap")|" \
  -e "s|@CEDAR_PATH@|$pack/policies/baseline.cedar|" -e "s|@CEDAR_SHA256@|$(sha "$pack/policies/baseline.cedar")|" \
  -e "s|@SCHEMA_PATH@|$pack/policies/coding-agent.cedarschema|" -e "s|@SCHEMA_SHA256@|$(sha "$pack/policies/coding-agent.cedarschema")|"; }
rows() { "$OSQUERYD" -S --json "$1" | grep -c '"1"' || true; }
want() { [ "$(rows "$2")" = "$1" ] || fail "osquery: $3 (want $1 row)"; ok "osquery: $3"; }
ide=$("$OSQUERYD" -S --json "select 1 from processes where lower(name) in ('cursor','cursor-agent','claude');" | grep -c '"1"' || true)
q=$(mkq)
if [ "$ide" -gt 0 ]; then
  want 1 "$q" "IDE running, all three files match: pass"
  cp "$hooks" "$T/hooks.bak"; echo " " >> "$hooks"
  want 0 "$q" "IDE running, managed hooks.json edited by one byte: FAIL"
  cp "$T/hooks.bak" "$hooks"
  cp "$wrap" "$T/wrap.bak"; echo "# edit" >> "$wrap"
  want 0 "$q" "IDE running, wrapper edited: FAIL"
  cp "$T/wrap.bak" "$wrap"; chmod 755 "$wrap"
  cp "$pack/policies/baseline.cedar" "$T/cedar.bak"; echo "// tamper" >> "$pack/policies/baseline.cedar"
  want 0 "$q" "IDE running, baseline.cedar edited by one line: FAIL"
  cp "$T/cedar.bak" "$pack/policies/baseline.cedar"
  mv "$hooks" "$T/hooks.moved"
  want 0 "$q" "IDE running, hooks.json deleted: FAIL"
  mv "$T/hooks.moved" "$hooks"
  want 1 "$q" "restored: pass again"
else
  echo "skip IDE-running osquery cases: no Cursor/cursor-agent/claude process on this machine"
fi
mv "$hooks" "$T/hooks.moved"
want 1 "$(printf '%s\n' "$q" | sed 's|FROM processes WHERE (|FROM processes WHERE 0 AND (|')" "no IDE process, hooks.json deleted: pass (never page a closed IDE)"
mv "$T/hooks.moved" "$hooks"
echo "install check: pass"
