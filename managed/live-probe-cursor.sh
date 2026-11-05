#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
# Live Cursor probe for the managed-hooks questions (macOS). A human runs it; it needs sudo for the
# managed path and a Cursor window opened on the disposable folder it prints. Nothing here touches
# this repository, pack/ or the real receipts: every artifact lives under /tmp/fairlead-cursor-probe.
#
#   ./live-probe-cursor.sh setup a    Phase A: marker hooks. Settles precedence, exec semantics, reload.
#   ./live-probe-cursor.sh bump       Phase A: add a second managed entry (hot reload test, no restart).
#   ./live-probe-cursor.sh setup b    Phase B: real fairlead through a wrapper at the managed path.
#   ./live-probe-cursor.sh read       Print what happened, with pass/fail readings.
#   ./live-probe-cursor.sh teardown   Restore the user and managed hooks files byte for byte. ALWAYS run.
#
# Self-test without Cursor or sudo: FAIRLEAD_PROBE_MANAGED=/tmp/x/hooks.json HOME=/tmp/h SUDO= ./live-probe-cursor.sh ...
set -eu
[ "$(uname)" = Darwin ] || { echo "macOS only (managed path is /Library/Application Support/Cursor)" >&2; exit 1; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
S=/tmp/fairlead-cursor-probe
SP="/tmp/fairlead cursor probe"
M=${FAIRLEAD_PROBE_MANAGED:-/Library/Application Support/Cursor/hooks.json}
U=$HOME/.cursor/hooks.json
SUDO=${SUDO-sudo}
MARK=fairlead-probe-managed
DENY=${DENY-managed}  # which Phase A tag denies: managed (default) or user (reverse-precedence test)
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
die() { echo "$*" >&2; exit 1; }

wrap_marker() { # $1 = path; records argv, env, cwd, stdin per tag; denies only the tag "managed"
  cat > "$1" <<EOF
#!/bin/sh
tag=\$1; body=\$(cat)
case \$body in *$MARK*) ;; *) printf '%s\n' '{"permission":"allow"}'; exit 0;; esac
{ echo "tag=\$tag"; echo "pwd=\$(pwd)"; echo "prefix=\${FAIRLEAD_PREFIX-unset}"; echo "PATH=\$PATH"
  echo "CURSOR_PROJECT_DIR=\${CURSOR_PROJECT_DIR-unset}"; echo "CURSOR_VERSION=\${CURSOR_VERSION-unset}"
  echo "argc=\$#"; i=0; for a in "\$@"; do i=\$((i+1)); echo "argv\$i=\$a"; done
  echo "--- stdin ---"; printf '%s\n' "\$body"; } > "$S/out-\$tag.txt"
if [ "\$tag" = "$DENY" ]; then printf '%s\n' '{"permission":"deny","user_message":"$DENY-deny-v1"}'
else printf '%s\n' '{"permission":"allow"}'; fi
exit 0
EOF
  chmod 755 "$1"
}

put_managed() { # $1 = source file
  $SUDO mkdir -p "$(dirname "$M")"; $SUDO cp "$1" "$M"; $SUDO chmod 644 "$M"
}

phase_a_json() { # $1 = extra entry command or empty
  extra=
  [ -n "$1" ] && extra=",{\"command\":\"$1\",\"matcher\":\"$MARK\"}"
  cat <<EOF
{"version":1,"hooks":{"beforeShellExecution":[
{"command":"$S/wrap.sh managed","matcher":"$MARK"},
{"command":"FAIRLEAD_PREFIX=shell $S/wrap.sh prefix","matcher":"$MARK"},
{"command":"\"$SP/wrap.sh\" quoted","matcher":"$MARK"}$extra]}}
EOF
}

setup() {
  [ -e "$S/state" ] && die "already set up ($S/state). Run teardown first."
  [ -L "$M" ] && die "$M is a symlink: refusing (restore could not put the link back)"
  [ -L "$U" ] && die "$U is a symlink: refusing"
  mkdir -p "$S/bak" "$S/ws" "$SP"
  trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "setup failed ($rc): rolling back" >&2; [ -e "$S/state" ] && teardown; rm -rf "$S" "$SP"; fi' EXIT
  # Backups first; state is written only after every backup succeeded, so a failed backup can never
  # make teardown delete a file it never saved.
  st=
  if [ -e "$M" ]; then
    $SUDO cp -p "$M" "$S/bak/managed"
    st="$st had-managed owner=$(stat -f '%u:%g' "$M") mode=$(stat -f '%Lp' "$M")"
  else st="$st created-managed"; fi
  if [ -e "$U" ]; then cp -p "$U" "$S/bak/user"; st="$st had-user"; else st="$st created-user"; fi
  [ -d "$(dirname "$U")" ] || st="$st created-userdir"
  printf '%s\n' $st > "$S/state"
  echo "Record your Cursor plan name (Settings) now: the result only means something with it."
  case "$1" in
    a)
      wrap_marker "$S/wrap.sh"; cp "$S/wrap.sh" "$SP/wrap.sh"
      phase_a_json "" > "$S/managed.json"; put_managed "$S/managed.json"
      mkdir -p "$(dirname "$U")"
      python3 - "$U" "$S/wrap.sh" "$MARK" <<'PY'
import json, os, sys
p, wrap, mark = sys.argv[1:4]
d = json.load(open(p)) if os.path.exists(p) else {"version": 1, "hooks": {}}
d.setdefault("hooks", {}).setdefault("beforeShellExecution", []).append({"command": wrap + " user", "matcher": mark})
json.dump(d, open(p, "w"), indent=2)
PY
      cat <<EOF

Phase A is live. In a NEW Cursor window: File > Open Folder > $S/ws (trust it), then open
View > Output > Hooks. In a new agent chat send exactly:
    run exactly this shell command and nothing else: echo $MARK
Then ./live-probe-cursor.sh read.  Hot reload: ./live-probe-cursor.sh bump, send the same
command again WITHOUT restarting Cursor, read again.  Finish with ./live-probe-cursor.sh teardown.
EOF
      ;;
    b)
      bin=${FAIRLEAD_BIN:-$here/../target/debug/fairlead}; docs=$here/../pack
      [ -x "$bin" ] || die "no binary at $bin (cargo build -p fairlead-cli)"
      mkdir -p "$S/b/lib" "$S/b/pack/policies" "$S/b/pack/tests/doctor"
      b=$(CDPATH= cd -- "$S/b" && pwd -P)  # install-hooks embeds the canonical path; match it
      mkdir -p "$b/managed"
      cp "$bin" "$b/lib/fairlead"
      cp "$docs/policies/baseline.cedar" "$docs/policies/coding-agent.cedarschema" "$b/pack/policies/"
      cp "$docs/tests/doctor/cases.json" "$b/pack/tests/doctor/"
      echo "// cursor-probe: pack hash differs from the repo pack" >> "$b/pack/policies/baseline.cedar"
      # Probe wrapper: same env contract as managed/fairlead-hook, plus temp receipts and a body filter so
      # every other command in every other Cursor window passes straight through while this is installed.
      cat > "$b/lib/fairlead-hook" <<EOF
#!/bin/sh
tmp=\$(mktemp); trap 'rm -f "\$tmp"' EXIT; cat > "\$tmp"
# No match: answer allow JSON. Empty stdout with exit 0 is a block for permission hooks.
grep -a -F -q fairlead-probe-b "\$tmp" || { printf '%s\n' '{"permission":"allow"}'; exit 0; }
export FAIRLEAD_ROOT="$b/pack"
export FAIRLEAD_HOOKS="$M"
export FAIRLEAD_RECEIPTS="$b/receipts.jsonl"
export FAIRLEAD_SESSION_DIR="$b/sessions"
export FAIRLEAD_MANAGED_DIR="$b/managed"  # debug binary only: kill-switch test dir, user-writable on purpose
"$b/lib/fairlead" hook "\$@" < "\$tmp"
EOF
      chmod 755 "$b/lib/fairlead-hook"
      env -u FAIRLEAD_HOOKS -u FAIRLEAD_CLAUDE_SETTINGS FAIRLEAD_ROOT="$b/pack" "$b/lib/fairlead" install-hooks "$b/stage" >/dev/null
      sed "s|FAIRLEAD_HOOKS=[^ ]* $b/lib/fairlead hook |$b/lib/fairlead-hook |" "$b/stage/.cursor/hooks.json" > "$b/managed.json"
      ! grep -q "$b/lib/fairlead hook " "$b/managed.json" || die "a staged command still calls the binary directly"
      put_managed "$b/managed.json"
      env -u FAIRLEAD_CLAUDE_SETTINGS FAIRLEAD_ROOT="$b/pack" FAIRLEAD_HOOKS="$M" "$b/lib/fairlead" arm > "$b/arm.txt" 2>&1 || { cat "$b/arm.txt" >&2; die "arm failed"; }
      cat <<EOF

Phase B is live (managed file armed against a temp pack; only commands containing fairlead-probe-b
reach fairlead, everything else gets allow JSON from the wrapper). In a NEW Cursor window open $S/ws, then
View > Output > Hooks, and send exactly:
    run exactly this shell command and nothing else: curl -s https://example.invalid/fairlead-probe-b
Expected: Cursor shows a Fairlead deny and the curl does not run. Then ./live-probe-cursor.sh read,
then teardown.
EOF
      ;;
    *) die "usage: setup a|b" ;;
  esac
}

bump() {
  [ -e "$S/state" ] || die "run setup a first"
  [ -f "$S/managed.json" ] || die "bump is Phase A only"
  phase_a_json "$S/wrap.sh bumped" > "$S/managed2.json"; put_managed "$S/managed2.json"
  rm -f "$S/out-bumped.txt"
  echo "managed file rewritten with an extra 'bumped' entry. Send the echo command again without restarting Cursor."
}

show() { [ -f "$1" ] && { echo "== $1"; cat "$1"; } || echo "== $1: MISSING"; }

read_() {
  [ -e "$S/state" ] || die "nothing set up"
  if [ -f "$S/managed.json" ]; then
    for t in managed user prefix quoted bumped; do show "$S/out-$t.txt"; done
    cat <<EOF

Readings (Phase A):
 both out-managed and out-user exist, and the echo did not run   -> every source runs, deny wins
 only out-user                                                   -> the OS managed file was NOT loaded (plan, path or permissions)
 out-prefix.txt exists with prefix=shell                         -> Cursor runs command through a shell (FOO=bar prefix works)
 out-prefix.txt MISSING, out-managed exists                      -> no shell: env prefix is dead (on 3.6.21 / macOS the file existed)
 out-quoted.txt exists with argv1=quoted                         -> quoted path with a space works
 out-managed.txt pwd = /Library/Application Support/Cursor       -> enterprise cwd rule confirmed
 out-bumped.txt appears with no restart                          -> hot reload of the managed file works
Also read View > Output > Hooks: 'No enterprise hooks configuration found' means the file did not load.
EOF
  else
    b=$S/b; show "$b/arm.txt"
    if [ -s "$b/receipts.jsonl" ]; then
      last=$(tail -1 "$b/receipts.jsonl")
      rh=$(printf '%s' "$last" | grep -o '"hooks_sha256": *"[0-9a-f]\{64\}"' | grep -o '[0-9a-f]\{64\}')
      echo "decision: $(printf '%s' "$last" | grep -o '"decision": *"[a-z]*"')"
      echo "receipt hooks_sha256 = $rh"; echo "sha256(managed)      = $(sha "$M")"
      [ -f "$U" ] && echo "sha256(user)         = $(sha "$U")"
      [ "$rh" = "$(sha "$M")" ] && echo "PASS: receipt names the managed file" || echo "FAIL: receipt hooks hash is not the managed file"
      echo "signature: $(FAIRLEAD_ROOT="$b/pack" "$b/lib/fairlead" verify-receipt "$b/receipts.jsonl" 2>&1 | tail -1)"
    else
      echo "FAIL: no receipt. Either Cursor never exec'd the wrapper from the managed file, or the body filter skipped it."
    fi
    echo "Also read View > Output > Hooks: the exec'd command should be $b/lib/fairlead-hook cursor shell."
  fi
}

teardown() {
  [ -e "$S/state" ] || { echo "nothing to tear down"; return 0; }
  # Remove a file only when state says setup created it; an empty or odd state deletes nothing.
  if grep -q had-managed "$S/state"; then
    own=$(sed -n 's/.*owner=\([0-9]*:[0-9]*\).*/\1/p' "$S/state"); mode=$(sed -n 's/.*mode=\([0-7]*\).*/\1/p' "$S/state")
    $SUDO cp "$S/bak/managed" "$M"; $SUDO chown "$own" "$M"; $SUDO chmod "$mode" "$M"
  elif grep -q created-managed "$S/state"; then $SUDO rm -f "$M"; fi
  if grep -q had-user "$S/state"; then cp -p "$S/bak/user" "$U"
  elif grep -q created-user "$S/state"; then rm -f "$U"; fi
  if grep -q created-userdir "$S/state"; then rmdir "$(dirname "$U")" 2>/dev/null || true; fi
  rm -rf "$S" "$SP"
  echo "restored. managed: $( [ -f "$M" ] && echo present || echo absent ); user hooks: $( [ -f "$U" ] && echo present || echo absent )"
}

case "${1-}" in
  setup) setup "${2-}" ;; bump) bump ;; read) read_ ;; teardown) teardown ;;
  *) sed -n '2,13p' "$0"; exit 1 ;;
esac
