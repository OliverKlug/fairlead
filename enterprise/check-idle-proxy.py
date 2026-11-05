#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
"""Local stand-in for the Fleet policy loop: osqueryd runs fleet-pin-policy.sql on a short snapshot
schedule while the pinned files are edited, deleted and restored. Proves the predicate under a real
scheduler, NOT Fleet: no policy interval, no policy_membership, no webhooks, no asleep-host state.

    OSQUERYD=/path/to/osqueryd python3 enterprise/check-idle-proxy.py

Needs a running Cursor/cursor-agent/claude process for the IDE-running phases (it says so and exits
otherwise). Snapshot mode is deliberate: differential mode logs nothing for a stable zero-row FAIL.
"""
import json, os, re, subprocess, sys, tempfile, time, hashlib
from pathlib import Path

INTERVAL_S = 2      # schedule interval for both queries
PHASE_S = 8         # how long each phase holds (several snapshots per phase)
SETTLE_S = 3        # snapshots this close to a mutation are ignored (a tick can straddle it)

osqueryd = os.environ.get("OSQUERYD", "")
if not osqueryd or not os.access(osqueryd, os.X_OK):
    sys.exit("set OSQUERYD=/path/to/osqueryd")
here = Path(__file__).resolve().parent
sql_src = "\n".join(l for l in (here / "fleet-pin-policy.sql").read_text().splitlines() if not l.startswith("--"))


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


D = Path(tempfile.mkdtemp(prefix="fl-idle-")).resolve()
files = {"hooks": D / "hooks.json", "bin": D / "fairlead", "wrap": D / "fairlead-hook",
         "cedar": D / "baseline.cedar", "schema": D / "coding-agent.cedarschema"}
for k, p in files.items():
    p.write_text(f"original {k}\n")
pinned = {k: sha(p) for k, p in files.items()}
sql = (sql_src.replace("@HOOKS_PATH@", str(files["hooks"])).replace("@HOOKS_SHA256@", pinned["hooks"])
       .replace("@BIN_PATH@", str(files["bin"])).replace("@BIN_SHA256@", pinned["bin"])
       .replace("@WRAP_PATH@", str(files["wrap"])).replace("@WRAP_SHA256@", pinned["wrap"])
       .replace("@CEDAR_PATH@", str(files["cedar"])).replace("@CEDAR_SHA256@", pinned["cedar"])
       .replace("@SCHEMA_PATH@", str(files["schema"])).replace("@SCHEMA_SHA256@", pinned["schema"]))
assert "@" not in sql, "unfilled placeholder"
sql_noide = sql.replace("FROM processes WHERE (", "FROM processes WHERE 0 AND (")
assert sql_noide != sql, "no-IDE variant did not change the query"

probe = subprocess.run([osqueryd, "-S", "--json", "SELECT 1 FROM processes WHERE lower(name) IN "
                        "('cursor','cursor-agent','claude') OR path LIKE '%/Cursor.app/Contents/MacOS/Cursor';"],
                       capture_output=True, text=True, check=True)
ide_running = '"1"' in probe.stdout
if not ide_running:
    sys.exit("no Cursor/cursor-agent/claude process is running: the IDE-running phases cannot be exercised")

cfg = D / "osquery.conf"
cfg.write_text(json.dumps({"options": {"schedule_splay_percent": 0},
                           "schedule": {"pin": {"query": sql, "interval": INTERVAL_S, "snapshot": True},
                                        "pin_noide": {"query": sql_noide, "interval": INTERVAL_S, "snapshot": True}}}))
logs = D / "logs"
logs.mkdir()
proc = subprocess.Popen([osqueryd, "--ephemeral", "--disable_watchdog", "--disable_extensions", "--disable_events",
                         "--disable_audit", "--force", f"--config_path={cfg}", "--config_plugin=filesystem",
                         "--logger_plugin=filesystem", f"--logger_path={logs}", f"--database_path={D/'db'}",
                         f"--pidfile={D/'pid'}"],
                        stdout=subprocess.DEVNULL, stderr=(D / "osqueryd.err").open("w"), text=True)


def put(p: Path, text: str) -> None:
    tmp = p.with_name(p.name + ".tmp")  # atomic: a snapshot never reads a half-written file
    tmp.write_text(text)
    os.replace(tmp, p)


def mutate(kind: str) -> None:
    if kind == "edit":
        put(files["hooks"], "edited hooks\n")
    elif kind == "delete":
        files["hooks"].unlink()
    elif kind == "restore":
        put(files["hooks"], "original hooks\n")
    elif kind == "swap-bin":
        put(files["bin"], "swapped bin\n")
    elif kind == "restore-bin":
        put(files["bin"], "original bin\n")


# (label, mutation applied at the start of the phase, expected pin rows>0, expected no-IDE rows>0)
phases = [("IDE running, all three files match", None, True, True),
          ("IDE running, hooks.json edited", "edit", False, True),
          ("IDE running, hooks.json restored", "restore", True, True),
          ("IDE running, hooks.json deleted", "delete", False, True),
          ("IDE running, hooks.json restored", "restore", True, True),
          ("IDE running, binary swapped", "swap-bin", False, True),
          ("IDE running, binary restored", "restore-bin", True, True)]
t0 = time.time()
spans = []
try:
    time.sleep(1)
    if proc.poll() is not None:
        sys.exit("osqueryd exited at startup:\n" + (D / "osqueryd.err").read_text())
    time.sleep(INTERVAL_S + 1)  # let the first snapshot land on the unmodified files
    for label, mut, *_ in phases:
        if mut:
            mutate(mut)
        start = time.time()
        time.sleep(PHASE_S)
        spans.append((label, start, time.time()))
finally:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

snaps = []
log = logs / "osqueryd.snapshots.log"
if log.exists():
    for line in log.read_text().splitlines():
        r = json.loads(line)
        snaps.append((float(r["unixTime"]), r["name"], len(r["snapshot"])))  # KeyError on a missing key is a failure, not zero rows
if not snaps:
    sys.exit("osqueryd wrote no snapshots:\n" + (D / "osqueryd.err").read_text())

if os.environ.get("IDLE_DEBUG"):
    base = min(ts for ts, _, _ in snaps)
    for label, start, end in spans:
        print(f"span {label}: {start - base:.1f}..{end - base:.1f}")
    print("pin rows by tick:", [(round(ts - base), rows) for ts, n, rows in snaps if n == "pin"])
bad = 0
for (label, start, end), (_, _, want_pin, want_noide) in zip(spans, phases):
    inside = [(n, rows) for ts, n, rows in snaps if start + SETTLE_S <= ts and ts + 1 <= end]  # unixTime is floored to whole seconds
    for name, want in (("pin", want_pin), ("pin_noide", want_noide)):
        got = [rows > 0 for n, rows in inside if n == name]
        ok = bool(got) and all(g == want for g in got)
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {label:40s} {name:9s} want {'row' if want else 'zero rows'}, saw {len(got)} snapshots {sorted(set(got))}")
print("idle proxy: " + ("all phases pass" if not bad else f"{bad} FAILED"))
print(f"(run took {time.time() - t0:.0f}s; artifacts in {D})")
sys.exit(1 if bad else 0)
