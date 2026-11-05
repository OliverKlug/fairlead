-- Fleet / osquery policy (a returned row is PASS). Goal 11 pin (F-BYP-08); no heartbeat.
-- Replace the ten @...@ values with: the managed hooks file path and sha256, the installed
-- fairlead binary path and sha256, the installed fairlead-hook wrapper path and sha256, and the
-- installed policies/baseline.cedar and policies/coding-agent.cedarschema path and sha256
-- (`fairlead doctor` prints the hooks and binary hashes; `shasum -a 256` the rest). The pack
-- rows are there because the hook signs an allow with whatever pack is on disk (live probe
-- 2026-10-10: an edited baseline.cedar was loaded, allowed, and stamped with the new hash).
-- hooks_sha256 equals sha256(file) only when FAIRLEAD_CLAUDE_SETTINGS is unset at arm time.
--
-- PASS when no IDE agent is running (closed or idle; a sleeping host usually returns no result, which Fleet does not count as a fail), or when one is
-- running and all five pinned files hash to the armed value. Missing file, unreadable file, or a
-- different digest returns zero rows, which Fleet marks as failing.
-- Receipt age is deliberately not in this query: quiet receipts are normal while the IDE is idle.
-- Every pinned file must stay under osquery read_max (default 50MB): above it the hash columns
-- come back empty and this policy fails on a healthy seat. The release binary is about 10MB.
-- Process arms match the main executable only. Never use LIKE '%cursor%': it hits "Cursor Helper"
-- processes that linger after quit and would page a closed IDE. macOS reports name = basename of
-- the executable ("Cursor"); Windows reports "Cursor.exe"; the native Claude Code installer runs
-- from .../claude/versions/<version>, so its name can be the version, not "claude". Known misses:
-- cursor-agent execs node, Claude.app's main binary is "Claude", and an npm-fallback Claude Code
-- runs as node. Run `SELECT name, path FROM processes WHERE path LIKE '%laude%' OR path LIKE
-- '%ursor%'` with the IDE open on each OS and delete any arm that never hits.
SELECT 1 WHERE
  NOT EXISTS (SELECT 1 FROM processes WHERE (
    lower(name) IN ('cursor', 'cursor.exe', 'cursor-agent', 'cursor-agent.exe', 'claude', 'claude.exe')
    OR path LIKE '%/Cursor.app/Contents/MacOS/Cursor'
    OR path LIKE '%\Cursor.exe'
    OR path LIKE '%/claude/versions/%'
    OR path LIKE '%\claude.exe'
  ))
  OR (
    EXISTS (SELECT 1 FROM hash WHERE path = '@HOOKS_PATH@' AND sha256 = '@HOOKS_SHA256@')
    AND EXISTS (SELECT 1 FROM hash WHERE path = '@BIN_PATH@' AND sha256 = '@BIN_SHA256@')
    AND EXISTS (SELECT 1 FROM hash WHERE path = '@WRAP_PATH@' AND sha256 = '@WRAP_SHA256@')
    AND EXISTS (SELECT 1 FROM hash WHERE path = '@CEDAR_PATH@' AND sha256 = '@CEDAR_SHA256@')
    AND EXISTS (SELECT 1 FROM hash WHERE path = '@SCHEMA_PATH@' AND sha256 = '@SCHEMA_SHA256@')
  );
