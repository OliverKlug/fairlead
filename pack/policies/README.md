# Fairlead policy pack (agent contract)

Load `coding-agent.cedarschema` + `baseline.cedar`. Do not invent a parallel policy language.

**Adapter job:** parse shell/MCP/path into booleans, then Cedar. Cedar never sees raw “is this dangerous?” LLM output.

## Context record (required every request)

Matches `Fairlead::DecisionContext`. Fill **all** fields. Empty string / empty set / `false` / `0` if unknown. Never omit (Cedar skip-on-error).

| Field | Type | Who sets it |
|---|---|---|
| `command` | String | hook stdin (shell) or `""` |
| `cwd` | String | hook |
| `sandbox` | Bool | hook |
| `argv0` | String | first token of command, else `""` |
| `argv0_is_boring` | Bool | argv0 ∈ {`ls`,`rg`,`grep`,`git`,`pytest`,`python`,`python3`,`npm`,`npx`,`cargo`,`go`,`tsc`,`node`} or `python3.<digit>` **and** no `&&`/`\|`/`curl`/`wget`/`nc` in command |
| `command_looks_like_network` | Bool | argv0 or args match curl/wget/nc/ssh/scp or URL/`0.0.0.0` bind; loopback in command or MCP tool_input; python/node script-body markers (`http.client`, `http.server`, …); `python`/`python3`/`node` `-m` unless exact token is `pytest`/`unittest`/`doctest` (that Clean is still F-DEF-09); `node --eval`/`--print`/`-p`/`-pe`/glued `--eval=` same as `-e`; FileWrite of SCRIPT_EXT: hook JSON `contents`/`content` via `inspect_inline_body` only (no flatten_scan loopback) |
| `path_is_sensitive` | Bool | path (raw, argv token, or canonical/symlink target) under `.git/hooks`, `.git/config`, `.cursor/mcp.json`, `~/.cursor/**/mcp.json`, shell rc, `.env`, `*.pem`, `*/credentials*`, SSH keys; opaque symlink; `git` + `--no-verify` / `git commit -n` / `hooksPath=` / `git config` write of hooksPath; `$(...)` / backticks; unquoted or double-quoted `$ident` / `${...}` (fail-closed, do not exec) |
| `mcp_is_write` | Bool | tool name/schema looks mutating (write/create/update/delete/push/send) |
| `tool_name` | String | MCP tool or `""` |
| `provenance` | Set\<String\> | union of arg tags + session; coarse tags `web`/`mcp`/`subagent`/… |
| `granted_caps` | Set\<String\> | session grants: `net.egress`, `secrets.read`, `mcp.write` |
| `parent_caps` | Set\<String\> | parent envelope; copy of parent `granted_caps` (full set if not a subagent) |
| `session.touched_secrets` | Bool | prior FileRead/Shell hit sensitive path |
| `session.saw_untrusted_web` | Bool | prior Fetch/web |
| `session.saw_mcp_untrusted` | Bool | prior MCP result tagged untrusted |
| `session.subagent_active` | Bool | inside Task/subagent child session |
| `session.secret_read_count` | Long | count of sensitive reads this session |

`parent_caps` when **not** a subagent: set equal to `granted_caps` so F-SUB forbids do not fire on the parent.

## Entities

- `principal`: `Fairlead::Agent::"<harness>:<session>"`
- `resource`: `Fairlead::Resource::"<path-or-tool-or-workspace>"`
- `action`: `Fairlead::Action::"Shell"` \| `"McpCall"` \| `"FileRead"` \| `"FileWrite"` \| `"Fetch"` \| `"SubagentStart"`

## Doctor

`tests/doctor/cases.json` — `fairlead doctor` must Allow/Deny exactly as `expect`. Fail closed: if Cedar errors, treat as Deny **and** refuse to arm. Cases with `"live_argv": true` fill context from `command` via the adapter (`filled_context`); preset booleans are ignored. `arm` re-runs the same fixtures on the pack bytes it is about to pin. `--i-reviewed-pack` accepts pack-hash drift only; it never skips fixtures.

## ponytail

`F-Q-ARG` (Goal 10) reads the optional `context.argument_from_untrusted`. The Controller sets it when `handles.jsonl` in the session dir has a record. The call's bytes are not the predicate. All four host adapters fill it (Cursor directly; Windsurf and OpenHands via `cursor_hook_eval_in`; Claude in `claude_tool_gate_in`), pinned per host by `suite10_value_forbid_fires_on_every_host_adapter`. The forbid fires on Shell, Fetch, McpCall, and FileWrite while that record is live, including `python3 -c "print(1)"` and `ls` (`suite10_boring_shell_carrying_title_is_denied`) and `python3 clean.py` (`suite10_script_file_carrying_title_is_denied`). No record, and a boring shell stays `F-DEF-06`. It is not exempted by `net.egress`. Ceiling: one file taints every conversation in that dir. No `cases.json` row: `context has` makes it unreachable from the doctor fixtures, so it is covered by `suite10_*`.

`argv0_is_boring` / `command_looks_like_network` / `path_is_sensitive` are adapter heuristics (string features), not a full argv AST. Ceiling: chained `safe && curl` must set `command_looks_like_network=true`. Shell write to `.git/hooks` inside `python -c` / `open(` sets `path_is_sensitive` (F-DEF-01). Loopback in MCP tool_input sets `command_looks_like_network` (F-DEF-03). F-DEF-03 also forbids FileWrite when that bool is set; net-on-Write is SCRIPT_EXT JSON `contents` then `content` via `inspect_inline_body` only (do not OR `looks_like_loopback(flatten_scan)` or README `127.0.0.1` Denies). Missing both keys Skip (Edit leftover). POSIX-split argv tokens union into `path_is_sensitive` (`git show .env`, `ls .git/hooks`). `$''` ANSI-C is decoded in the splitter (`ls $'.env'`, `$'\x2eenv'`). `$(...)` / backticks fail closed (do not exec). Unquoted / double-quoted `$ident` / `${...}` fail closed in the splitter quote machine (do not exec; `ls $FILE` Deny). Named FPs: `echo $PATH` is already default-deny (`echo` not BORING); `git commit -m '$HOME'` Allow (single-quoted); `rg $PAT` / `git commit -m "$HOME"` Deny. `python leak.py` / `node x.js` size-capped body scan (256 KiB) ORs into `command_looks_like_network`; missing/over-cap/non-UTF8 Deny. `python -m` / `node -m` stays Clean for exact tokens `pytest`/`unittest`/`doctest` and Deny otherwise (`python -m http.server` is F-DEF-03; `python -m pytest` is F-DEF-09). Glued `-mhttp.server` and missing `-m` operand Deny. Ceiling: next Safe Auto-run module (`ruff`) is a list add; next CPython server module is already Deny. `python3` and `python3.<digit>` (e.g. `python3.12`) are in BORING and INTERPRETERS (`python3.12 -m pytest` is F-DEF-09; `python3.12 -m http.server` Deny). Do not glob `python3*` (`python3-config`). File-run `import http.server` hits the same body markers. FileWrite of SCRIPT_EXT (`py|pyw|js|mjs|cjs`) is the JSON-body scan above, not this Shell file scan. `git` + `--no-verify` or `git commit -n` / `-an` or `hooksPath=` / `git config` write of hooksPath ORs into `path_is_sensitive` (not a path; keep the overload, no F-DEF-09 schema field unless a fixture cannot map). `git push -n` / `git merge -n` stay Allow. `git config --get core.hooksPath` stays Allow. Symlink canonicalize (incl. dangling `read_link`, depth 40) before the boolean. TOCTOU vs the agent's later open is residual, not a Cedar field: Shell `inspect_script` `File::open` at T0 vs host exec at T1 (same class as Read/Write). Upgrade: host `O_NOFOLLOW` / sandbox. Leftover: wrappers as program identity (`sudo` / `bash -c` already miss F-DEF-06). `node --eval` / `--print` / `-p` / `-pe` / glued `--eval=` scan like `-e`. `node -r` / `--require` / glued `--require=` consume before `-e`; path-like and cwd SCRIPT_EXT files are scanned; package names (`ts-node/register`) are specifier-string only. Markers include `child_process`, `http.createServer`, `net.createServer`, `https.createServer`, `tls.createServer`, `http2.createServer`, `http2.createSecureServer`. Leftovers: `--import`; `NODE_OPTIONS=--require`; host stdin / flags-only / REPL (token `-` closed); Edit/`new_string`. Doctor live-argv covers eleven strings; other splitter inputs stay CI-only. Upgrade: S1 tree-sitter when a wrapper fixture of that form must Deny.
