// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ed25519_dalek::SigningKey;

pub const HOOKS_ABSENT_DOMAIN: &[u8] = b"fairlead:hooks:absent\0";
pub const PACK_DOMAIN: &[u8] = b"fairlead:policy-pack:v1\0";
const REQUIRED_HOOK_EVENTS: [&str; 3] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashTriple {
    pub binary_sha256: String,
    pub policy_pack_sha256: String,
    pub hooks_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LastArmed {
    pub v: u32,
    pub binary_sha256: String,
    pub policy_pack_sha256: String,
    pub hooks_sha256: String,
    /// Org-signed update counter (managed pin only). Absent in older pins means 0.
    #[serde(default)]
    pub generation: u64,
}

#[derive(Clone, Debug)]
pub struct TcbSnapshot {
    pub hashes: HashTriple,
    pub hooks_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArmedDrift {
    Pack { old: String, new: String },
    Binary { old: String, new: String },
    Hooks { old: String, new: String },
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}

pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(to_hex(&hasher.finalize()))
}

pub fn pack_hash(schema: &[u8], cedar: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PACK_DOMAIN);
    hasher.update(Sha256::digest(schema));
    hasher.update(Sha256::digest(cedar));
    to_hex(&hasher.finalize())
}

pub fn hooks_hash(file_bytes: Option<&[u8]>) -> String {
    match file_bytes {
        Some(bytes) => sha256_hex(bytes),
        None => sha256_hex(HOOKS_ABSENT_DOMAIN),
    }
}

pub fn hash_current_exe() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    sha256_file(&exe)
}

pub fn last_armed_path(root: &Path) -> PathBuf {
    root.join("last-armed.json")
}

/// Cargo workspace root, not the pack.
pub fn app_workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Default receipts live next to the crates, never under `pack/`.
/// Override with `FAIRLEAD_RECEIPTS`.
pub fn receipts_path() -> PathBuf {
    if let Ok(p) = std::env::var("FAIRLEAD_RECEIPTS") {
        return PathBuf::from(p);
    }
    let app = app_workspace();
    match fs::canonicalize(&app) {
        Ok(c) => c.join("receipts.jsonl"),
        Err(_) => app.join("receipts.jsonl"),
    }
}

/// Shadow observe JSONL. Override with `FAIRLEAD_OBSERVE`.
/// Armed `gate()` must not read this. `install-hooks` must not point at `observe`.
pub fn observe_path() -> PathBuf {
    if let Ok(p) = std::env::var("FAIRLEAD_OBSERVE") {
        return PathBuf::from(p);
    }
    let app = app_workspace();
    match fs::canonicalize(&app) {
        Ok(c) => c.join("observe.jsonl"),
        Err(_) => app.join("observe.jsonl"),
    }
}

pub fn seed_path(root: &Path) -> PathBuf {
    root.join("ed25519.seed")
}

pub fn hooks_file_path(root: &Path) -> Result<Option<PathBuf>, String> {
    if let Ok(p) = std::env::var("FAIRLEAD_HOOKS") {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return Ok(Some(fs::canonicalize(&pb).unwrap_or(pb)));
        }
        return Err(format!("FAIRLEAD_HOOKS={p} is not a file"));
    }
    let p = root.join("hooks.json");
    if p.is_file() {
        Ok(Some(fs::canonicalize(&p).unwrap_or(p)))
    } else {
        Ok(None)
    }
}

pub fn claude_settings_file_path() -> Result<Option<PathBuf>, String> {
    if let Ok(p) = std::env::var("FAIRLEAD_CLAUDE_SETTINGS") {
        let pb = PathBuf::from(&p);
        if pb.is_file() {
            return Ok(Some(fs::canonicalize(&pb).unwrap_or(pb)));
        }
        return Err(format!("FAIRLEAD_CLAUDE_SETTINGS={p} is not a file"));
    }
    Ok(None)
}

pub struct PolicyBytes {
    pub schema: Vec<u8>,
    pub cedar: Vec<u8>,
    pub hooks: Option<(PathBuf, Vec<u8>)>,
    pub claude_settings: Option<(PathBuf, Vec<u8>)>,
}

pub fn load_policy_bytes(
    root: &Path,
    schema_rel: &str,
    cedar_rel: &str,
) -> Result<PolicyBytes, String> {
    let schema_path = root.join(schema_rel);
    let cedar_path = root.join(cedar_rel);
    let schema =
        fs::read(&schema_path).map_err(|e| format!("read {}: {e}", schema_path.display()))?;
    let cedar = fs::read(&cedar_path).map_err(|e| format!("read {}: {e}", cedar_path.display()))?;
    let hooks = match hooks_file_path(root)? {
        Some(p) => {
            let bytes = fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
            Some((p, bytes))
        }
        None => None,
    };
    let claude_settings = match claude_settings_file_path()? {
        Some(p) => {
            let bytes = fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
            Some((p, bytes))
        }
        None => None,
    };
    Ok(PolicyBytes {
        schema,
        cedar,
        hooks,
        claude_settings,
    })
}

pub fn utf8_src(bytes: &[u8], what: &str) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|e| format!("{what} is not utf-8: {e}"))
}

pub fn hashes_of(policy: &PolicyBytes) -> Result<HashTriple, String> {
    Ok(HashTriple {
        binary_sha256: hash_current_exe()?,
        policy_pack_sha256: pack_hash(&policy.schema, &policy.cedar),
        // The hook reads only FAIRLEAD_HOOKS; the Claude settings file is its own osquery row.
        hooks_sha256: hooks_hash(policy.hooks.as_ref().map(|(_, b)| b.as_slice())),
    })
}

pub fn compute_tcb(root: &Path, schema_rel: &str, cedar_rel: &str) -> Result<TcbSnapshot, String> {
    let policy = load_policy_bytes(root, schema_rel, cedar_rel)?;
    let hashes = hashes_of(&policy)?;
    Ok(TcbSnapshot {
        hashes,
        hooks_path: policy.hooks.map(|(p, _)| p),
    })
}

pub fn check_hooks_fail_closed(hooks_json: &serde_json::Value) -> Result<(), String> {
    let hooks = hooks_json
        .get("hooks")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "hooks.json missing hooks object".to_string())?;
    for event in REQUIRED_HOOK_EVENTS {
        let arr = hooks
            .get(event)
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("hooks.json missing {event}"))?;
        if arr.is_empty() {
            return Err(format!("hooks.json {event} is empty"));
        }
        for (i, entry) in arr.iter().enumerate() {
            match entry.get("failClosed") {
                Some(v) if v.as_bool() == Some(true) => {}
                _ => {
                    return Err(format!(
                        "hooks.json {event}[{i}] failClosed is not true"
                    ))
                }
            }
        }
    }
    check_pretool_write_fail_closed(hooks)?;
    check_pretool_named_fail_closed(hooks, "grep", "Grep")?;
    check_pretool_named_fail_closed(hooks, "read", "Read")?;
    check_pretool_named_fail_closed(hooks, "glob", "Glob")
}

fn matcher_covers_write(matcher: Option<&str>) -> bool {
    match matcher {
        None => true,
        Some(m) if m == "*" || m == ".*" => true,
        Some(m) => m.to_ascii_lowercase().contains("write"),
    }
}

fn check_pretool_write_fail_closed(
    hooks: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let arr = hooks
        .get("preToolUse")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "hooks.json missing preToolUse".to_string())?;
    if arr.is_empty() {
        return Err("hooks.json preToolUse is empty".into());
    }
    for (i, entry) in arr.iter().enumerate() {
        let matcher = entry.get("matcher").and_then(|v| v.as_str());
        if !matcher_covers_write(matcher) {
            continue;
        }
        match entry.get("failClosed") {
            Some(v) if v.as_bool() == Some(true) => return Ok(()),
            _ => {
                return Err(format!(
                    "hooks.json preToolUse[{i}] Write matcher failClosed is not true"
                ))
            }
        }
    }
    Err("hooks.json preToolUse has no failClosed Write matcher".into())
}

fn check_pretool_named_fail_closed(
    hooks: &serde_json::Map<String, serde_json::Value>,
    needle: &str,
    label: &str,
) -> Result<(), String> {
    let arr = hooks
        .get("preToolUse")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "hooks.json missing preToolUse".to_string())?;
    for (i, entry) in arr.iter().enumerate() {
        let matcher = entry.get("matcher").and_then(|v| v.as_str());
        let covers = match matcher {
            None => true,
            Some(m) if m == "*" || m == ".*" => true,
            Some(m) => m.to_ascii_lowercase().contains(needle),
        };
        if !covers {
            continue;
        }
        match entry.get("failClosed") {
            Some(v) if v.as_bool() == Some(true) => return Ok(()),
            _ => {
                return Err(format!(
                    "hooks.json preToolUse[{i}] {label} matcher failClosed is not true"
                ))
            }
        }
    }
    Err(format!("hooks.json preToolUse has no failClosed {label} matcher").into())
}

fn shell_quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    if s.bytes().any(|b| matches!(b, b' ' | b'\'' | b'"' | b'\\')) {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.into_owned()
    }
}

/// `FAIRLEAD_HOOKS=<abs hooks.json> <exe>`: every host runs `command` as a shell string, and the
/// hook gets no other way to learn which hooks file launched it (Cursor stdin has no path).
fn hook_launcher(exe: &Path, hooks: &Path) -> String {
    format!("FAIRLEAD_HOOKS={} {}", shell_quote(hooks), shell_quote(exe))
}

pub fn cursor_hooks_template(exe: &Path, hooks: &Path) -> serde_json::Value {
    let exe = hook_launcher(exe, hooks);
    serde_json::json!({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [{
                "command": format!("{exe} hook cursor shell"),
                "timeout": 10,
                "failClosed": true
            }],
            "beforeMCPExecution": [{
                "command": format!("{exe} hook cursor mcp"),
                "timeout": 10,
                "failClosed": true
            }],
            "beforeReadFile": [{
                "command": format!("{exe} hook cursor read"),
                "timeout": 5,
                "failClosed": true
            }],
            "preToolUse": [
                {
                    "command": format!("{exe} hook cursor pretool"),
                    "matcher": "Task",
                    "timeout": 5,
                    "failClosed": true
                },
                {
                    "command": format!("{exe} hook cursor pretool"),
                    "matcher": "Write",
                    "timeout": 5,
                    "failClosed": true
                },
                {
                    "command": format!("{exe} hook cursor pretool"),
                    "matcher": "Delete",
                    "timeout": 5,
                    "failClosed": true
                },
                {
                    "command": format!("{exe} hook cursor pretool"),
                    "matcher": "Grep",
                    "timeout": 5,
                    "failClosed": true
                },
                {
                    "command": format!("{exe} hook cursor pretool"),
                    "matcher": "Read",
                    "timeout": 5,
                    "failClosed": true
                },
                {
                    "command": format!("{exe} hook cursor pretool"),
                    "matcher": "Glob",
                    "timeout": 5,
                    "failClosed": true
                }
            ],
            "subagentStart": [{
                "command": format!("{exe} hook cursor subagent-start"),
                "timeout": 5,
                "failClosed": true
            }],
            "subagentStop": [{
                "command": format!("{exe} hook cursor subagent-stop"),
                "timeout": 5
            }],
            "afterMCPExecution": [{
                "command": format!("{exe} hook cursor after-mcp"),
                "timeout": 30
            }],
            "afterShellExecution": [{
                "command": format!("{exe} hook cursor after-shell"),
                "timeout": 10
            }]
        }
    })
}

pub fn windsurf_hooks_template(exe: &Path, hooks: &Path) -> serde_json::Value {
    let exe = hook_launcher(exe, hooks);
    let cmd = |sub: &str| format!("{exe} hook windsurf {sub}");
    serde_json::json!({
        "hooks": {
            "pre_run_command": [{ "command": cmd("pre") }],
            "pre_write_code": [{ "command": cmd("pre") }],
            "pre_read_code": [{ "command": cmd("pre") }],
            "pre_mcp_tool_use": [{ "command": cmd("pre") }]
        }
    })
}

pub fn openhands_hooks_template(exe: &Path, hooks: &Path) -> serde_json::Value {
    let exe = hook_launcher(exe, hooks);
    serde_json::json!({
        "pre_tool_use": [{
            "matcher": "*",
            "hooks": [{
                "command": format!("{exe} hook openhands pretool"),
                "timeout": 10
            }]
        }]
    })
}

pub fn install_windsurf_dest(dir: &Path) -> PathBuf {
    dir.join(".windsurf").join("hooks.json")
}

pub fn install_openhands_dest(dir: &Path) -> PathBuf {
    dir.join(".openhands").join("hooks.json")
}

pub fn write_windsurf_hooks(dir: &Path, exe: &Path, docs: &Path) -> Result<PathBuf, String> {
    let dest = absolute_install_dest(dir, install_windsurf_dest(dir))?;
    refuse_install_dest(&dest, docs)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let v = windsurf_hooks_template(exe, &absolute_install_dest(dir, install_hooks_dest(dir))?);
    let bytes = serde_json::to_vec_pretty(&v).map_err(|e| format!("windsurf json: {e}"))?;
    fs::write(&dest, bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(dest)
}

pub fn write_openhands_hooks(dir: &Path, exe: &Path, docs: &Path) -> Result<PathBuf, String> {
    let dest = absolute_install_dest(dir, install_openhands_dest(dir))?;
    refuse_install_dest(&dest, docs)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let v = openhands_hooks_template(exe, &absolute_install_dest(dir, install_hooks_dest(dir))?);
    let raw = serde_json::to_string_pretty(&v).map_err(|e| format!("openhands json: {e}"))?;
    if raw.contains("\"decision\": \"allow\"") || raw.contains("LLMSecurityAnalyzer") {
        return Err("openhands template must not emit decision allow".into());
    }
    fs::write(&dest, raw.as_bytes()).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(dest)
}

fn dest_is_under(dest: &Path, root: &Path) -> bool {
    dest.starts_with(root)
}

fn refuse_install_dest(dest: &Path, docs: &Path) -> Result<(), String> {
    let docs_can = fs::canonicalize(docs).unwrap_or_else(|_| docs.to_path_buf());
    if dest_is_under(dest, &docs_can) {
        return Err("refuse: will not install into the Fairlead pack".into());
    }
    Ok(())
}

fn absolute_install_dest(dir: &Path, dest: PathBuf) -> Result<PathBuf, String> {
    if dir.is_absolute() {
        Ok(dest)
    } else {
        Ok(std::env::current_dir()
            .map_err(|e| format!("cwd: {e}"))?
            .join(dest))
    }
}

pub fn install_hooks_dest(dir: &Path) -> PathBuf {
    dir.join(".cursor").join("hooks.json")
}

pub fn install_claude_dest(dir: &Path) -> PathBuf {
    dir.join(".claude").join("settings.json")
}

pub fn validate_install_dir(dir: &Path, docs: &Path) -> Result<PathBuf, String> {
    let dest = absolute_install_dest(dir, install_hooks_dest(dir))?;
    refuse_install_dest(&dest, docs)?;
    Ok(dest)
}

pub fn validate_claude_install_dir(dir: &Path, docs: &Path) -> Result<PathBuf, String> {
    let dest = absolute_install_dest(dir, install_claude_dest(dir))?;
    refuse_install_dest(&dest, docs)?;
    Ok(dest)
}

pub fn write_cursor_hooks(dir: &Path, exe: &Path, docs: &Path) -> Result<PathBuf, String> {
    let dest = validate_install_dir(dir, docs)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let v = cursor_hooks_template(exe, &dest);
    if hooks_json_has_failclosed_false(&v) {
        return Err("template emitted failClosed false".into());
    }
    check_hooks_fail_closed(&v)?;
    let bytes = serde_json::to_vec_pretty(&v).map_err(|e| format!("hooks json: {e}"))?;
    fs::write(&dest, bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    check_hooks_file(&dest)?;
    Ok(dest)
}

fn refuse_symlink_dest(dest: &Path) -> Result<(), String> {
    match dest.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err("refuse: will not write through symlink dest".into())
        }
        _ => Ok(()),
    }
}

/// Exec form: no shell, so `FAIRLEAD_HOOKS` travels in the settings `env` block instead of a
/// `VAR=value` prefix. Needs Claude Code 2.1.139+ (older builds ignore `args`: fail-open).
/// `onFailure: block` makes a missing binary, crash, timeout or bad JSON deny; Claude Code 2.1.295+
/// only, older builds ignore the key (probed on 2.1.285: the hook still runs, failures still pass).
fn claude_hook_entry(exe: &Path, sub: &str) -> serde_json::Value {
    serde_json::json!({
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": exe.to_string_lossy(),
            "args": ["hook", "claude", sub],
            "timeout": 10,
            "onFailure": "block"
        }]
    })
}

pub fn claude_settings_template(exe: &Path, hooks: &Path) -> serde_json::Value {
    serde_json::json!({
        "env": { "FAIRLEAD_HOOKS": hooks.to_string_lossy() },
        "hooks": {
            "PreToolUse": [claude_hook_entry(exe, "pretool")],
            "PermissionRequest": [claude_hook_entry(exe, "permission-request")],
            "SubagentStop": [claude_hook_entry(exe, "subagent-stop")],
            "SubagentStart": [claude_hook_entry(exe, "subagent-start")]
        }
    })
}

fn hook_blob(hook: &serde_json::Value) -> String {
    let cmd = hook.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let args = hook
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    format!("{cmd} {args}")
}

/// What Fairlead can read about the host's own OS sandbox. `gaps` are settings that switch the
/// sandbox off or leave an escape hatch open; `notes` are things it cannot read at all.
/// Fairlead does not provide a sandbox: the host (Seatbelt, bubblewrap) enforces, this only checks
/// the config the user can see. A hook is a policy gate, not an isolation boundary.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SandboxFindings {
    pub gaps: Vec<String>,
    pub notes: Vec<String>,
}

/// `claude`: the effective sandbox keys from `claude_effective_sandbox`, if Claude is in use. `cursor`: parsed
/// `sandbox.json` files (label, body). Claude needs `sandbox.enabled` true,
/// `allowUnsandboxedCommands` false (default true) and `failIfUnavailable` true (otherwise it runs
/// unsandboxed when the sandbox cannot start). Cursor's `type: "insecure_none"` disables its sandbox.
/// ponytail: Claude MDM and server-managed settings are not files, so they are never read. Cursor's Run Everything mode and team-admin policy are not in any file Fairlead can see.
pub fn host_sandbox_findings(
    claude: Option<&serde_json::Value>,
    cursor: &[(String, serde_json::Value)],
) -> SandboxFindings {
    let mut f = SandboxFindings::default();
    match claude {
        None => f.notes.push(
            "claude: sandbox not verified (no Fairlead Claude hook found in any readable scope); Claude Code default is no sandbox".into(),
        ),
        Some(v) => {
            let sb = v.get("sandbox");
            let flag = |k: &str| sb.and_then(|o| o.get(k)).and_then(|b| b.as_bool());
            if flag("enabled") != Some(true) {
                f.gaps.push("claude: sandbox.enabled is not true".into());
            }
            if flag("allowUnsandboxedCommands") != Some(false) {
                f.gaps.push("claude: sandbox.allowUnsandboxedCommands is not false (the agent can retry outside the sandbox)".into());
            }
            if flag("failIfUnavailable") != Some(true) {
                f.gaps.push("claude: sandbox.failIfUnavailable is not true (runs unsandboxed when the sandbox cannot start)".into());
            }
        }
    }
    for (label, v) in cursor {
        if v.get("type").and_then(|t| t.as_str()) == Some("insecure_none") {
            f.gaps.push(format!("cursor: {label} sets type insecure_none (sandbox off)"));
        }
    }
    f.notes.push(
        "cursor: Run Everything has no sandbox and is not readable from a file; the per-call `sandbox` flag in the hook input is the only evidence".into(),
    );
    f
}

/// First Claude Code release with `onFailure: "block"` on command/http hooks.
pub const CLAUDE_ONFAILURE_MIN: (u32, u32, u32) = (2, 1, 295);

/// Claude's own managed directory (not Fairlead's `managed_dir`). `FAIRLEAD_CLAUDE_MANAGED_DIR`
/// overrides in debug builds only, so a release build never trusts a seat-controlled path.
pub fn claude_managed_root() -> PathBuf {
    if cfg!(debug_assertions) {
        if let Ok(p) = std::env::var("FAIRLEAD_CLAUDE_MANAGED_DIR") {
            return PathBuf::from(p);
        }
    }
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/ClaudeCode")
    } else {
        PathBuf::from("/etc/claude-code")
    }
}

/// One readable Claude Code settings file.
#[derive(Clone, Debug)]
pub struct ClaudeScope {
    pub label: String,
    pub managed: bool,
    pub value: serde_json::Value,
}

/// Readable scopes in Claude Code precedence order (managed, `FAIRLEAD_CLAUDE_SETTINGS` as the
/// `--settings` tier, local, project, user). Unparseable files are returned as errors: the host
/// ignores them, so their hooks and sandbox keys do not apply.
/// Managed files are returned in merge order (`managed-settings.json`, then `managed-settings.d`
/// alphabetically): the host merges them, so a later file replaces an earlier single value, lists
/// union and nested blocks merge key by key. Other scopes are returned highest precedence first.
/// ponytail: MDM plist and remote (server-managed) settings outrank the managed files and under the
/// host's default `first-wins` replace them whole; they are not files, so they are never read.
pub fn claude_scopes_at(
    managed_root: &Path,
    config_dir: &Path,
    cwd: &Path,
    flag_file: Option<&Path>,
) -> (Vec<ClaudeScope>, Vec<String>) {
    let mut files: Vec<(String, bool, PathBuf)> =
        vec![("managed".into(), true, managed_root.join("managed-settings.json"))];
    let mut drop_ins: Vec<PathBuf> = fs::read_dir(managed_root.join("managed-settings.d"))
        .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    drop_ins.retain(|p| {
        p.extension().is_some_and(|e| e == "json")
            && !p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('.'))
    });
    drop_ins.sort();
    files.extend(drop_ins.into_iter().map(|p| ("managed".into(), true, p)));
    if let Some(p) = flag_file {
        files.push(("FAIRLEAD_CLAUDE_SETTINGS".into(), false, p.to_path_buf()));
    }
    files.push(("local".into(), false, cwd.join(".claude/settings.local.json")));
    files.push(("project".into(), false, cwd.join(".claude/settings.json")));
    files.push(("user".into(), false, config_dir.join("settings.json")));
    let (mut scopes, mut errs) = (Vec::new(), Vec::new());
    for (kind, managed, path) in files {
        let label = format!("{kind} {}", path.display());
        match fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errs.push(format!("claude: {label} unreadable ({e})")),
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(value) => scopes.push(ClaudeScope { label, managed, value }),
                Err(e) => errs.push(format!(
                    "claude: {label} is not valid JSON ({e}); {}",
                    if managed { "the host refuses to start" } else { "the host ignores it" }
                )),
            },
        }
    }
    (scopes, errs)
}

/// Environment-driven wrapper: `CLAUDE_CONFIG_DIR` (else `$HOME/.claude`), the current directory.
pub fn claude_scopes() -> (Vec<ClaudeScope>, Vec<String>) {
    let config = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude")))
        .unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();
    let flag = claude_settings_file_path().ok().flatten();
    claude_scopes_at(&claude_managed_root(), &config, &cwd, flag.as_deref())
}

fn fairlead_hook_groups<'a>(
    v: &'a serde_json::Value,
    event: &str,
) -> Vec<(&'a serde_json::Value, &'a serde_json::Value)> {
    let groups = v.pointer(&format!("/hooks/{event}")).and_then(|x| x.as_array());
    let mut out = Vec::new();
    for g in groups.into_iter().flatten() {
        for h in g.get("hooks").and_then(|x| x.as_array()).into_iter().flatten() {
            if hook_blob(h).contains("hook claude") {
                out.push((g, h));
            }
        }
    }
    out
}

/// Claude counts as in use for Fairlead only when some scope carries a Fairlead Claude hook.
pub fn claude_in_use(scopes: &[ClaudeScope]) -> bool {
    scopes.iter().any(|s| {
        ["PreToolUse", "PermissionRequest", "SubagentStart", "SubagentStop"]
            .iter()
            .any(|e| !fairlead_hook_groups(&s.value, e).is_empty())
    })
}

fn first_bool(scopes: &[&ClaudeScope], key: &str) -> Option<(bool, String)> {
    scopes
        .iter()
        .find_map(|s| s.value.get(key).and_then(|b| b.as_bool()).map(|b| (b, s.label.clone())))
}

/// Sandbox keys as the host resolves them, for `host_sandbox_findings`: managed outranks every other
/// scope and, among managed files, the later one wins; otherwise the first scope that sets a key wins.
pub fn claude_effective_sandbox(scopes: &[ClaudeScope]) -> serde_json::Value {
    let mut sb = serde_json::Map::new();
    let ordered: Vec<&ClaudeScope> = scopes
        .iter()
        .rev()
        .filter(|s| s.managed)
        .chain(scopes.iter().filter(|s| !s.managed))
        .collect();
    for k in ["enabled", "allowUnsandboxedCommands", "failIfUnavailable"] {
        if let Some(b) = ordered.iter().find_map(|s| s.value.pointer(&format!("/sandbox/{k}")).and_then(|b| b.as_bool())) {
            sb.insert(k.into(), b.into());
        }
    }
    serde_json::json!({ "sandbox": sb })
}

/// Hook-layer findings across scopes, assuming `claude_in_use`. Managed hooks cannot be removed by
/// other scopes; only `disableAllHooks` (managed: everything, other scopes: non-managed hooks) or an
/// `allowManagedHooksOnly` managed file takes a hook out. Strict-profile keys only ever produce notes.
pub fn claude_hook_findings(scopes: &[ClaudeScope]) -> SandboxFindings {
    let mut f = SandboxFindings::default();
    // Reversed: among managed files the later one replaces an earlier single value.
    let managed: Vec<&ClaudeScope> = scopes.iter().rev().filter(|s| s.managed).collect();
    let other: Vec<&ClaudeScope> = scopes.iter().filter(|s| !s.managed).collect();
    let hooks_only = first_bool(&managed, "allowManagedHooksOnly").is_some_and(|(b, _)| b);
    let managed_off = first_bool(&managed, "disableAllHooks");
    let other_off = first_bool(&other, "disableAllHooks");
    if let Some((true, l)) = &managed_off {
        f.gaps.push(format!("claude: disableAllHooks is true in {l} (every hook is off, Fairlead's included)"));
    }
    let other_dead = matches!(&other_off, Some((true, _))) || hooks_only;
    if let (Some((true, l)), false) = (&other_off, hooks_only) {
        f.gaps.push(format!("claude: disableAllHooks is true in {l} (turns off non-managed hooks, Fairlead's included)"));
    }
    let managed_dead = matches!(&managed_off, Some((true, _)));
    if hooks_only {
        for s in &other {
            if s.value.get("hooks").is_some() {
                f.notes.push(format!("claude: hooks in {} are inert (managed allowManagedHooksOnly)", s.label));
            }
        }
    }
    let live: Vec<&ClaudeScope> = scopes
        .iter()
        .filter(|s| if s.managed { !managed_dead } else { !other_dead && !managed_dead })
        .collect();
    for event in ["PreToolUse", "PermissionRequest"] {
        let found: Vec<_> = live.iter().flat_map(|s| fairlead_hook_groups(&s.value, event)).collect();
        if found.is_empty() {
            f.gaps.push(format!("claude: no effective scope supplies a Fairlead {event} hook"));
            continue;
        }
        if !found.iter().any(|(g, _)| g.get("matcher").and_then(|m| m.as_str()) == Some("*")) {
            f.gaps.push(format!("claude: the Fairlead {event} hook matcher is not * in any effective scope"));
        }
        if found.iter().any(|(_, h)| h.get("onFailure").and_then(|x| x.as_str()) != Some("block")) {
            f.gaps.push(format!("claude: a Fairlead {event} hook lacks onFailure block (a dead or slow hook lets the call through)"));
        }
    }
    let m = |p: &str| managed.iter().find_map(|s| s.value.pointer(p).cloned());
    let strict = m("/permissions/defaultMode").and_then(|v| v.as_str().map(String::from)).as_deref() == Some("dontAsk")
        && first_bool(&managed, "allowManagedPermissionRulesOnly").is_some_and(|(b, _)| b)
        && m("/permissions/disableBypassPermissionsMode").and_then(|v| v.as_str().map(String::from)).as_deref() == Some("disable")
        && m("/permissions/disableAutoMode")
            .or_else(|| m("/disableAutoMode"))
            .and_then(|v| v.as_str().map(String::from))
            .as_deref()
            == Some("disable");
    f.notes.push(if strict {
        "claude: strict permission profile is applied in managed settings".into()
    } else {
        "claude: strict permission profile not applied (optional enterprise/claude-managed-strict.json); a hook that never loads is covered only by permission rules and the OS sandbox".into()
    });
    f
}

pub fn parse_claude_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split_whitespace().next()?.split('.').map(|p| p.parse::<u32>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(v)
}

/// `(gap, note)` from the raw `claude --version` output (`None` = no binary or no answer).
/// An older host ignores `onFailure`, so the hook protection silently is not there.
pub fn claude_version_finding(out: Option<&str>) -> (Option<String>, Option<String>) {
    match out.and_then(parse_claude_version) {
        None => (None, Some("claude: version not read (no `claude` on PATH or no answer); onFailure needs 2.1.295+".into())),
        Some(v) if v < CLAUDE_ONFAILURE_MIN => (
            Some(format!(
                "claude: {}.{}.{} is older than 2.1.295, which ignores onFailure; a missing, crashed or slow hook lets the call through",
                v.0, v.1, v.2
            )),
            None,
        ),
        Some(_) => (None, None),
    }
}

pub fn check_claude_settings(v: &serde_json::Value) -> Result<(), String> {
    if v.get("disableAllHooks").and_then(|x| x.as_bool()) == Some(true) {
        return Err("settings.json disableAllHooks is true".into());
    }
    let hooks = v
        .get("hooks")
        .and_then(|x| x.as_object())
        .ok_or_else(|| "settings.json missing hooks object".to_string())?;
    for event in ["PreToolUse", "PermissionRequest"] {
        let arr = hooks
            .get(event)
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("settings.json missing {event}"))?;
        if arr.is_empty() {
            return Err(format!("settings.json {event} is empty"));
        }
        let mut saw_cmd = false;
        for (i, group) in arr.iter().enumerate() {
            let matcher = group.get("matcher").and_then(|x| x.as_str()).unwrap_or("");
            if matcher != "*" {
                return Err(format!("settings.json {event}[{i}] matcher is not *"));
            }
            let inner = group
                .get("hooks")
                .and_then(|x| x.as_array())
                .ok_or_else(|| format!("settings.json {event}[{i}] missing hooks"))?;
            for (j, hook) in inner.iter().enumerate() {
                let ty = hook.get("type").and_then(|x| x.as_str()).unwrap_or("");
                if ty == "http" {
                    return Err(format!(
                        "settings.json {event}[{i}].hooks[{j}] type http"
                    ));
                }
                if ty != "command" {
                    return Err(format!(
                        "settings.json {event}[{i}].hooks[{j}] type is not command"
                    ));
                }
                let timeout_ok = hook.get("timeout").and_then(|x| x.as_u64()).is_some()
                    || hook.get("timeout").and_then(|x| x.as_i64()).is_some()
                    || hook.get("timeout").and_then(|x| x.as_f64()).is_some();
                if !timeout_ok {
                    return Err(format!(
                        "settings.json {event}[{i}].hooks[{j}] missing timeout"
                    ));
                }
                let blob = hook_blob(hook);
                if blob.contains("9377") || blob.to_ascii_lowercase().contains("http://") {
                    return Err(format!(
                        "settings.json {event}[{i}].hooks[{j}] looks like HTTP init-hooks"
                    ));
                }
                if blob.contains("hook claude") {
                    saw_cmd = true;
                    if hook.get("onFailure").and_then(|x| x.as_str()) != Some("block") {
                        return Err(format!(
                            "settings.json {event}[{i}].hooks[{j}] onFailure is not block (Claude Code 2.1.295+); re-run install-hooks"
                        ));
                    }
                }
            }
        }
        if !saw_cmd {
            return Err(format!(
                "settings.json {event} command does not contain hook claude"
            ));
        }
    }
    Ok(())
}

pub fn check_claude_settings_file(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    check_claude_settings(&v)
}

pub fn write_claude_settings(dir: &Path, exe: &Path, docs: &Path) -> Result<PathBuf, String> {
    let dest = validate_claude_install_dir(dir, docs)?;
    refuse_symlink_dest(&dest)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let v = claude_settings_template(exe, &absolute_install_dest(dir, install_hooks_dest(dir))?);
    check_claude_settings(&v)?;
    // ponytail: fs::write clobbers existing settings.json. Upgrade: 1.5B/S3 splice.
    let bytes = serde_json::to_vec_pretty(&v).map_err(|e| format!("settings json: {e}"))?;
    fs::write(&dest, bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    check_claude_settings_file(&dest)?;
    Ok(dest)
}

pub fn hooks_json_has_failclosed_false(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(m) => {
            if let Some(serde_json::Value::Bool(false)) = m.get("failClosed") {
                return true;
            }
            m.values().any(hooks_json_has_failclosed_false)
        }
        serde_json::Value::Array(a) => a.iter().any(hooks_json_has_failclosed_false),
        _ => false,
    }
}

pub fn check_hooks_file(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    check_hooks_fail_closed(&v)
}

pub fn compare_armed(live: &HashTriple, last: &LastArmed) -> Result<(), ArmedDrift> {
    if live.policy_pack_sha256 != last.policy_pack_sha256 {
        return Err(ArmedDrift::Pack {
            old: last.policy_pack_sha256.clone(),
            new: live.policy_pack_sha256.clone(),
        });
    }
    if live.binary_sha256 != last.binary_sha256 {
        return Err(ArmedDrift::Binary {
            old: last.binary_sha256.clone(),
            new: live.binary_sha256.clone(),
        });
    }
    if live.hooks_sha256 != last.hooks_sha256 {
        return Err(ArmedDrift::Hooks {
            old: last.hooks_sha256.clone(),
            new: live.hooks_sha256.clone(),
        });
    }
    Ok(())
}

/// A live hook call that must deny before Cedar runs. `sentence` is the user-facing deny text.
#[derive(Debug)]
pub struct LiveDeny {
    pub sentence: &'static str,
    pub detail: String,
}

fn live_deny(sentence: &'static str, detail: impl Into<String>) -> LiveDeny {
    LiveDeny {
        sentence,
        detail: detail.into(),
    }
}

/// Hooks digest for an armed seat: exactly the file `FAIRLEAD_HOOKS` names (required, written
/// into every installed command or settings env), hashed as arm does. The absent-hooks constant
/// is never an answer here: the hook cannot learn its own file path from Cursor, so a missing
/// env on an armed seat is drift, not "no hooks file".
fn live_hooks_hash() -> Result<String, String> {
    let p = std::env::var("FAIRLEAD_HOOKS")
        .map_err(|_| "FAIRLEAD_HOOKS unset on an armed seat".to_string())?;
    let cursor = fs::read(&p).map_err(|e| format!("read FAIRLEAD_HOOKS={p}: {e}"))?;
    Ok(hooks_hash(Some(&cursor)))
}

/// A managed seat has an `org.pub`, an `armed.stamp`, or a managed pin. Any of them moves the
/// pin out of the docs root for good: the docs copy is never read on such a seat.
pub fn managed_seat(managed: &Path) -> bool {
    crate::kill::org_present(managed)
        || crate::kill::armed_stamp_present(managed)
        || fs::symlink_metadata(last_armed_path(managed)).is_ok()
}

/// `arm` and `doctor` opt in as soon as the managed dir exists, even empty: the first arm on a
/// root-prepared directory must land the pin there. The hook itself only needs `managed_seat`.
pub fn managed_optin(managed: &Path) -> bool {
    managed.is_dir() || managed_seat(managed)
}

/// Where the pin lives: the managed dir on a managed seat, else the docs root.
pub fn pin_dir(root: &Path, managed: &Path) -> PathBuf {
    if managed_seat(managed) {
        managed.to_path_buf()
    } else {
        root.to_path_buf()
    }
}

/// Managed-pin guard: the pin and its dir must be root-owned and not group/other writable, and a
/// missing pin is a deny once `armed.stamp` exists. Without a stamp the seat was never armed.
fn managed_pin_guard(managed: &Path) -> Result<(), LiveDeny> {
    let pin = last_armed_path(managed);
    match fs::symlink_metadata(&pin) {
        Ok(_) => crate::kill::root_only(managed, true)
            .and_then(|()| crate::kill::root_only(&pin, false))
            .map_err(|e| live_deny("fairlead deny: pin writable", e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if crate::kill::armed_stamp_present(managed) {
                Err(live_deny(
                    "fairlead deny: pin missing",
                    format!("armed.stamp present, {} missing", pin.display()),
                ))
            } else {
                Ok(())
            }
        }
        Err(e) => Err(live_deny("fairlead deny: pin missing", format!("{}: {e}", pin.display()))),
    }
}

/// Check the bytes this call is about to use. `schema` and `cedar` are the buffers the caller
/// parses next; the digest returned is the one the receipt must carry. No pin means unarmed:
/// pack, binary and hooks checks are skipped. A pin that exists but cannot be parsed denies.
/// On a managed seat (`org.pub`, `armed.stamp`, or a managed pin) the pin is read only from the
/// managed dir, never the docs root, and must be root-only. With `org.pub` the pack digest must
/// also carry that key's signature, and an org-signed successor at exactly `pin.generation + 1`
/// replaces the pack and binary compare. A self-managed seat has no signed roll: re-arm.
pub fn live_check(
    root: &Path,
    managed: &Path,
    schema: &[u8],
    cedar: &[u8],
) -> Result<String, LiveDeny> {
    let pack = pack_hash(schema, cedar);
    let org = crate::kill::org_present(managed);
    let seat = managed_seat(managed);
    if seat {
        managed_pin_guard(managed)?;
    }
    let pin_root = if seat { managed } else { root };
    if let Some(last) =
        read_last_armed(pin_root).map_err(|e| live_deny("fairlead deny: policy drift", e))?
    {
        let bin = hash_current_exe().map_err(|e| live_deny("fairlead deny: binary drift", e))?;
        if (pack != last.policy_pack_sha256 || bin != last.binary_sha256)
            && !(org
                && crate::kill::pack_successor(managed, &pack, &bin, last.generation, now_unix()))
        {
            if pack != last.policy_pack_sha256 {
                return Err(live_deny(
                    "fairlead deny: policy drift",
                    format!("pack {} pinned {}", pack, last.policy_pack_sha256),
                ));
            }
            return Err(live_deny(
                "fairlead deny: binary drift",
                format!("binary {} pinned {}", bin, last.binary_sha256),
            ));
        }
        let hooks = live_hooks_hash().map_err(|e| live_deny("fairlead deny: hooks drift", e))?;
        if hooks != last.hooks_sha256 {
            return Err(live_deny(
                "fairlead deny: hooks drift",
                format!("hooks {} pinned {}", hooks, last.hooks_sha256),
            ));
        }
    }
    crate::kill::check_pack_signature(managed, &pack)
        .map_err(|e| live_deny("fairlead deny: pack signature", e))?;
    Ok(pack)
}

/// Clock failure reads as the far future, so a `not_after` signature never outlives it.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(u64::MAX, |d| d.as_secs())
}

pub fn read_last_armed(root: &Path) -> Result<Option<LastArmed>, String> {
    let path = last_armed_path(root);
    if !path.is_file() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let last: LastArmed =
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok(Some(last))
}

pub fn last_armed_bytes(hashes: &HashTriple, generation: u64) -> Result<Vec<u8>, String> {
    let body = LastArmed {
        v: 1,
        binary_sha256: hashes.binary_sha256.clone(),
        policy_pack_sha256: hashes.policy_pack_sha256.clone(),
        hooks_sha256: hashes.hooks_sha256.clone(),
        generation,
    };
    serde_json::to_vec_pretty(&body).map_err(|e| format!("last-armed json: {e}"))
}

pub fn write_last_armed(root: &Path, hashes: &HashTriple) -> Result<(), String> {
    write_last_armed_gen(root, hashes, 0)
}

pub fn write_last_armed_gen(root: &Path, hashes: &HashTriple, generation: u64) -> Result<(), String> {
    let path = last_armed_path(root);
    let tmp = root.join("last-armed.json.tmp");
    let bytes = last_armed_bytes(hashes, generation)?;
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o644);
        let mut f = opts.open(&tmp).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.write_all(&bytes)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("sync {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {e}", tmp.display()))?;
    if let Ok(dir) = File::open(root) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn check_seed_mode(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let meta = fs::metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "{} mode {mode:#o} not 0600",
                path.display()
            ));
        }
    }
    let _ = path;
    Ok(())
}

pub fn load_or_create_signing_key(root: &Path) -> Result<SigningKey, String> {
    let path = seed_path(root);
    if path.is_file() {
        check_seed_mode(&path)?;
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!("{}: expected 32-byte seed", path.display()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(SigningKey::from_bytes(&seed));
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("getrandom: {e}"))?;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(&seed)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    check_seed_mode(&path)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn load_signing_key(root: &Path) -> Result<SigningKey, String> {
    let path = seed_path(root);
    if !path.is_file() {
        return Err(format!("missing {}", path.display()));
    }
    check_seed_mode(&path)?;
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if bytes.len() != 32 {
        return Err(format!("{}: expected 32-byte seed", path.display()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

pub fn require_pin_if_keyed(root: &Path) -> Result<(), String> {
    require_pin_if_keyed_at(root, root)
}

/// Seed lives in `root`; the pin in `pin_root` (the managed dir on an org seat). A managed seat
/// with `armed.stamp` but no pin counts as keyed-without-pin.
pub fn require_pin_if_keyed_at(root: &Path, pin_root: &Path) -> Result<(), String> {
    let seed = seed_path(root);
    let pin = read_last_armed(pin_root)?;
    if pin.is_none() && crate::kill::armed_stamp_present(pin_root) {
        return Err("armed.stamp present but last-armed.json missing".into());
    }
    match (seed.is_file(), pin.is_some()) {
        (false, false) => Ok(()),
        (false, true) => Err("last-armed.json present but ed25519.seed missing".into()),
        (true, false) => {
            check_seed_mode(&seed)?;
            Err("ed25519.seed present but last-armed.json missing".into())
        }
        (true, true) => check_seed_mode(&seed),
    }
}
