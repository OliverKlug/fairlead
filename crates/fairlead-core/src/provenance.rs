// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

use crate::{command_looks_like_network, mint_session_id, path_is_sensitive, sha256_hex};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub const SECRET_TAG: &str = "secret";
pub const SUBAGENT_TAG: &str = "subagent";

fn pending_path(dir: &Path) -> PathBuf {
    dir.join("_pending.jsonl")
}

const LOCK_WAIT: Duration = Duration::from_millis(100);
const LOCK_SLEEP: Duration = Duration::from_millis(10);
// ponytail: create_new lock, stale after kill; flock if this fires in anger
const STALE_LOCK: Duration = Duration::from_secs(60);

/// Agent `rm` of this store resets taint (same class as uninstall / F-BYP).
pub fn session_dir() -> PathBuf {
    if let Ok(p) = std::env::var("FAIRLEAD_SESSION_DIR") {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(p).join("fairlead").join("sessions");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("fairlead")
            .join("sessions");
    }
    std::env::temp_dir().join("fairlead-sessions")
}

pub fn conversation_id_from_stdin(v: &Value) -> Option<String> {
    for k in ["conversation_id", "session_id"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    None
}

pub fn session_path(dir: &Path, conversation_id: &str) -> PathBuf {
    dir.join(format!("{}.jsonl", sha256_hex(conversation_id.as_bytes())))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSnap {
    pub session_id: String,
    pub tags: Vec<String>,
    pub parent_session_id: Option<String>,
    pub parent_conversation_id: Option<String>,
    pub parent_caps: Vec<String>,
    pub subagent_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildEnvelope {
    pub child_session_id: String,
    pub parent_session_id: String,
    pub parent_conversation_id: String,
    pub parent_caps: Vec<String>,
    pub spawn_id: String,
}

/// Dogwood-lite fold over JSONL tags. Not temporal algebra.
/// ponytail: no formerly/within; upgrade is dogwood lower when we want windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionFacts {
    pub touched_secrets: bool,
    pub saw_untrusted_web: bool,
    pub saw_mcp_untrusted: bool,
    pub subagent_active: bool,
    pub secret_read_count: i64,
}

impl Default for SessionFacts {
    fn default() -> Self {
        Self {
            touched_secrets: false,
            saw_untrusted_web: false,
            saw_mcp_untrusted: false,
            subagent_active: false,
            secret_read_count: 0,
        }
    }
}

/// Pure. `secret`/`web`/`mcp` tags only. `mcp:<server>` and `shell` ignored.
pub fn reduce(lines: &[Value]) -> SessionFacts {
    let mut facts = SessionFacts::default();
    let mut secret_hashes: Vec<String> = Vec::new();
    for v in lines {
        let Some(arr) = v.get("tags").and_then(|x| x.as_array()) else {
            continue;
        };
        let mut has_secret = false;
        for t in arr {
            let Some(s) = t.as_str() else {
                continue;
            };
            match s {
                "secret" => {
                    facts.touched_secrets = true;
                    has_secret = true;
                }
                "web" => facts.saw_untrusted_web = true,
                "mcp" => facts.saw_mcp_untrusted = true,
                _ => {}
            }
        }
        if has_secret {
            let h = v
                .get("args_hash")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if !secret_hashes.iter().any(|x| x == &h) {
                secret_hashes.push(h);
            }
        }
    }
    facts.secret_read_count = secret_hashes.len() as i64;
    facts
}

pub fn cedar_provenance(tags: &[String]) -> Vec<String> {
    union_tags(tags, &[])
}

pub fn union_tags(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = a
        .iter()
        .chain(b.iter())
        .filter(|t| t.as_str() != SECRET_TAG)
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn classify_after_mcp(stdin: &Value) -> Vec<String> {
    let mut tags = vec!["mcp".to_string()];
    if let Some(fine) = mcp_server_tag(stdin) {
        tags.push(fine);
    }
    let tool = stdin
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if tool_looks_like_web(tool) {
        tags.push("web".to_string());
    }
    tags
}

pub fn classify_after_shell(stdin: &Value) -> Vec<String> {
    let mut tags = vec!["shell".to_string()];
    let command = stdin
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if command_looks_like_network(command) {
        tags.push("web".to_string());
    }
    tags
}

pub fn hop_secret_tags(path: &str) -> Vec<String> {
    if path_is_sensitive(path) {
        vec![SECRET_TAG.to_string()]
    } else {
        vec![]
    }
}

pub fn load_session(dir: &Path, conversation_id: &str) -> Result<Option<SessionSnap>, String> {
    let path = session_path(dir, conversation_id);
    if !path.is_file() {
        return Ok(None);
    }
    with_lock(&path, || read_snap(&path)).map(Some)
}

pub fn load_lines(dir: &Path, conversation_id: &str) -> Result<Vec<Value>, String> {
    let path = session_path(dir, conversation_id);
    if !path.is_file() {
        return Ok(vec![]);
    }
    with_lock(&path, || read_lines(&path))
}

pub fn append_tags(
    dir: &Path,
    conversation_id: &str,
    src: &str,
    tags: &[String],
    args_hash: &str,
) -> Result<SessionSnap, String> {
    if tags.is_empty() {
        return load_session(dir, conversation_id)?
            .ok_or_else(|| "empty tags and no session".to_string());
    }
    ensure_session_dir(dir)?;
    let path = session_path(dir, conversation_id);
    with_lock(&path, || {
        let mut snap = if path.is_file() {
            read_snap(&path)?
        } else {
            SessionSnap {
                session_id: mint_session_id(),
                tags: vec![],
                parent_session_id: None,
                parent_conversation_id: None,
                parent_caps: vec![],
                subagent_active: false,
            }
        };
        snap.tags = merge_raw(&snap.tags, tags);
        let ts = unix_ts();
        let line = json!({
            "v": 1,
            "ts": ts,
            "op": "tag",
            "src": src,
            "session_id": snap.session_id,
            "tags": tags,
            "args_hash": args_hash,
        });
        append_jsonl(&path, &line)?;
        Ok(snap)
    })
}

/// F-SEQ-01. Empty `tags` so the line is not a taint source.
pub fn append_decision(
    dir: &Path,
    conversation_id: &str,
    action: &str,
    outcome: &str,
    args_hash: &str,
    provenance: &[String],
    session_id: &str,
) -> Result<SessionSnap, String> {
    ensure_session_dir(dir)?;
    let path = session_path(dir, conversation_id);
    with_lock(&path, || {
        let snap = if path.is_file() {
            read_snap(&path)?
        } else {
            SessionSnap {
                session_id: if session_id.is_empty() {
                    mint_session_id()
                } else {
                    session_id.to_string()
                },
                tags: vec![],
                parent_session_id: None,
                parent_conversation_id: None,
                parent_caps: vec![],
                subagent_active: false,
            }
        };
        let line = json!({
            "v": 1,
            "ts": unix_ts(),
            "op": "decision",
            "action": action,
            "outcome": outcome,
            "args_hash": args_hash,
            "provenance": provenance,
            "session_id": snap.session_id,
            "tags": [],
        });
        append_jsonl(&path, &line)?;
        Ok(snap)
    })
}

pub fn workspace_key(v: &Value) -> String {
    let mut roots: Vec<String> = v
        .get("workspace_roots")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    roots.sort();
    if !roots.is_empty() {
        return roots.join("\n");
    }
    v.get("cwd")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn spawn_id_from_stdin(v: &Value) -> String {
    for k in ["agent_id", "tool_call_id", "tool_use_id", "subagent_id"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
            return s.to_string();
        }
    }
    String::new()
}

fn workspace_match(pending: &str, hop: &str) -> bool {
    pending.is_empty() || hop.is_empty() || pending == hop
}

fn pending_to_env(v: &Value) -> Option<ChildEnvelope> {
    let child_session_id = v.get("child_session_id")?.as_str()?.to_string();
    let parent_session_id = v.get("parent_session_id")?.as_str()?.to_string();
    let parent_conversation_id = v.get("parent_conversation_id")?.as_str()?.to_string();
    if child_session_id.is_empty() || parent_session_id.is_empty() {
        return None;
    }
    let parent_caps = v
        .get("parent_caps")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    Some(ChildEnvelope {
        child_session_id,
        parent_session_id,
        parent_conversation_id,
        parent_caps,
        spawn_id: v
            .get("spawn_id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Mint a child in the PEP store. Do not trust Cursor parent_conversation_id.
pub fn child_open(
    dir: &Path,
    parent_conversation_id: &str,
    spawn_id: &str,
    workspace: &str,
    parent_caps: &[String],
    parallel: bool,
) -> Result<ChildEnvelope, String> {
    ensure_session_dir(dir)?;
    let ppath = pending_path(dir);
    let env = with_lock(&ppath, || {
        let pending = if ppath.is_file() {
            read_lines(&ppath)?
        } else {
            vec![]
        };
        if !spawn_id.is_empty() {
            for v in &pending {
                if v.get("spawn_id").and_then(|x| x.as_str()) == Some(spawn_id) {
                    if let Some(e) = pending_to_env(v) {
                        return Ok(e);
                    }
                }
            }
        }
        if !parallel {
            for v in &pending {
                if v.get("parent_conversation_id").and_then(|x| x.as_str())
                    == Some(parent_conversation_id)
                {
                    if let Some(e) = pending_to_env(v) {
                        return Ok(e);
                    }
                }
            }
        }
        let parent_path = session_path(dir, parent_conversation_id);
        let parent_snap = with_lock(&parent_path, || {
            let mut snap = if parent_path.is_file() {
                read_snap(&parent_path)?
            } else {
                empty_snap(mint_session_id())
            };
            if snap.session_id.is_empty() {
                snap.session_id = mint_session_id();
            }
            Ok(snap)
        })?;
        let env = ChildEnvelope {
            child_session_id: mint_session_id(),
            parent_session_id: parent_snap.session_id.clone(),
            parent_conversation_id: parent_conversation_id.to_string(),
            parent_caps: parent_caps.to_vec(),
            spawn_id: spawn_id.to_string(),
        };
        let line = json!({
            "v": 1,
            "ts": unix_ts(),
            "op": "pending",
            "child_session_id": env.child_session_id,
            "parent_session_id": env.parent_session_id,
            "parent_conversation_id": env.parent_conversation_id,
            "parent_caps": env.parent_caps,
            "spawn_id": env.spawn_id,
            "workspace": workspace,
            "tags": [],
        });
        append_jsonl(&ppath, &line)?;
        Ok(env)
    })?;
    let parent_path = session_path(dir, parent_conversation_id);
    with_lock(&parent_path, || {
        let snap = if parent_path.is_file() {
            read_snap(&parent_path)?
        } else {
            empty_snap(env.parent_session_id.clone())
        };
        let line = json!({
            "v": 1,
            "ts": unix_ts(),
            "op": "child_open",
            "session_id": snap.session_id,
            "child_session_id": env.child_session_id,
            "parent_session_id": env.parent_session_id,
            "parent_caps": env.parent_caps,
            "spawn_id": env.spawn_id,
            "tags": [],
        });
        append_jsonl(&parent_path, &line)?;
        Ok(())
    })?;
    Ok(env)
}

/// ponytail: FIFO pending bind. Ceiling: parallel workers / a new chat in the same
/// workspace can mis-bind; Cursor parent_conversation_id is unusable (forum 163054).
/// Upgrade: real parent link on child hooks.
pub fn bind_pending_child(
    dir: &Path,
    child_conversation_id: &str,
    workspace: &str,
) -> Result<Option<ChildEnvelope>, String> {
    if let Some(snap) = load_session(dir, child_conversation_id)? {
        if snap.subagent_active {
            return Ok(Some(ChildEnvelope {
                child_session_id: snap.session_id,
                parent_session_id: snap.parent_session_id.unwrap_or_default(),
                parent_conversation_id: snap.parent_conversation_id.unwrap_or_default(),
                parent_caps: snap.parent_caps,
                spawn_id: String::new(),
            }));
        }
        return Ok(None);
    }
    ensure_session_dir(dir)?;
    let ppath = pending_path(dir);
    let env = with_lock(&ppath, || {
        if !ppath.is_file() {
            return Ok(None);
        }
        let pending = read_lines(&ppath)?;
        let mut keep = Vec::new();
        let mut found = None;
        for v in pending {
            if found.is_none() {
                let ws = v.get("workspace").and_then(|x| x.as_str()).unwrap_or("");
                if workspace_match(ws, workspace) {
                    found = pending_to_env(&v);
                    continue;
                }
            }
            keep.push(v);
        }
        write_all_jsonl(&ppath, &keep)?;
        Ok(found)
    })?;
    let Some(env) = env else {
        return Ok(None);
    };
    let child_path = session_path(dir, child_conversation_id);
    with_lock(&child_path, || {
        let line = json!({
            "v": 1,
            "ts": unix_ts(),
            "op": "child_bind",
            "session_id": env.child_session_id,
            "parent_session_id": env.parent_session_id,
            "parent_conversation_id": env.parent_conversation_id,
            "parent_caps": env.parent_caps,
            "subagent_active": true,
            "tags": [SUBAGENT_TAG],
        });
        append_jsonl(&child_path, &line)?;
        Ok(())
    })?;
    let parent_path = session_path(dir, &env.parent_conversation_id);
    with_lock(&parent_path, || {
        let snap = if parent_path.is_file() {
            read_snap(&parent_path)?
        } else {
            empty_snap(env.parent_session_id.clone())
        };
        let line = json!({
            "v": 1,
            "ts": unix_ts(),
            "op": "child_bind",
            "session_id": snap.session_id,
            "child_session_id": env.child_session_id,
            "child_conversation_id": child_conversation_id,
            "parent_session_id": env.parent_session_id,
            "tags": [],
        });
        append_jsonl(&parent_path, &line)?;
        Ok(())
    })?;
    Ok(Some(env))
}

/// Observe. Never deletes secret/web/mcp tags.
pub fn child_stop(dir: &Path, parent_conversation_id: &str) -> Result<SessionSnap, String> {
    ensure_session_dir(dir)?;
    let path = session_path(dir, parent_conversation_id);
    with_lock(&path, || {
        let snap = if path.is_file() {
            read_snap(&path)?
        } else {
            empty_snap(mint_session_id())
        };
        let line = json!({
            "v": 1,
            "ts": unix_ts(),
            "op": "child_stop",
            "session_id": snap.session_id,
            "tags": [],
        });
        append_jsonl(&path, &line)?;
        Ok(snap)
    })
}

pub fn append_tags_maybe_parent(
    dir: &Path,
    conversation_id: &str,
    src: &str,
    tags: &[String],
    args_hash: &str,
) -> Result<SessionSnap, String> {
    let snap = append_tags(dir, conversation_id, src, tags, args_hash)?;
    if let Some(parent_cid) = &snap.parent_conversation_id {
        if parent_cid != conversation_id && !tags.is_empty() {
            append_tags(dir, parent_cid, src, tags, args_hash)?;
        }
    }
    Ok(snap)
}

fn empty_snap(session_id: String) -> SessionSnap {
    SessionSnap {
        session_id,
        tags: vec![],
        parent_session_id: None,
        parent_conversation_id: None,
        parent_caps: vec![],
        subagent_active: false,
    }
}

fn write_all_jsonl(path: &Path, lines: &[Value]) -> Result<(), String> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    for line in lines {
        let s = serde_json::to_string(line).map_err(|e| format!("session json: {e}"))?;
        writeln!(f, "{s}").map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(())
}

fn merge_raw(a: &[String], b: &[String]) -> Vec<String> {
    let mut out: Vec<String> = a.iter().chain(b.iter()).cloned().collect();
    out.sort();
    out.dedup();
    out
}

fn tool_looks_like_web(name: &str) -> bool {
    let t = name.to_ascii_lowercase();
    t.contains("fetch") || t.contains("search") || t.contains("http") || t.contains("web")
}

fn mcp_server_tag(stdin: &Value) -> Option<String> {
    if let Some(name) = stdin.get("mcp_server_name").and_then(|v| v.as_str()) {
        if let Some(t) = sanitize_server(name) {
            return Some(t);
        }
    }
    if let Some(url) = stdin.get("url").and_then(|v| v.as_str()) {
        if let Some(host) = rough_host(url) {
            if let Some(t) = sanitize_server(&host) {
                return Some(t);
            }
        }
    }
    if let Some(cmd) = stdin.get("command").and_then(|v| v.as_str()) {
        let a0 = cmd.split_whitespace().next().unwrap_or("");
        let base = Path::new(a0)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(a0);
        return sanitize_server(base);
    }
    None
}

fn sanitize_server(s: &str) -> Option<String> {
    let t: String = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if t.is_empty() {
        None
    } else {
        Some(format!("mcp:{t}"))
    }
}

fn rough_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn unix_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

pub(crate) fn ensure_session_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(dir) {
            let mut p = meta.permissions();
            p.set_mode(0o700);
            let _ = fs::set_permissions(dir, p);
        }
    }
    Ok(())
}

fn is_stale_lock(lock_path: &Path) -> bool {
    let Ok(meta) = fs::metadata(lock_path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|age| age >= STALE_LOCK)
        .unwrap_or(false)
}

struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn with_lock<T>(jsonl: &Path, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    if let Some(parent) = jsonl.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_session_dir(parent)?;
        }
    }
    let lock_path = jsonl.with_extension("lock");
    let start = Instant::now();
    loop {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        match opts.open(&lock_path) {
            Ok(_file) => {
                let _guard = LockGuard(lock_path);
                return f();
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if is_stale_lock(&lock_path) {
                    let _ = fs::remove_file(&lock_path);
                    continue;
                }
                if start.elapsed() >= LOCK_WAIT {
                    return Err("session lock timeout".into());
                }
                thread::sleep(LOCK_SLEEP);
            }
            Err(e) => return Err(format!("session lock: {e}")),
        }
    }
}

fn read_lines(path: &Path) -> Result<Vec<Value>, String> {
    let f = fs::File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let reader = BufReader::new(f);
    let mut out = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read {}: {e}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(&line)
            .map_err(|e| format!("corrupt session line {}: {e}", i + 1))?;
        let Some(arr) = v.get("tags").and_then(|x| x.as_array()) else {
            return Err(format!("corrupt session line {}: missing tags", i + 1));
        };
        for t in arr {
            if !t.is_string() {
                return Err(format!("corrupt session line {}: tag not string", i + 1));
            }
        }
        out.push(v);
    }
    Ok(out)
}

fn read_snap(path: &Path) -> Result<SessionSnap, String> {
    let lines = read_lines(path)?;
    let mut session_id = String::new();
    let mut tags = Vec::new();
    let mut parent_session_id = None;
    let mut parent_conversation_id = None;
    let mut parent_caps = Vec::new();
    let mut subagent_active = false;
    for v in &lines {
        if let Some(s) = v.get("session_id").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                session_id = s.to_string();
            }
        }
        if let Some(s) = v.get("parent_session_id").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                parent_session_id = Some(s.to_string());
            }
        }
        if let Some(s) = v.get("parent_conversation_id").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                parent_conversation_id = Some(s.to_string());
            }
        }
        if let Some(arr) = v.get("parent_caps").and_then(|x| x.as_array()) {
            parent_caps = arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
        }
        if v.get("subagent_active").and_then(|x| x.as_bool()) == Some(true)
            || v.get("op").and_then(|x| x.as_str()) == Some("child_bind")
        {
            subagent_active = true;
        }
        if let Some(arr) = v.get("tags").and_then(|x| x.as_array()) {
            for t in arr {
                if let Some(s) = t.as_str() {
                    tags.push(s.to_string());
                }
            }
        }
    }
    tags.sort();
    tags.dedup();
    if session_id.is_empty() {
        session_id = mint_session_id();
    }
    // Parent jsonl also records child_bind (empty tags). That must not taint the parent hop.
    if parent_conversation_id.is_none() {
        subagent_active = false;
    }
    Ok(SessionSnap {
        session_id,
        tags,
        parent_session_id,
        parent_conversation_id,
        parent_caps,
        subagent_active,
    })
}

pub(crate) fn append_jsonl(path: &Path, line: &Value) -> Result<(), String> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let s = serde_json::to_string(line).map_err(|e| format!("session json: {e}"))?;
    writeln!(f, "{s}").map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fairlead-1a-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp");
        dir
    }

    #[test]
    fn classify_web_search_is_mcp_and_web() {
        let v = json!({"tool_name": "web_search", "mcp_server_name": "cursor-ide-browser"});
        let tags = classify_after_mcp(&v);
        assert!(tags.contains(&"mcp".into()), "{tags:?}");
        assert!(tags.contains(&"web".into()), "{tags:?}");
        assert!(tags.contains(&"mcp:cursor-ide-browser".into()), "{tags:?}");
    }

    #[test]
    fn classify_issue_tool_is_mcp_only() {
        let v = json!({"tool_name": "get_latest_issue"});
        let tags = classify_after_mcp(&v);
        assert_eq!(tags, vec!["mcp".to_string()]);
    }

    #[test]
    fn classify_shell_curl_is_shell_and_web() {
        let v = json!({"command": "curl https://x"});
        let tags = classify_after_shell(&v);
        assert!(tags.contains(&"shell".into()));
        assert!(tags.contains(&"web".into()));
    }

    #[test]
    fn secret_filtered_from_cedar() {
        let tags = vec!["mcp".into(), "secret".into(), "web".into()];
        assert_eq!(cedar_provenance(&tags), vec!["mcp".to_string(), "web".to_string()]);
        assert!(hop_secret_tags("/tmp/.env").contains(&SECRET_TAG.to_string()));
        assert!(hop_secret_tags("src/main.rs").is_empty());
    }

    #[test]
    fn append_then_load_unions() {
        let dir = temp_dir();
        let cid = "conv-a";
        append_tags(&dir, cid, "after-mcp", &["mcp".into()], "aa").expect("tag mcp");
        append_tags(&dir, cid, "after-mcp", &["web".into(), "mcp".into()], "bb")
            .expect("tag web");
        let snap = load_session(&dir, cid).expect("load").expect("present");
        assert!(snap.tags.contains(&"mcp".into()));
        assert!(snap.tags.contains(&"web".into()));
        assert!(!snap.session_id.is_empty());
        let raw = fs::read_to_string(session_path(&dir, cid)).expect("read");
        assert!(!raw.contains("result_json"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reduce_maps_secret_web_mcp_not_fine_tags() {
        let empty = reduce(&[]);
        assert_eq!(empty, SessionFacts::default());

        let lines = vec![
            json!({"tags": ["secret"], "args_hash": "a1"}),
            json!({"tags": ["secret"], "args_hash": "a1"}),
            json!({"tags": ["web", "mcp"], "args_hash": "b"}),
            json!({"tags": ["mcp:cursor-ide-browser", "shell"], "args_hash": "c"}),
            json!({"op": "decision", "tags": [], "args_hash": "d"}),
        ];
        let facts = reduce(&lines);
        assert!(facts.touched_secrets);
        assert!(facts.saw_untrusted_web);
        assert!(facts.saw_mcp_untrusted);
        assert_eq!(facts.secret_read_count, 1);
        assert!(!facts.subagent_active);

        let two = reduce(&[
            json!({"tags": ["secret"], "args_hash": "x"}),
            json!({"tags": ["secret"], "args_hash": "y"}),
        ]);
        assert_eq!(two.secret_read_count, 2);
    }

    #[test]
    fn append_decision_empty_tags_does_not_taint() {
        let dir = temp_dir();
        let cid = "conv-dec";
        append_decision(&dir, cid, "Shell", "allow", "hh", &["user".into()], "sid1")
            .expect("decision");
        let snap = load_session(&dir, cid).expect("load").expect("present");
        assert_eq!(snap.session_id, "sid1");
        assert!(snap.tags.is_empty(), "{:?}", snap.tags);
        let facts = reduce(&load_lines(&dir, cid).expect("lines"));
        assert_eq!(facts, SessionFacts::default());
        let raw = fs::read_to_string(session_path(&dir, cid)).expect("read");
        assert!(raw.contains("\"op\":\"decision\""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn child_open_bind_stop_monotonic_secret() {
        let dir = temp_dir();
        let parent = "conv-parent";
        let child = "conv-child";
        let env = child_open(&dir, parent, "spawn-1", "", &[], false).expect("open");
        assert!(!env.child_session_id.is_empty());
        assert_eq!(env.parent_conversation_id, parent);
        let again = child_open(&dir, parent, "spawn-1", "", &[], false).expect("idempotent");
        assert_eq!(again.child_session_id, env.child_session_id);

        let bound = bind_pending_child(&dir, child, "").expect("bind").expect("pending");
        assert_eq!(bound.child_session_id, env.child_session_id);
        let snap = load_session(&dir, child).expect("load").expect("child");
        assert!(snap.subagent_active);
        assert_eq!(snap.parent_session_id.as_deref(), Some(env.parent_session_id.as_str()));
        assert!(snap.tags.contains(&SUBAGENT_TAG.to_string()));

        append_tags_maybe_parent(&dir, child, "read", &[SECRET_TAG.into()], "hh").expect("tag");
        let parent_facts = reduce(&load_lines(&dir, parent).expect("plines"));
        assert!(parent_facts.touched_secrets);
        child_stop(&dir, parent).expect("stop");
        let after = reduce(&load_lines(&dir, parent).expect("plines2"));
        assert!(after.touched_secrets);
        assert!(!after.subagent_active);
        let raw = fs::read_to_string(session_path(&dir, parent)).expect("pread");
        assert!(raw.contains("\"secret\""));
        assert!(raw.contains("\"op\":\"child_stop\""));
        let parent_snap = load_session(&dir, parent).expect("pload").expect("parent");
        assert!(!parent_snap.subagent_active);
        let _ = fs::remove_dir_all(&dir);
    }
}
