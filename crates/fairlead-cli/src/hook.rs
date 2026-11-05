// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

use fairlead_core::{
    append_shadow_line, claude_deny_stdout, claude_hook_eval, cursor_hook_eval, cursor_hook_observe,
    cursor_hook_shadow, cursor_pretool, cursor_subagent_start, cursor_subagent_stop,
    armed_stamp_present, check_kill, docs_root, format_stats, hashes_of, key_id, last_armed_path, live_check, load_policy_bytes,
    utf8_src,
    load_signing_key, managed_dir, observe_path, pin_dir, Kill, openhands_hook_eval, permission_label, receipts_path, seed_path, sha256_hex, sign_receipt,
    tally_decisions, tally_would_deny, windsurf_hook_eval, write_claude_settings, write_cursor_hooks,
    write_openhands_hooks, write_windsurf_hooks, Engine, HashTriple,
    HookEval, ReceiptPayload, ReceiptPrincipal,
};
use std::io::{self, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Below Claude host timeout (settings.json timeout is seconds). Deny-on-stuck, not LLM room.
const CLAUDE_HOOK_BUDGET: Duration = Duration::from_millis(5_000);
/// Empty stdin waits this long for the sibling that got the body.
const SIBLING_WAIT: Duration = Duration::from_millis(300);
/// A body marker older than this is a previous command, not this step.
const SIBLING_FRESH: Duration = Duration::from_millis(800);

pub fn run_hook(mut args: impl Iterator<Item = String>) {
    match args.next().as_deref() {
        Some("cursor") => match args.next().as_deref() {
            Some("shell") => gate("shell"),
            Some("mcp") => gate("mcp"),
            Some("read") => gate("read"),
            Some("subagent-start") => start_gate(),
            Some("subagent-stop") => stop_observe(),
            Some("pretool") => pretool_gate(),
            Some("after-mcp") => observe("after-mcp"),
            Some("after-shell") => observe("after-shell"),
            _ => {
                eprintln!("usage: fairlead hook cursor {{shell,mcp,read,subagent-start,subagent-stop,pretool,after-mcp,after-shell}}");
                std::process::exit(2);
            }
        },
        Some("claude") => match args.next().as_deref() {
            Some("pretool") => claude_gate("pretool"),
            Some("permission-request") => claude_gate("permission-request"),
            Some("subagent-stop") => claude_gate("subagent-stop"),
            Some("subagent-start") => claude_gate("subagent-start"),
            _ => {
                eprintln!("usage: fairlead hook claude {{pretool,permission-request,subagent-stop,subagent-start}}");
                std::process::exit(2);
            }
        },
        Some("windsurf") => match args.next().as_deref() {
            Some("pre") => windsurf_gate(),
            _ => {
                eprintln!("usage: fairlead hook windsurf pre");
                std::process::exit(2);
            }
        },
        Some("openhands") => match args.next().as_deref() {
            Some("pretool") => openhands_gate(),
            _ => {
                eprintln!("usage: fairlead hook openhands pretool");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!("usage: fairlead hook cursor {{shell,mcp,read,subagent-start,subagent-stop,pretool,after-mcp,after-shell}} | hook claude {{pretool,permission-request,subagent-stop,subagent-start}}");
            std::process::exit(2);
        }
    }
}

pub fn run_observe(mut args: impl Iterator<Item = String>) {
    match args.next().as_deref() {
        Some("cursor") => match args.next().as_deref() {
            Some("shell") => shadow_gate("shell"),
            Some("mcp") => shadow_gate("mcp"),
            Some("read") => shadow_gate("read"),
            _ => {
                eprintln!("usage: fairlead observe cursor {{shell,mcp,read}}");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!("usage: fairlead observe cursor {{shell,mcp,read}}");
            std::process::exit(2);
        }
    }
}

pub fn stats() {
    let rec = receipts_path();
    let tally = tally_decisions(&rec);
    if tally.malformed > 0 {
        eprintln!("malformed receipts: {}", tally.malformed);
    }
    let would_deny = if observe_path().is_file() {
        match tally_would_deny(&observe_path()) {
            Some((n, mal)) => {
                if mal > 0 {
                    eprintln!("malformed observe: {mal}");
                }
                Some(n)
            }
            None => None,
        }
    } else {
        None
    };
    print!("{}", format_stats(&tally, &rec, would_deny));
}

fn shadow_gate(kind: &str) {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        let dest = observe_path();
        let _ = append_shadow_line(&dest, true, true, kind, None, &[], "");
        emit(
            &serde_json::json!({
                "permission": "allow",
                "user_message": "",
                "agent_message": "",
            }),
            0,
        );
    }
    let engine = match load_engine() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            let dest = observe_path();
            let _ = append_shadow_line(&dest, true, true, kind, None, &[], "");
            emit(
                &serde_json::json!({
                    "permission": "allow",
                    "user_message": "",
                    "agent_message": "",
                }),
                0,
            );
        }
    };
    let eval = cursor_hook_shadow(kind, &raw, &engine);
    emit(&eval.stdout, 0);
}

pub fn install_hooks(dir: &str) {
    let docs = match docs_root() {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    let exe = match std::env::current_exe() {
        Ok(p) => std::fs::canonicalize(&p).unwrap_or(p),
        Err(e) => refuse(&format!("current_exe: {e}")),
    };
    match write_cursor_hooks(Path::new(dir), &exe, &docs) {
        Ok(dest) => println!("{}", dest.display()),
        Err(e) => refuse(&e),
    }
    match write_claude_settings(Path::new(dir), &exe, &docs) {
        Ok(dest) => println!("{}", dest.display()),
        Err(e) => refuse(&e),
    }
    match write_windsurf_hooks(Path::new(dir), &exe, &docs) {
        Ok(dest) => println!("{}", dest.display()),
        Err(e) => refuse(&e),
    }
    match write_openhands_hooks(Path::new(dir), &exe, &docs) {
        Ok(dest) => println!("{}", dest.display()),
        Err(e) => refuse(&e),
    }
}

fn refuse(msg: &str) -> ! {
    eprintln!("refuse to arm: {msg}");
    std::process::exit(1);
}

/// F-BYP-07: org deny-all, read before Cedar and before the empty-stdin sibling stand-down.
/// Returns the kill id, or None on OSS / never-killed seats. No docs root means no pack and
/// the engine load denies anyway.
fn killed() -> Option<String> {
    let root = docs_root().ok()?;
    match check_kill(&managed_dir(), &root) {
        Kill::Killed(id) => Some(id),
        Kill::Clear => None,
    }
}

/// Cursor-shaped deny for an org kill. Signs a receipt when armed; deny stands if signing fails.
fn cursor_kill_deny(raw: &str, action: &str, agent: &str) {
    let Some(id) = killed() else { return };
    let msg = format!("fairlead deny: org kill switch ({id})");
    let mut eval = claude_fail_eval("pretool", &msg);
    eval.stdout = if agent == "openhands" {
        // OpenHands: a present `decision` overrides the exit code, so say deny in its own shape.
        serde_json::json!({"decision": "deny", "reason": msg})
    } else {
        serde_json::json!({"permission": "deny", "user_message": msg, "agent_message": msg})
    };
    // Same action labels as the Cedar path, so fleet queries over receipts see one vocabulary
    // (live probe 2026-10-10: kill receipts said "shell", allowed ones said "Shell").
    eval.action = match action {
        "shell" => "Shell",
        "mcp" => "McpCall",
        "read" => "FileRead",
        "write" => "FileWrite",
        "subagent-start" => "SubagentStart",
        other => other,
    }
    .to_string();
    eval.policy_ids = vec!["F-BYP-07".into()];
    eval.tool_name = tool_name_of(raw);
    let _ = maybe_sign(&eval, raw, agent);
    emit(&eval.stdout, 2);
}

fn gate(kind: &str) {
    // F-AUD-04: ignore FAIRLEAD_OBSERVE. Observe is a separate argv, not fail-open.
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit_deny("invalid hook json");
    }
    cursor_kill_deny(&raw, kind, "cursor");
    finish_closed_stdin(&raw, kind);
    let engine = match load_engine() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            emit_deny(e.sentence);
        }
    };
    let eval = cursor_hook_eval(kind, &raw, &engine);
    if maybe_sign(&eval, &raw, "cursor").is_err() {
        emit_deny("fairlead deny: receipt");
    }
    emit(&eval.stdout, eval.exit);
}

fn observe(kind: &str) {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit(&serde_json::json!({}), 0);
    }
    let eval = cursor_hook_observe(kind, &raw);
    emit(&eval.stdout, eval.exit);
}

fn start_gate() {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit_deny("invalid hook json");
    }
    cursor_kill_deny(&raw, "subagent-start", "cursor");
    finish_closed_stdin(&raw, "subagent-start");
    let eval = cursor_subagent_start(&raw);
    if maybe_sign(&eval, &raw, "cursor").is_err() {
        emit_deny("fairlead deny: receipt");
    }
    emit(&eval.stdout, eval.exit);
}

fn stop_observe() {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit(&serde_json::json!({}), 0);
    }
    let eval = cursor_subagent_stop(&raw);
    emit(&eval.stdout, eval.exit);
}

fn windsurf_gate() {
    host_gate("windsurf", |raw, engine| windsurf_hook_eval(raw, engine));
}

fn openhands_gate() {
    host_gate("openhands", |raw, engine| openhands_hook_eval(raw, engine));
}

fn host_gate(agent: &str, eval_fn: impl Fn(&str, &Engine) -> HookEval) {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit_deny("invalid hook json");
    }
    cursor_kill_deny(&raw, agent, agent);
    let engine = match load_engine() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            emit_deny(e.sentence);
        }
    };
    let eval = eval_fn(&raw, &engine);
    if maybe_sign(&eval, &raw, agent).is_err() {
        emit_deny("fairlead deny: receipt");
    }
    emit(&eval.stdout, eval.exit);
}

fn pretool_gate() {
    // ponytail: Task matcher may not fire; spawn still gated by subagentStart.
    // Write matcher + failClosed is the F-DEF-01 socket. afterFileEdit is too late.
    // Cursor ask on preToolUse is unenforced; deny JSON + exit 2 is the contract.
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit_deny("invalid hook json");
    }
    cursor_kill_deny(&raw, "pretool", "cursor");
    finish_closed_stdin(&raw, "pretool");
    let engine = match load_engine() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            emit_deny(e.sentence);
        }
    };
    let eval = cursor_pretool(&raw, &engine);
    if maybe_sign(&eval, &raw, "cursor").is_err() {
        emit_deny("fairlead deny: receipt");
    }
    emit(&eval.stdout, eval.exit);
}

fn claude_fail_eval(event: &str, msg: &str) -> HookEval {
    let (stdout, exit) = claude_deny_stdout(event, msg);
    HookEval {
        stdout,
        exit,
        action: event.to_string(),
        command_preview: None,
        tool_name: String::new(),
        session: String::new(),
        provenance: vec![],
        policy_ids: vec![],
        parent_session_id: None,
        parent_caps: vec![],
    }
}

fn tool_name_of(raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return String::new();
    };
    let name = v
        .get("tool_name")
        .and_then(|s| s.as_str())
        .or_else(|| {
            v.get("tool_info")
                .and_then(|t| t.get("mcp_tool_name"))
                .and_then(|s| s.as_str())
        })
        .unwrap_or("");
    name.chars().take(200).collect()
}

fn claude_gate(event: &str) {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("stdin: {e}");
        emit_claude_deny(event, "invalid hook json");
    }
    if let Some(id) = killed() {
        let mut eval = claude_fail_eval(event, &format!("fairlead deny: org kill switch ({id})"));
        eval.policy_ids = vec!["F-BYP-07".into()];
        // SubagentStart/Stop deny is `{}` on the wire (the host cannot block them), which
        // permission_label reads as allow. Sign the truth: an org kill is a deny.
        let mut signed = claude_fail_eval(event, "fairlead deny: org kill switch");
        signed.stdout = serde_json::json!({"permission": "deny"});
        signed.policy_ids = eval.policy_ids.clone();
        signed.tool_name = tool_name_of(&raw);
        let _ = maybe_sign(&signed, &raw, "claude");
        emit_claude(&eval.stdout, eval.exit);
    }
    let event_s = event.to_string();
    let event_panic = event_s.clone();
    let raw_worker = raw.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let eval = panic::catch_unwind(AssertUnwindSafe(|| match load_engine() {
            Ok(engine) => claude_hook_eval(&event_s, &raw_worker, &engine),
            Err(e) => {
                eprintln!("engine: {e}");
                let mut eval = claude_fail_eval(&event_s, e.sentence);
                eval.tool_name = tool_name_of(&raw_worker);
                eval
            }
        }))
        .unwrap_or_else(|_| {
            eprintln!("fairlead panic");
            let mut eval = claude_fail_eval(&event_panic, "fairlead deny");
            eval.tool_name = tool_name_of(&raw_worker);
            eval
        });
        let _ = tx.send(eval);
    });
    match rx.recv_timeout(CLAUDE_HOOK_BUDGET) {
        Ok(eval) => {
            if maybe_sign(&eval, &raw, "claude").is_err() {
                emit_claude_deny(event, "fairlead deny: receipt");
            }
            emit_claude(&eval.stdout, eval.exit);
        }
        Err(_) => {
            eprintln!("fairlead deny: budget");
            emit_claude_deny(event, "fairlead deny: timeout");
        }
    }
}

/// A load that must deny. `sentence` is what the host shows; Display is the stderr detail.
struct LoadErr {
    sentence: &'static str,
    detail: String,
}

impl std::fmt::Display for LoadErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

/// Digest of the pack bytes this process parsed. The receipt carries this one, not a second read.
static PARSED_PACK: OnceLock<String> = OnceLock::new();

/// One read of schema and cedar. The same buffers are drift-checked, hashed and parsed, so no
/// rewrite can land between the check and the evaluate.
fn load_engine() -> Result<Engine, LoadErr> {
    let plain = |detail: String| LoadErr {
        sentence: "fairlead deny",
        detail,
    };
    let docs = docs_root().map_err(plain)?;
    let read = |rel: &str| {
        let p = docs.join(rel);
        std::fs::read(&p).map_err(|e| plain(format!("read {}: {e}", p.display())))
    };
    let schema = read("policies/coding-agent.cedarschema")?;
    let cedar = read("policies/baseline.cedar")?;
    let digest = live_check(&docs, &managed_dir(), &schema, &cedar).map_err(|d| LoadErr {
        sentence: d.sentence,
        detail: d.detail,
    })?;
    let _ = PARSED_PACK.set(digest);
    let schema = utf8_src(&schema, "schema").map_err(plain)?;
    let cedar = utf8_src(&cedar, "cedar").map_err(plain)?;
    Engine::load(&schema, &cedar).map_err(plain)
}

fn maybe_sign(eval: &HookEval, raw: &str, agent: &str) -> Result<(), String> {
    let docs = match docs_root() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("receipt: {e}");
            write_signing_tombstone(eval, raw, agent, &e, None);
            return Err(e);
        }
    };
    let managed = managed_dir();
    let required = seed_path(&docs).is_file()
        || last_armed_path(&pin_dir(&docs, &managed)).is_file()
        || armed_stamp_present(&managed);
    if !required {
        return Ok(());
    }
    let dest = receipts_path();
    let fail = |e: String, hashes: Option<&HashTriple>| {
        eprintln!("receipt: {e}");
        write_signing_tombstone(eval, raw, agent, &e, hashes);
        e
    };
    let policy = match load_policy_bytes(&docs, "policies/coding-agent.cedarschema", "policies/baseline.cedar")
    {
        Ok(p) => p,
        Err(e) => return Err(fail(e, None)),
    };
    let mut hashes = match hashes_of(&policy) {
        Ok(h) => h,
        Err(e) => return Err(fail(e, None)),
    };
    if let Some(p) = PARSED_PACK.get() {
        hashes.policy_pack_sha256 = p.clone();
    }
    let key = match load_signing_key(&docs) {
        Ok(k) => k,
        Err(e) => return Err(fail(e, Some(&hashes))),
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());
    let permission = permission_label(&eval.stdout);
    let payload = ReceiptPayload {
        v: 1,
        ts,
        decision: permission.to_string(),
        principal: ReceiptPrincipal {
            user: String::new(),
            agent: agent.into(),
            session: eval.session.clone(),
        },
        action: eval.action.clone(),
        tool_name: eval.tool_name.chars().take(200).collect(),
        args_hash: sha256_hex(raw.as_bytes()),
        command_preview: eval.command_preview.clone(),
        provenance: eval.provenance.clone(),
        policy_ids: eval.policy_ids.clone(),
        granted_caps: vec![],
        parent_session_id: eval.parent_session_id.clone(),
        parent_caps: eval.parent_caps.clone(),
        key_id: key_id(&key.verifying_key()),
        binary_sha256: hashes.binary_sha256.clone(),
        policy_pack_sha256: hashes.policy_pack_sha256.clone(),
        hooks_sha256: hashes.hooks_sha256.clone(),
    };
    let json = match sign_receipt(&payload, &key) {
        Ok(s) => s,
        Err(e) => return Err(fail(e, Some(&hashes))),
    };
    let line = json.replace('\n', "").replace('\r', "");
    if let Err(e) = append_line(&dest, &line) {
        return Err(fail(e, Some(&hashes)));
    }
    Ok(())
}

fn write_signing_tombstone(
    eval: &HookEval,
    raw: &str,
    agent: &str,
    error: &str,
    hashes: Option<&HashTriple>,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into());
    let mut line = serde_json::json!({
        "type": "fairlead.signing_failure.v1",
        "v": 1,
        "ts": ts,
        "decision": "deny",
        "policy_decision": permission_label(&eval.stdout),
        "action": eval.action,
        "args_hash": sha256_hex(raw.as_bytes()),
        "error": error,
        "agent": agent,
        "session": eval.session,
    });
    if let Some(h) = hashes {
        line["binary_sha256"] = serde_json::Value::String(h.binary_sha256.clone());
        line["policy_pack_sha256"] = serde_json::Value::String(h.policy_pack_sha256.clone());
        line["hooks_sha256"] = serde_json::Value::String(h.hooks_sha256.clone());
    }
    let compact = line.to_string();
    let _ = append_line(&receipts_path(), &compact);
}

fn append_line(path: &Path, line: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("write {}: {e}", path.display()))
}

enum ClosedStdin {
    /// Sibling already has the body. Do not veto it.
    NoOpinion,
    /// This was the only delivery. Fail closed.
    Deny,
}

/// Cursor double-fires a hook step: one process gets the JSON body, one gets immediate EOF
/// (live: `ls` allowed and sha256("") denied in the same second). The empty process stands
/// down only when a sibling of the same kind wrote a body marker inside `SIBLING_FRESH`.
/// Otherwise empty stdin denies. Junk JSON is `None` and still denies in the eval path.
/// ponytail: marker is per hook kind, not per call. Ceiling: two overlapping commands of
/// the same kind inside `SIBLING_FRESH` can cross-wire, so a lost body no-opinions.
/// Upgrade: key the marker on a host request id once Cursor puts one on the empty process.
fn finish_closed_stdin(raw: &str, kind: &str) {
    match cursor_closed_stdin(raw, kind, &fairlead_core::session_dir(), SIBLING_WAIT) {
        Some(ClosedStdin::NoOpinion) => emit(
            &serde_json::json!({
                "permission": "allow",
                "user_message": "",
                "agent_message": "",
            }),
            0,
        ),
        Some(ClosedStdin::Deny) => emit_deny("empty hook stdin"),
        None => {
            if let Err(e) = write_body_marker(kind, &fairlead_core::session_dir()) {
                eprintln!("fairlead: hook body marker: {e}");
            }
        }
    }
}

fn cursor_closed_stdin(raw: &str, kind: &str, dir: &Path, wait: Duration) -> Option<ClosedStdin> {
    if !raw.trim().is_empty() {
        return None;
    }
    if sibling_has_body(kind, dir, wait) {
        eprintln!("fairlead: empty hook stdin; sibling has the body");
        Some(ClosedStdin::NoOpinion)
    } else {
        eprintln!("fairlead: empty hook stdin");
        Some(ClosedStdin::Deny)
    }
}

fn write_body_marker(kind: &str, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let path = marker_path(dir, kind);
    std::fs::write(&path, now_ms().to_string()).map_err(|e| format!("write {}: {e}", path.display()))
}

fn sibling_has_body(kind: &str, dir: &Path, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    loop {
        if marker_fresh(kind, dir) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn marker_fresh(kind: &str, dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(marker_path(dir, kind)) else {
        return false;
    };
    let Ok(ms) = text.trim().parse::<u128>() else {
        return false;
    };
    now_ms().saturating_sub(ms) <= SIBLING_FRESH.as_millis()
}

fn marker_path(dir: &Path, kind: &str) -> PathBuf {
    let safe: String = kind
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    dir.join(format!("hook-body-{safe}"))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn emit_deny(msg: &str) -> ! {
    emit(
        &serde_json::json!({
            "permission": "deny",
            "user_message": msg,
            "agent_message": msg,
        }),
        2,
    );
}

fn emit(stdout: &serde_json::Value, exit: i32) -> ! {
    let mut out = io::stdout();
    let _ = writeln!(out, "{stdout}");
    let _ = out.flush();
    // ponytail: Cursor drain race (forum 165818); drop when they fix it
    thread::sleep(Duration::from_millis(50));
    std::process::exit(exit);
}

fn emit_claude_deny(event: &str, msg: &str) -> ! {
    let (stdout, exit) = claude_deny_stdout(event, msg);
    emit_claude(&stdout, exit);
}

fn emit_claude(stdout: &serde_json::Value, exit: i32) -> ! {
    let mut out = io::stdout();
    let _ = writeln!(out, "{stdout}");
    let _ = out.flush();
    std::process::exit(exit);
}

#[cfg(test)]
mod tests {
    use super::{cursor_closed_stdin, write_body_marker, ClosedStdin};
    use std::time::Duration;

    #[test]
    fn empty_stdin_denies_unless_sibling_has_the_body() {
        let dir = std::env::temp_dir().join(format!("fairlead-stdin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        assert!(matches!(
            cursor_closed_stdin("", "shell", &dir, Duration::ZERO),
            Some(ClosedStdin::Deny)
        ));
        write_body_marker("shell", &dir).expect("marker");
        assert!(matches!(
            cursor_closed_stdin(" \n", "shell", &dir, Duration::ZERO),
            Some(ClosedStdin::NoOpinion)
        ));
        assert!(
            matches!(
                cursor_closed_stdin("", "read", &dir, Duration::ZERO),
                Some(ClosedStdin::Deny)
            ),
            "a shell marker must not cover read"
        );
        assert!(cursor_closed_stdin("not-json", "shell", &dir, Duration::ZERO).is_none());
        assert!(cursor_closed_stdin("{}", "shell", &dir, Duration::ZERO).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
