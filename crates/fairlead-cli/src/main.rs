// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

mod hook;

use fairlead_core::{
    check_claude_settings, check_hooks_fail_closed, compare_armed, decision_label, docs_file,
    docs_root, hashes_of, load_or_create_signing_key, load_policy_bytes, load_signing_key,
    read_last_armed, run_cases, utf8_src, verify_receipt_json,
    ArmedDrift, Engine, PolicyBytes,
};
use fairlead_core::{
    claude_effective_sandbox, claude_hook_findings, claude_in_use, claude_scopes,
    claude_version_finding, host_sandbox_findings, last_armed_bytes, managed_dir, managed_optin, require_pin_if_keyed_at,
    root_only, write_armed_stamp, write_last_armed_gen,
};
use std::io::Read;
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("doctor") => doctor(),
        Some("verify-receipt") => match args.next() {
            Some(path) => verify_receipt(&path),
            None => usage(),
        },
        Some("arm") => {
            let reviewed = args.any(|a| a == "--i-reviewed-pack");
            arm(reviewed);
        }
        Some("hook") => hook::run_hook(args),
        Some("observe") => hook::run_observe(args),
        Some("stats") => hook::stats(),
        Some("mcp-proxy") => mcp_proxy(args.collect()),
        Some("install-hooks") => match args.next() {
            Some(dir) => hook::install_hooks(&dir),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: fairlead doctor | verify-receipt <path> | arm [--i-reviewed-pack] | hook cursor {{shell,mcp,read,subagent-start,subagent-stop,pretool,after-mcp,after-shell}} | hook claude {{pretool,permission-request,subagent-stop,subagent-start}} | hook windsurf pre | hook openhands pretool | observe cursor {{shell,mcp,read}} | stats | install-hooks <dir> | mcp-proxy [--observe] [--tool NAME]... -- <upstream cmd...>"
    );
    std::process::exit(2);
}

/// `fairlead mcp-proxy [--observe] [--tool NAME]... -- upstream args...`. Stdout is MCP protocol only.
fn mcp_proxy(args: Vec<String>) {
    let (mut tools, mut it) = (Vec::new(), args.into_iter());
    let (mut upstream, mut observe) = (Vec::new(), false);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tool" => tools.extend(it.next()),
            "--observe" => observe = true,
            "--" => {
                upstream.extend(it.by_ref());
            }
            _ => usage(),
        }
    }
    if upstream.is_empty() {
        usage();
    }
    if tools.is_empty() {
        // ponytail: Goal 10 ships one pipe; list more with repeated --tool.
        tools.push("get_latest_issue".into());
    }
    // Rewrite is the default; FAIRLEAD_QLLM unset makes every quarantined call fail closed.
    let dir = fairlead_core::session_dir();
    let rewrite = (!observe).then_some(fairlead_core::mcp_proxy::Rewrite {
        dir: &dir,
        complete: &fairlead_core::quarantine::env_complete,
    });
    let cfg = fairlead_core::mcp_proxy::Config { tools, rewrite };
    let stdin = std::io::stdin().lock();
    if let Err(e) = fairlead_core::mcp_proxy::run_io(&cfg, &upstream, stdin, std::io::stdout(), std::io::stderr()) {
        eprintln!("mcp-proxy: {e}");
        std::process::exit(1);
    }
}

struct Fixture {
    schema_rel: String,
    policies_rel: String,
    json: serde_json::Value,
}

fn load_fixture(docs: &Path) -> Fixture {
    let fixture_rel = "tests/doctor/cases.json";
    let raw = match docs_file(fixture_rel) {
        Ok(s) => s,
        Err(e) => refuse(&e),
    };
    let json: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => refuse(&format!(
            "parse {}: {e}",
            docs.join(fixture_rel).display()
        )),
    };
    let schema_rel = match json.get("schema").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => refuse("missing schema path"),
    };
    let policies_rel = match json.get("policies").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => refuse("missing policies path"),
    };
    Fixture {
        schema_rel,
        policies_rel,
        json,
    }
}

fn doctor() {
    let docs = match docs_root() {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    let fixture = load_fixture(&docs);
    let policy = match load_policy_bytes(&docs, &fixture.schema_rel, &fixture.policies_rel) {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    let hashes = match hashes_of(&policy) {
        Ok(h) => h,
        Err(e) => refuse(&e),
    };
    println!("binary_sha256: {}", hashes.binary_sha256);
    println!("policy_pack_sha256: {}", hashes.policy_pack_sha256);
    println!("hooks_sha256: {}", hashes.hooks_sha256);

    match (&policy.hooks, &policy.claude_settings) {
        (None, None) => eprintln!("unarmed: no hooks"),
        (cursor, claude) => {
            if let Some((_, bytes)) = cursor {
                let v: serde_json::Value = match serde_json::from_slice(bytes) {
                    Ok(v) => v,
                    Err(e) => refuse(&format!("parse hooks.json: {e}")),
                };
                if let Err(e) = check_hooks_fail_closed(&v) {
                    refuse(&e);
                }
            }
            if let Some((_, bytes)) = claude {
                let v: serde_json::Value = match serde_json::from_slice(bytes) {
                    Ok(v) => v,
                    Err(e) => refuse(&format!("parse settings.json: {e}")),
                };
                if let Err(e) = check_claude_settings(&v) {
                    refuse(&e);
                }
            }
        }
    }

    let managed = managed_dir();
    let optin = managed_optin(&managed);
    let pin_root = if optin { managed.clone() } else { docs.clone() };
    if let Err(e) = require_pin_if_keyed_at(&docs, &pin_root) {
        refuse(&e);
    }

    let fixtures_ok = prove_pack(&policy, &fixture.json);
    eprintln!("residual: prompt injection not solved");
    eprintln!("residual: local admin can uninstall (F-BYP-10)");
    eprintln!("residual: receipts are hook surface not host; MVP has no tools-without-receipts");
    eprintln!("residual: Cursor Cloud user hooks / early read-only turns / MCP hooks do not run, and Claude YOLO subagents are untested; an empty receipt log is not a finding");
    eprintln!("residual: Claude onFailure block covers a failing hook (2.1.295+); a hook entry that never loads is not covered");
    eprintln!("residual: Shell inspect vs exec TOCTOU (host O_NOFOLLOW / sandbox)");
    eprintln!("residual: quarantine covers one MCP pipe only; paste, cat/shell output, repo files not quarantined (F-Q-09)");
    if optin {
        refuse_on_gaps(&managed, &policy, true);
    }
    check_host_sandbox(optin);
    if !fixtures_ok {
        refuse("fixtures failed");
    }

    match read_last_armed(&pin_root) {
        Ok(None) => {}
        Ok(Some(last)) => match compare_armed(&hashes, &last) {
            Ok(()) => {}
            Err(ArmedDrift::Pack { old, new }) => {
                eprintln!("pack hash drifted\nold: {old}\nnew: {new}");
                refuse("pack hash drifted; fairlead arm --i-reviewed-pack");
            }
            Err(ArmedDrift::Binary { old, new }) => {
                eprintln!("binary hash drifted\nold: {old}\nnew: {new}");
                refuse("hash drifted; fairlead arm");
            }
            Err(ArmedDrift::Hooks { old, new }) => {
                eprintln!("hooks hash drifted\nold: {old}\nnew: {new}");
                refuse("hash drifted; fairlead arm");
            }
        },
        Err(e) => refuse(&e),
    }
}

/// `claude --version`, 5s budget; `None` when there is no binary or it does not answer.
fn claude_version_out() -> Option<String> {
    let mut child = std::process::Command::new("claude")
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        let _ = tx.send(s);
    });
    let got = rx.recv_timeout(std::time::Duration::from_secs(5)).ok();
    if got.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    got
}

/// Host config check (Fairlead enforces nothing here): Claude hook layer and version, Claude and
/// Cursor OS sandbox. Notes always print. Gaps refuse on a managed seat and warn elsewhere, so an
/// OSS arm is never blocked by a host setting. Claude is only checked when some scope carries a
/// Fairlead Claude hook, so a Cursor-only seat with a stray `~/.claude` is left alone.
fn check_host_sandbox(enforce: bool) {
    let (scopes, scope_errs) = claude_scopes();
    let in_use = claude_in_use(&scopes);
    let mut hook = fairlead_core::SandboxFindings::default();
    if in_use {
        hook = claude_hook_findings(&scopes);
        hook.gaps.extend(scope_errs);
        let (gap, note) = claude_version_finding(claude_version_out().as_deref());
        hook.gaps.extend(gap);
        hook.notes.extend(note);
    }
    let claude = in_use.then(|| claude_effective_sandbox(&scopes));
    let mut cursor = Vec::new();
    let mut candidates = Vec::new();
    if let Ok(h) = std::env::var("HOME") {
        candidates.push(Path::new(&h).join(".cursor/sandbox.json"));
    }
    if let Ok(c) = std::env::current_dir() {
        candidates.push(c.join(".cursor/sandbox.json"));
    }
    for p in candidates {
        let Ok(bytes) = std::fs::read(&p) else { continue };
        match serde_json::from_slice(&bytes) {
            Ok(v) => cursor.push((p.display().to_string(), v)),
            Err(e) => eprintln!("residual: host sandbox: {} unparseable ({e})", p.display()),
        }
    }
    let mut f = host_sandbox_findings(claude.as_ref(), &cursor);
    f.gaps.extend(hook.gaps);
    f.notes.extend(hook.notes);
    for n in &f.notes {
        eprintln!("residual: host sandbox: {n}");
    }
    if f.gaps.is_empty() {
        return;
    }
    if enforce {
        refuse(&format!("host hooks or sandbox are off or loosened:\n- {}", f.gaps.join("\n- ")));
    }
    for g in &f.gaps {
        eprintln!("warning: host sandbox: {g}");
    }
}

/// Managed opt-in: a root-only pin is worthless if the seat user can swap what the hook runs.
/// Refuse (doctor and arm) unless the managed dir, the binary and the `FAIRLEAD_HOOKS` file are
/// root-owned and not group/other writable (file and its parent). Mode-bit check, so a root-run
/// doctor gives the same answer. The pin is checked only by doctor: arm replaces it.
/// ponytail: ACLs are not read; the osquery hash rows stay the detector for a swap (F-BYP-08).
fn refuse_on_gaps(managed: &Path, policy: &PolicyBytes, check_pin: bool) {
    let mut gaps = Vec::new();
    let fix = |p: &Path| format!("as root: chown root '{0}' && chmod go-w '{0}'", p.display());
    if managed.is_dir() {
        if let Err(e) = root_only(managed, true) {
            gaps.push(format!(
                "managed dir is not root-only ({e}); {}, or remove the directory to stay on the docs pin",
                fix(managed)
            ));
        }
    }
    let pin = managed.join("last-armed.json");
    if check_pin && pin.exists() {
        if let Err(e) = root_only(&pin, false) {
            gaps.push(format!("managed pin is not root-only ({e}); {}", fix(&pin)));
        }
    }
    let exe = std::env::current_exe().ok().map(|e| std::fs::canonicalize(&e).unwrap_or(e));
    let hooks = policy.hooks.as_ref().map(|(p, _)| p.clone());
    for (label, path) in [("binary", exe), ("hooks file", hooks)] {
        let Some(path) = path else { continue };
        let parent = path.parent().unwrap_or(Path::new("/"));
        if let Err(e) = root_only(&path, false).and_then(|()| root_only(parent, true)) {
            gaps.push(format!(
                "{label} {} is user-writable ({e}); a user-owned path lets the agent point away from the checker; {} and its parent",
                path.display(),
                fix(&path)
            ));
        }
    }
    if !gaps.is_empty() {
        refuse(&format!("managed seat is not root-only:\n- {}", gaps.join("\n- ")));
    }
}

fn arm(reviewed_pack: bool) {
    let docs = match docs_root() {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    let fixture = load_fixture(&docs);
    let policy = match load_policy_bytes(&docs, &fixture.schema_rel, &fixture.policies_rel) {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    let hashes = match hashes_of(&policy) {
        Ok(h) => h,
        Err(e) => refuse(&e),
    };
    if let Some((_, bytes)) = &policy.hooks {
        let v: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => refuse(&format!("parse hooks.json: {e}")),
        };
        if let Err(e) = check_hooks_fail_closed(&v) {
            refuse(&e);
        }
    }
    if let Some((_, bytes)) = &policy.claude_settings {
        let v: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(v) => v,
            Err(e) => refuse(&format!("parse settings.json: {e}")),
        };
        if let Err(e) = check_claude_settings(&v) {
            refuse(&e);
        }
    }
    if !prove_pack(&policy, &fixture.json) {
        refuse("fixtures failed");
    }
    let managed = managed_dir();
    // An existing managed dir is the opt-in: from then on the pin lives there, never in the docs root.
    let org = managed_optin(&managed);
    if org {
        refuse_on_gaps(&managed, &policy, false);
    }
    check_host_sandbox(org);
    let pin_root = if org { managed.clone() } else { docs.clone() };
    // Generation moves only when the pack or binary changes, so a re-arm never skips a signed N+1.
    let generation = match read_last_armed(&pin_root) {
        Ok(None) => 0,
        Ok(Some(last)) => {
            if last.policy_pack_sha256 != hashes.policy_pack_sha256 && !reviewed_pack {
                eprintln!(
                    "pack hash drifted\nold: {}\nnew: {}",
                    last.policy_pack_sha256, hashes.policy_pack_sha256
                );
                refuse("pack hash drifted; fairlead arm --i-reviewed-pack");
            }
            let same = last.policy_pack_sha256 == hashes.policy_pack_sha256
                && last.binary_sha256 == hashes.binary_sha256;
            if same { last.generation } else { last.generation + 1 }
        }
        Err(e) => refuse(&e),
    };
    if let Err(e) = load_or_create_signing_key(&docs) {
        refuse(&e);
    }
    if org {
        // Stamp before pin: a crash between them leaves "stamp, no pin", which denies.
        match write_armed_stamp(&managed) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Never fall back to a docs pin: a seat-user-writable pin is the hole this closes.
                let body = last_armed_bytes(&hashes, generation).unwrap_or_else(|e| refuse(&e));
                println!("managed dir {} is not writable by this user; as root install:", managed.display());
                println!("1. armed.stamp (content: armed)");
                println!("2. last-armed.json (root-owned, mode 0644), after the stamp:");
                println!("{}", String::from_utf8_lossy(&body));
                return;
            }
            Err(e) => refuse(&format!("armed.stamp: {e}")),
        }
    }
    if let Err(e) = write_last_armed_gen(&pin_root, &hashes, generation) {
        refuse(&e);
    }
    println!("armed");
    println!("binary_sha256: {}", hashes.binary_sha256);
    println!("policy_pack_sha256: {}", hashes.policy_pack_sha256);
    println!("hooks_sha256: {}", hashes.hooks_sha256);
}

fn verify_receipt(path: &str) {
    let docs = match docs_root() {
        Ok(p) => p,
        Err(e) => refuse(&e),
    };
    let key = match load_signing_key(&docs) {
        Ok(k) => k,
        Err(e) => refuse(&e),
    };
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => refuse(&format!("read {path}: {e}")),
    };
    // receipts.jsonl is one object per line; a single-object file is the one-line case.
    // Live probe 2026-10-10: the whole-file parse failed with "trailing characters" at 2+ receipts.
    let mut n = 0usize;
    for (i, line) in raw.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        if let Err(e) = verify_receipt_json(line, &key.verifying_key()) {
            refuse(&format!("receipt line {}: {e}", i + 1));
        }
        n += 1;
    }
    if n == 0 {
        refuse(&format!("{path}: no receipts"));
    }
    println!("ok");
}

fn prove_pack(policy: &PolicyBytes, fixture: &serde_json::Value) -> bool {
    let schema_src = match utf8_src(&policy.schema, "schema") {
        Ok(s) => s,
        Err(e) => refuse(&e),
    };
    let cedar_src = match utf8_src(&policy.cedar, "cedar") {
        Ok(s) => s,
        Err(e) => refuse(&e),
    };
    let engine = match Engine::load(&schema_src, &cedar_src) {
        Ok(e) => e,
        Err(e) => refuse(&e),
    };
    let results = match run_cases(&engine, fixture) {
        Ok(r) => r,
        Err(e) => refuse(&e),
    };
    let mut ok = true;
    for r in &results {
        let label = if r.errored {
            "Deny"
        } else {
            decision_label(r.decision)
        };
        println!("{} {}", r.id, label);
        if r.errored {
            eprintln!("{}: Cedar error (treated as Deny)", r.id);
            ok = false;
        } else if !r.matched() {
            eprintln!(
                "{}: expected {} got {}",
                r.id,
                decision_label(r.expect),
                decision_label(r.decision)
            );
            ok = false;
        }
    }
    ok
}

fn refuse(msg: &str) -> ! {
    eprintln!("refuse to arm: {msg}");
    std::process::exit(1);
}
