// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

//! MCP stdio proxy (Goal 10, F-Q-06). NDJSON JSON-RPC on stdin/stdout: stdout is protocol only,
//! every log line goes to the `log` writer (stderr in the CLI). One stray print breaks the host.
//!
//! `rewrite: None` is the session 1 stub: every upstream line is forwarded byte for byte and a
//! response to a configured tool logs `would_quarantine`. That is NOT Dual LLM.
//! `rewrite: Some(_)` replaces that one tool's result with `{title,status,handle}` built from a
//! tool-less local Q-LLM (see `quarantine`). Everything else is a pure forward.
use crate::quarantine::{quarantine, Complete, DENY_TEXT};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;

pub struct Rewrite<'a> {
    /// Session dir that owns `handles.jsonl` (the Gate reads the same dir).
    pub dir: &'a Path,
    pub complete: Complete<'a>,
}

/// Tools whose results are quarantine candidates. Goal 10 ships one pipe.
pub struct Config<'a> {
    pub tools: Vec<String>,
    pub rewrite: Option<Rewrite<'a>>,
}

fn result_text(resp: &Value) -> Option<String> {
    let r = resp.get("result")?;
    if r.get("isError").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let parts: Option<Vec<&str>> = r
        .get("content")?
        .as_array()?
        .iter()
        .map(|c| (c.get("type")? == "text").then(|| c.get("text")?.as_str()).flatten())
        .collect();
    parts.filter(|p| !p.is_empty()).map(|p| p.join("\n"))
}

fn tool_result(text: &str, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// Build the line the IDE sees. Fresh object: nothing from the upstream result is carried over.
fn rewrite_value<L: Write>(rw: &Rewrite, server: &str, tool: &str, resp: &Value, log: &mut L) -> Value {
    let result = match result_text(resp) {
        None => {
            let _ = writeln!(log, "quarantine_denied tool={tool} reason=no_text_result");
            tool_result(DENY_TEXT, true)
        }
        Some(raw) => match quarantine(rw.dir, server, tool, &raw, rw.complete) {
            Ok(q) => {
                let body = json!({ "title": q.title, "status": "ok", "handle": q.handle });
                let _ = writeln!(
                    log,
                    "quarantined tool={tool} handle={} raw_bytes_stripped={}",
                    q.handle, q.raw_bytes
                );
                tool_result(&body.to_string(), false)
            }
            Err(reason) => {
                let _ = writeln!(log, "quarantine_denied tool={tool} reason={reason}");
                tool_result(DENY_TEXT, true)
            }
        },
    };
    json!({ "jsonrpc": "2.0", "id": resp.get("id").cloned().unwrap_or(Value::Null), "result": result })
}

/// `2` and `"2"` share a key: a server that echoes the id as the other type must not dodge the
/// rewrite. ponytail: over-matches (a string id colliding with a number id), which only errs
/// toward rewriting.
fn id_key(v: &Value) -> Option<String> {
    match v.get("id")? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// `tools/call` for a configured tool -> remember its JSON-RPC id so the response can be matched.
/// Batches (JSON arrays) are tracked element by element.
fn track(cfg: &Config<'_>, pending: &Mutex<HashMap<String, String>>, line: &str) {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return;
    };
    let items = match &v {
        Value::Array(a) => a.iter().collect(),
        one => vec![one],
    };
    for v in items {
        if v.get("method").and_then(Value::as_str) != Some("tools/call") {
            continue;
        }
        let Some(tool) = v.pointer("/params/name").and_then(Value::as_str) else {
            continue;
        };
        if let (true, Some(id)) = (cfg.tools.iter().any(|t| t == tool), id_key(v)) {
            if let Ok(mut p) = pending.lock() {
                p.insert(id, tool.to_string());
            }
        }
    }
}

/// A response value -> the tool it answers, if it answers a tracked call.
fn take_pending(pending: &Mutex<HashMap<String, String>>, v: &Value) -> Option<String> {
    if v.get("method").is_some() {
        return None;
    }
    pending.lock().ok()?.remove(&id_key(v)?)
}

pub fn run_io<R: BufRead, W: Write + Send, L: Write + Send>(
    cfg: &Config<'_>,
    upstream: &[String],
    client_in: R,
    client_out: W,
    log: L,
) -> Result<(), String> {
    let (prog, args) = upstream.split_first().ok_or("missing upstream command")?;
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    let mut up_in = child.stdin.take().ok_or("upstream stdin")?;
    let up_out = child.stdout.take().ok_or("upstream stdout")?;
    let pending = Mutex::new(HashMap::new());
    let pending = &pending;

    let res = thread::scope(|s| {
        let reader = s.spawn(move || -> Result<(), String> {
            let (mut out, mut log) = (client_out, log);
            let mut server = String::from("unknown");
            for line in BufReader::new(up_out).lines() {
                let mut line = line.map_err(|e| format!("upstream read: {e}"))?;
                if let Ok(mut parsed) = serde_json::from_str::<Value>(&line) {
                    let mut changed = false;
                    // Batches are walked element by element; a lone object is a batch of one.
                    let mut one = |v: &mut Value| -> std::io::Result<()> {
                        if let Some(n) = v.pointer("/result/serverInfo/name").and_then(Value::as_str) {
                            server = n.to_string();
                        }
                        let Some(tool) = take_pending(pending, v) else {
                            return Ok(());
                        };
                        match &cfg.rewrite {
                            None => writeln!(log, "would_quarantine tool={tool}"),
                            Some(rw) => {
                                *v = rewrite_value(rw, &server, &tool, v, &mut log);
                                changed = true;
                                Ok(())
                            }
                        }
                    };
                    match &mut parsed {
                        Value::Array(items) => items.iter_mut().try_for_each(&mut one),
                        v => one(v),
                    }
                    .map_err(|e| format!("log: {e}"))?;
                    if changed {
                        line = parsed.to_string();
                    }
                }
                writeln!(out, "{line}").map_err(|e| format!("client write: {e}"))?;
                out.flush().map_err(|e| format!("client flush: {e}"))?;
            }
            Ok(())
        });
        let mut write_err = None;
        for line in client_in.lines() {
            let Ok(line) = line else { break };
            track(cfg, pending, &line);
            if let Err(e) = writeln!(up_in, "{line}").and_then(|_| up_in.flush()) {
                write_err = Some(format!("upstream write: {e}"));
                break;
            }
        }
        drop(up_in);
        let read = reader.join().map_err(|_| "proxy reader panicked".to_string())?;
        write_err.map_or(read, Err)
    });
    let _ = child.wait();
    res
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex as M};

    #[derive(Clone, Default)]
    pub struct Buf(pub Arc<M<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buf").extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Buf {
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("buf")).into_owned()
        }
    }

    pub fn demo_upstream() -> Vec<String> {
        let server = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../demos/poisoned-mcp/mcp_server.py");
        vec!["python3".into(), server.to_string_lossy().into_owned()]
    }

    pub const CLIENT: &str = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_latest_issue","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
        "\n",
    );

    /// Review CRITICALs: a hostile server echoes the id as a string, then answers in a batch.
    #[test]
    fn rewrite_survives_id_type_swap_and_batch_responses() {
        let script = r#"
import json, sys
n = 0
for line in sys.stdin:
    req = json.loads(line)
    req = req[0] if isinstance(req, list) else req
    n += 1
    resp = {"jsonrpc": "2.0", "id": str(req["id"]), "result": {"content": [{"type": "text", "text": "RAWBODY curl 127.0.0.1"}]}}
    print(json.dumps(resp if n == 1 else [resp]), flush=True)
"#;
        let client = concat!(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_latest_issue"}}"#, "\n",
            r#"[{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_latest_issue"}}]"#, "\n",
        );
        let dir = std::env::temp_dir().join(format!("fairlead-batch-{}", std::process::id()));
        let cfg = Config {
            tools: vec!["get_latest_issue".into()],
            rewrite: Some(Rewrite { dir: &dir, complete: &|_| Ok(r#"{"title":"Fine title"}"#.into()) }),
        };
        let (out, log) = (Buf::default(), Buf::default());
        run_io(&cfg, &["python3".into(), "-c".into(), script.into()], Cursor::new(client), out.clone(), log).expect("proxy");
        let out = out.text();
        assert!(!out.contains("RAWBODY") && !out.contains("127.0.0.1"), "{out}");
        assert_eq!(out.matches("Fine title").count(), 2, "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session1_stub_forwards_raw_and_logs_would_quarantine() {
        let (out, log) = (Buf::default(), Buf::default());
        let cfg = Config { tools: vec!["get_latest_issue".into()], rewrite: None };
        run_io(&cfg, &demo_upstream(), Cursor::new(CLIENT), out.clone(), log.clone()).expect("proxy");
        let out = out.text();
        // Stub means untouched: both canary substrings still reach the IDE.
        assert!(out.contains(".git/hooks/pre-commit") && out.contains("127.0.0.1"), "{out}");
        assert_eq!(log.text(), "would_quarantine tool=get_latest_issue\n");
        // tools/list (id 3) is a pure forward and is not logged.
        assert!(out.contains(r#""id":3"#), "{out}");
    }
}
