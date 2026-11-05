// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

use crate::tcb::{is_sha256_hex, to_hex};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPrincipal {
    pub user: String,
    pub agent: String,
    pub session: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPayload {
    pub v: u32,
    pub ts: String,
    pub decision: String,
    pub principal: ReceiptPrincipal,
    pub action: String,
    /// Always serialized, including "". Missing on old lines deserializes as "".
    #[serde(default)]
    pub tool_name: String,
    pub args_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_preview: Option<String>,
    pub provenance: Vec<String>,
    pub policy_ids: Vec<String>,
    pub granted_caps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_caps: Vec<String>,
    pub key_id: String,
    pub binary_sha256: String,
    pub policy_pack_sha256: String,
    pub hooks_sha256: String,
}

pub fn key_id(verifying: &VerifyingKey) -> String {
    to_hex(verifying.as_bytes())
}

pub fn sign_receipt(payload: &ReceiptPayload, signing_key: &SigningKey) -> Result<String, String> {
    require_tcb_hex(payload)?;
    let jcs = serde_json_canonicalizer::to_vec(payload)
        .map_err(|e| format!("canonical json: {e}"))?;
    let sig = signing_key.sign(&jcs);
    let mut envelope = serde_json::to_value(payload).map_err(|e| format!("receipt json: {e}"))?;
    envelope
        .as_object_mut()
        .ok_or_else(|| "receipt not an object".to_string())?
        .insert(
            "sig".to_string(),
            serde_json::Value::String(to_hex(&sig.to_bytes())),
        );
    serde_json::to_string_pretty(&envelope).map_err(|e| format!("receipt json: {e}"))
}

pub fn verify_receipt_json(raw: &str, verifying_key: &VerifyingKey) -> Result<ReceiptPayload, String> {
    let mut v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("parse receipt: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "receipt not an object".to_string())?;
    for key in ["binary_sha256", "policy_pack_sha256", "hooks_sha256"] {
        match obj.get(key) {
            Some(serde_json::Value::String(s)) if is_sha256_hex(s) => {}
            Some(_) => return Err(format!("{key} is not 64-char lowercase hex")),
            None => return Err(format!("missing {key}")),
        }
    }
    let sig_hex = match obj.remove("sig") {
        Some(serde_json::Value::String(s)) => s,
        _ => return Err("missing sig".to_string()),
    };
    // JCS of the stored object, not a re-serialize of ReceiptPayload. Old lines have no
    // tool_name key. A struct round-trip would insert "" and fail those signatures.
    let jcs = serde_json_canonicalizer::to_vec(&v).map_err(|e| format!("canonical json: {e}"))?;
    let sig_bytes = from_hex(&sig_hex)?;
    if sig_bytes.len() != 64 {
        return Err("sig is not 64 bytes".to_string());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    verifying_key
        .verify_strict(&jcs, &sig)
        .map_err(|e| format!("signature: {e}"))?;
    let payload: ReceiptPayload =
        serde_json::from_value(v).map_err(|e| format!("receipt payload: {e}"))?;
    require_tcb_hex(&payload)?;
    Ok(payload)
}

fn require_tcb_hex(payload: &ReceiptPayload) -> Result<(), String> {
    for (name, val) in [
        ("binary_sha256", payload.binary_sha256.as_str()),
        ("policy_pack_sha256", payload.policy_pack_sha256.as_str()),
        ("hooks_sha256", payload.hooks_sha256.as_str()),
    ] {
        if !is_sha256_hex(val) {
            return Err(format!("{name} is not 64-char lowercase hex"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DecisionTally {
    pub allow: u64,
    pub deny: u64,
    pub ask: u64,
    pub malformed: u64,
    /// Allow on Shell/FileWrite/McpCall whose policy_ids include F-DEF-06 or F-AUTO-*.
    pub auto_allow_num: u64,
    /// Parsed receipt lines (malformed excluded). Zero means coverage gap, not 0%.
    pub auto_allow_den: u64,
}

/// Count `decision` on each receipts JSONL line. Missing file → zeros.
pub fn tally_decisions(path: &Path) -> DecisionTally {
    let Ok(text) = fs::read_to_string(path) else {
        return DecisionTally::default();
    };
    let mut t = DecisionTally::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            t.malformed += 1;
            continue;
        };
        match v.get("decision").and_then(|x| x.as_str()) {
            Some("allow") => {
                t.allow += 1;
                t.auto_allow_den += 1;
                if auto_allow_hit(&v) {
                    t.auto_allow_num += 1;
                }
            }
            Some("deny") => {
                t.deny += 1;
                t.auto_allow_den += 1;
            }
            Some("ask") => {
                t.ask += 1;
                t.auto_allow_den += 1;
            }
            _ => t.malformed += 1,
        }
    }
    t
}

/// Count `would_deny: true` in observe JSONL. Missing file → None.
pub fn tally_would_deny(path: &Path) -> Option<(u64, u64)> {
    let text = fs::read_to_string(path).ok()?;
    let mut n = 0u64;
    let mut malformed = 0u64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            malformed += 1;
            continue;
        };
        match v.get("would_deny") {
            Some(Value::Bool(true)) => n += 1,
            Some(Value::Bool(false)) => {}
            _ => malformed += 1,
        }
    }
    Some((n, malformed))
}

pub fn format_stats(tally: &DecisionTally, receipts: &Path, would_deny: Option<u64>) -> String {
    let mut s = format!(
        "allow={} deny={} ask={}\npath: {}\nask=0 because granted_caps is always []; no cap-escalation Ask in 1D\n",
        tally.allow,
        tally.deny,
        tally.ask,
        receipts.display()
    );
    if let Some(n) = would_deny {
        s.push_str(&format!("would_deny={n}\n"));
    }
    s.push_str(&auto_allow_line(tally.auto_allow_num, tally.auto_allow_den));
    s
}

fn auto_allow_hit(v: &Value) -> bool {
    let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
    if !matches!(action, "Shell" | "FileWrite" | "McpCall") {
        return false;
    }
    let Some(ids) = v.get("policy_ids").and_then(|x| x.as_array()) else {
        return false;
    };
    ids.iter().any(|id| {
        let Some(s) = id.as_str() else {
            return false;
        };
        s == "F-DEF-06" || s.starts_with("F-AUTO-")
    })
}

fn auto_allow_line(num: u64, den: u64) -> String {
    if den == 0 {
        "auto_allow=coverage gap\n".to_string()
    } else {
        format!("auto_allow={num}/{den}\n")
    }
}

pub(crate) fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("sig is not lowercase hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "sig hex".to_string()))
        .collect()
}
