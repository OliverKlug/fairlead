// SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
// SPDX-License-Identifier: Apache-2.0

//! Org kill switch (F-BYP-07). One file read before Cedar, no daemon, no network.
//!
//! The org drops an Ed25519-signed `kill.json` plus `org.pub` into the managed directory
//! (MDM does the drop). A valid `deny-all` makes every hooked call Deny and writes
//! `killed.stamp` next to `last-armed.json`. After that the seat stays denied until a signed
//! `clear` that names the stamped id, even if `kill.json` is deleted. No stamp and no valid
//! blob (every OSS seat, every never-killed seat) means Clear. There is deliberately no TTL:
//! expiry into allow is fail-open, expiry into deny bricks a seat the org never killed.
//!
//! ponytail: the trust root is `org.pub` in the managed dir, so its file permissions are the
//! real boundary. A local admin who deletes the stamp and the blob gets fail-open; the fleet
//! pin query is the signal for that, not this code. Windows has no default dir (OSS behaviour).

use crate::receipt::from_hex;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

const KILL_FILE: &str = "kill.json";
const ORG_KEY_FILE: &str = "org.pub";
const STAMP_FILE: &str = "killed.stamp";
const PACK_FILE: &str = "pack.json";
const ARMED_STAMP_FILE: &str = "armed.stamp";
/// Every file this module reads is a small hex key, a short id, or a short JSON body.
const MAX_READ: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kill {
    Clear,
    Killed(String),
}

// Unknown fields are accepted on purpose: the signature already covers them, and rejecting a
// verified deny over a schema nit would fail open for the real org.
#[derive(Deserialize)]
struct Body {
    v: u32,
    decision: String,
    id: String,
    #[serde(default)]
    clears: Option<String>,
}

enum Blob {
    Deny(String),
    Clear(String),
}

/// `FAIRLEAD_MANAGED_DIR` overrides in debug builds only (tests). A release build ignores it:
/// the managed directory is the trust root, and an env var the seat user controls must not be
/// able to point it at an attacker's `org.pub` and a self-signed clear.
pub fn managed_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        if let Ok(p) = std::env::var("FAIRLEAD_MANAGED_DIR") {
            return PathBuf::from(p);
        }
    }
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Fairlead")
    } else {
        PathBuf::from("/etc/fairlead")
    }
}

pub fn stamp_path(root: &Path) -> PathBuf {
    root.join(STAMP_FILE)
}

/// Written by `arm` into the managed dir before the pin. Once it exists, a missing pin is a
/// deny, not "unarmed": deleting the pin must not turn an armed seat back into an OSS one.
pub fn armed_stamp_path(managed: &Path) -> PathBuf {
    managed.join(ARMED_STAMP_FILE)
}

/// Anything but NotFound counts as present (symlink, unreadable): fail toward deny.
fn present(p: &Path) -> bool {
    !matches!(fs::symlink_metadata(p), Err(e) if e.kind() == ErrorKind::NotFound)
}

/// A seat has an org trust root exactly when `org.pub` exists in the managed dir.
pub fn org_present(managed: &Path) -> bool {
    present(&managed.join(ORG_KEY_FILE))
}

pub fn armed_stamp_present(managed: &Path) -> bool {
    present(&armed_stamp_path(managed))
}

pub fn write_armed_stamp(managed: &Path) -> io::Result<()> {
    put_atomic(managed, ARMED_STAMP_FILE, b"armed\n")
}

/// Debug builds accept `FAIRLEAD_MANAGED_UID` (tests cannot chown to root); release is root only.
fn trusted_uid() -> u32 {
    if cfg!(debug_assertions) {
        if let Ok(v) = std::env::var("FAIRLEAD_MANAGED_UID") {
            if let Ok(u) = v.parse() {
                return u;
            }
        }
    }
    0
}

/// Ok when `p` is not a symlink, is a dir (`want_dir`) or a regular file, is owned by the
/// trusted uid, and has no group or other write bit. Mode bits, not access(2): the answer must
/// not depend on who runs the check (root-run doctor included), and `unsafe` is forbidden here.
/// ponytail: ACLs and immutable flags are not read; a stray ACL grant is invisible to this check.
#[cfg(unix)]
pub fn root_only(p: &Path, want_dir: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let kind_ok = if want_dir { m.file_type().is_dir() } else { m.file_type().is_file() };
    if !kind_ok {
        return Err(format!("{}: wrong file type", p.display()));
    }
    if m.uid() != trusted_uid() {
        return Err(format!("{}: owner uid {} is not the trusted owner", p.display(), m.uid()));
    }
    if m.mode() & 0o022 != 0 {
        return Err(format!("{}: group or other writable (mode {:o})", p.display(), m.mode() & 0o7777));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn root_only(_p: &Path, _want_dir: bool) -> Result<(), String> {
    Ok(())
}

fn valid_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Regular files only (no symlink, FIFO or device), capped at `MAX_READ`. A hostile entry on a
/// path the hook reads must not hang it or feed it gigabytes.
fn read_regular(p: &Path) -> io::Result<String> {
    if !fs::symlink_metadata(p)?.file_type().is_file() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "not a regular file"));
    }
    let mut s = String::new();
    File::open(p)?.take(MAX_READ + 1).read_to_string(&mut s)?;
    if s.len() as u64 > MAX_READ {
        return Err(io::Error::new(ErrorKind::InvalidData, "file too large"));
    }
    Ok(s)
}

/// Parse `raw`, verify its `sig` (strict Ed25519 over JCS of the rest) under the managed
/// `org.pub`, and return the verified body without `sig`.
fn verify_signed(managed: &Path, raw: &str) -> Result<Value, String> {
    let key_hex =
        read_regular(&managed.join(ORG_KEY_FILE)).map_err(|e| format!("{ORG_KEY_FILE}: {e}"))?;
    let key_bytes: [u8; 32] = from_hex(&key_hex.trim().to_ascii_lowercase())?
        .try_into()
        .map_err(|_| "org key is not 32 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("org key: {e}"))?;
    let mut v: Value = serde_json::from_str(raw).map_err(|e| format!("parse: {e}"))?;
    let sig_hex = match v.as_object_mut().and_then(|o| o.remove("sig")) {
        Some(Value::String(s)) => s,
        _ => return Err("missing sig".into()),
    };
    let sig_bytes: [u8; 64] = from_hex(&sig_hex.to_ascii_lowercase())?
        .try_into()
        .map_err(|_| "sig is not 64 bytes".to_string())?;
    let jcs = serde_json_canonicalizer::to_vec(&v).map_err(|e| format!("canonical json: {e}"))?;
    key.verify_strict(&jcs, &Signature::from_bytes(&sig_bytes))
        .map_err(|e| format!("signature: {e}"))?;
    Ok(v)
}

/// Live pack check: with no `org.pub` (every OSS seat) this is Ok. With one, `pack.json` must
/// carry `{"v":1,"policy_pack_sha256":<digest>,"sig":...}` signed by that key for exactly this
/// digest. An `org.pub` that is unreadable, or a `pack.json` that is missing or wrong, is Err.
pub fn check_pack_signature(managed: &Path, pack_sha256: &str) -> Result<(), String> {
    if let Err(e) = fs::symlink_metadata(managed.join(ORG_KEY_FILE)) {
        if e.kind() == ErrorKind::NotFound {
            return Ok(());
        }
    }
    let raw = read_regular(&managed.join(PACK_FILE)).map_err(|e| format!("{PACK_FILE}: {e}"))?;
    let v = verify_signed(managed, &raw)?;
    let signed = v.get("policy_pack_sha256").and_then(Value::as_str);
    if v.get("v").and_then(Value::as_u64) != Some(1) || signed != Some(pack_sha256) {
        return Err(format!("{PACK_FILE} does not sign pack {pack_sha256}"));
    }
    Ok(())
}

/// Org-signed successor to the pinned state: `pack.json` signs exactly this pack and binary at
/// generation `pin_generation + 1` (and has not passed `not_after`, unix seconds, if set). The
/// old pin keeps working until `arm` installs the new one; no unsigned previous hash is accepted.
pub fn pack_successor(
    managed: &Path,
    pack_sha256: &str,
    binary_sha256: &str,
    pin_generation: u64,
    now_unix: u64,
) -> bool {
    let Ok(raw) = read_regular(&managed.join(PACK_FILE)) else {
        return false;
    };
    let Ok(v) = verify_signed(managed, &raw) else {
        return false;
    };
    v.get("v").and_then(Value::as_u64) == Some(1)
        && v.get("policy_pack_sha256").and_then(Value::as_str) == Some(pack_sha256)
        && v.get("binary_sha256").and_then(Value::as_str) == Some(binary_sha256)
        && v.get("generation").and_then(Value::as_u64) == pin_generation.checked_add(1)
        && v.get("not_after").map_or(true, |t| t.as_u64().is_some_and(|t| now_unix <= t))
}

fn parse_blob(managed: &Path, raw: &str) -> Result<Blob, String> {
    let v = verify_signed(managed, raw)?;
    let body: Body = serde_json::from_value(v).map_err(|e| format!("body: {e}"))?;
    if body.v < 1 || !valid_id(&body.id) {
        return Err("bad v or id".into());
    }
    match (body.decision.as_str(), body.clears) {
        ("deny-all", None) => Ok(Blob::Deny(body.id)),
        ("clear", Some(c)) if valid_id(&c) => Ok(Blob::Clear(c)),
        _ => Err("bad decision".into()),
    }
}

/// None when absent. Unreadable, unverifiable, or malformed is ignored and printed, not trusted:
/// a half-written MDM push must not brick a seat the org never killed.
fn read_blob(managed: &Path) -> Option<Blob> {
    let raw = match read_regular(&managed.join(KILL_FILE)) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!("kill: read {KILL_FILE}: {e}");
            return None;
        }
    };
    match parse_blob(managed, &raw) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("kill: ignoring {KILL_FILE}: {e}");
            None
        }
    }
}

fn write_stamp(root: &Path, id: &str) -> io::Result<()> {
    put_atomic(root, STAMP_FILE, id.as_bytes())
}

fn put_atomic(root: &Path, name: &str, body: &[u8]) -> io::Result<()> {
    let tmp = root.join(format!("{name}.{}.tmp", std::process::id()));
    // create_new is O_EXCL: it never follows a symlink planted at the temp name.
    let mut f = match OpenOptions::new().write(true).create_new(true).open(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp)?;
            OpenOptions::new().write(true).create_new(true).open(&tmp)?
        }
        Err(e) => return Err(e),
    };
    f.write_all(body)?;
    f.sync_all()?;
    fs::rename(&tmp, root.join(name))
}

/// Read the org blob and the local stamp. Never errors: every failure path either ignores an
/// untrusted blob or stays Killed.
pub fn check_kill(managed: &Path, root: &Path) -> Kill {
    let stamp = stamp_path(root);
    // An unreadable stamp still means "was killed": sticky, and no clear can name "".
    let stamped = match read_regular(&stamp) {
        Ok(s) => Some(s.trim().to_string()),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(_) => Some(String::new()),
    };
    match read_blob(managed) {
        Some(Blob::Deny(id)) => {
            if stamped.as_deref() != Some(id.as_str()) {
                if let Err(e) = write_stamp(root, &id) {
                    eprintln!("kill: stamp write failed ({e}); still denying");
                }
            }
            Kill::Killed(id)
        }
        // An empty stamp id means the stamp exists but cannot be read (symlink, FIFO, too large,
        // bad perms): any signed org clear may lift it, since no clear can name "".
        Some(Blob::Clear(clears))
            if stamped.as_deref() == Some(clears.as_str()) || stamped.as_deref() == Some("") =>
        {
            if let Err(e) = fs::remove_file(&stamp) {
                eprintln!("kill: stamp remove failed ({e}); still denying");
                return Kill::Killed(clears);
            }
            Kill::Clear
        }
        _ => match stamped {
            Some(id) => Kill::Killed(id),
            None => Kill::Clear,
        },
    }
}

/// Test signer. The org key lives outside this repo; production code never signs a blob.
#[cfg(test)]
pub(crate) fn sign_blob(key: &ed25519_dalek::SigningKey, body: Value) -> String {
    use ed25519_dalek::Signer;
    let jcs = serde_json_canonicalizer::to_vec(&body).expect("jcs");
    let mut out = body;
    out["sig"] = Value::String(crate::tcb::to_hex(&key.sign(&jcs).to_bytes()));
    out.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn dirs(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("fairlead-kill-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (m, r) = (base.join("managed"), base.join("root"));
        fs::create_dir_all(&m).expect("managed");
        fs::create_dir_all(&r).expect("root");
        (m, r)
    }

    pub(crate) fn org_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn put(m: &Path, key: &SigningKey, body: Value) {
        fs::write(m.join(KILL_FILE), sign_blob(key, body)).expect("kill.json");
    }

    #[test]
    fn sticky_until_signed_clear() {
        let (m, r) = dirs("state");
        let key = org_key();
        let deny = json!({"v": 1, "decision": "deny-all", "id": "k1"});
        // OSS / never killed: no org.pub, no blob, no stamp.
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        fs::write(
            m.join(ORG_KEY_FILE),
            crate::tcb::to_hex(key.verifying_key().as_bytes()),
        )
        .expect("org.pub");
        assert_eq!(check_kill(&m, &r), Kill::Clear, "org.pub alone kills nothing");
        // Garbage and tampered blobs on a never-killed seat are ignored.
        fs::write(m.join(KILL_FILE), "{not json").expect("garbage");
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        let tampered = sign_blob(&key, deny.clone()).replace("k1", "k2");
        fs::write(m.join(KILL_FILE), tampered).expect("tampered");
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        put(&m, &stranger, deny.clone());
        assert_eq!(check_kill(&m, &r), Kill::Clear, "wrong key is not the org");
        // Valid deny kills and stamps.
        put(&m, &key, deny);
        assert_eq!(check_kill(&m, &r), Kill::Killed("k1".into()));
        assert!(stamp_path(&r).is_file());
        // Falsifier: delete only kill.json, still denied.
        fs::remove_file(m.join(KILL_FILE)).expect("rm kill.json");
        assert_eq!(check_kill(&m, &r), Kill::Killed("k1".into()));
        // A clear for another id, or signed by a stranger, does nothing.
        put(&m, &key, json!({"v": 1, "decision": "clear", "id": "c0", "clears": "other"}));
        assert_eq!(check_kill(&m, &r), Kill::Killed("k1".into()));
        put(&m, &stranger, json!({"v": 1, "decision": "clear", "id": "c1", "clears": "k1"}));
        assert_eq!(check_kill(&m, &r), Kill::Killed("k1".into()));
        // The signed clear that names the stamp is the only remover.
        put(&m, &key, json!({"v": 1, "decision": "clear", "id": "c2", "clears": "k1"}));
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        assert!(!stamp_path(&r).exists());
        assert_eq!(check_kill(&m, &r), Kill::Clear, "a spent clear does not re-kill");
        // Documented residual: local admin deletes stamp and blob, next call is fail-open.
        put(&m, &key, json!({"v": 1, "decision": "deny-all", "id": "k3"}));
        assert_eq!(check_kill(&m, &r), Kill::Killed("k3".into()));
        fs::remove_file(m.join(KILL_FILE)).expect("rm");
        fs::remove_file(stamp_path(&r)).expect("rm stamp");
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        let _ = fs::remove_dir_all(m.parent().expect("base"));
    }

    /// Fixtures for the live Cursor probe (no cargo there): the fixed test org key signs them.
    /// `FAIRLEAD_EMIT_KILL_DIR=/path cargo test -p fairlead-core emit_kill_fixtures -- --ignored`
    #[test]
    #[ignore]
    fn emit_kill_fixtures() {
        let dir = PathBuf::from(std::env::var("FAIRLEAD_EMIT_KILL_DIR").expect("FAIRLEAD_EMIT_KILL_DIR"));
        fs::create_dir_all(&dir).expect("dir");
        let key = org_key();
        let stranger = SigningKey::from_bytes(&[9u8; 32]);
        let w = |name: &str, body: String| fs::write(dir.join(name), body).expect(name);
        w("org.pub", crate::tcb::to_hex(key.verifying_key().as_bytes()));
        w("deny.json", sign_blob(&key, json!({"v": 1, "decision": "deny-all", "id": "live-k1"})));
        w("deny-wrongkey.json", sign_blob(&stranger, json!({"v": 1, "decision": "deny-all", "id": "live-bad"})));
        w("clear-wrongid.json", sign_blob(&key, json!({"v": 1, "decision": "clear", "id": "live-c0", "clears": "other"})));
        w("clear.json", sign_blob(&key, json!({"v": 1, "decision": "clear", "id": "live-c1", "clears": "live-k1"})));
    }

    #[cfg(unix)]
    #[test]
    fn hostile_files_and_schema_nits() {
        use std::os::unix::fs::symlink;
        let (m, r) = dirs("hostile");
        let key = org_key();
        let pub_hex = crate::tcb::to_hex(key.verifying_key().as_bytes());
        // Uppercase hex in org.pub and sig, an extra signed field, and v: 2 still deny.
        fs::write(m.join(ORG_KEY_FILE), pub_hex.to_ascii_uppercase()).expect("org.pub");
        let body = json!({"v": 2, "decision": "deny-all", "id": "k1", "reason": "incident"});
        let blob = sign_blob(&key, body);
        let sig = blob.split("\"sig\":\"").nth(1).expect("sig").split('"').next().expect("hex").to_string();
        fs::write(m.join(KILL_FILE), blob.replace(&sig, &sig.to_ascii_uppercase())).expect("kill");
        assert_eq!(check_kill(&m, &r), Kill::Killed("k1".into()));
        // kill.json removed: the stamp keeps it denied. Replace the stamp with a symlink to
        // /dev/zero: unreadable stamp is sticky Killed("") and must not hang.
        fs::remove_file(m.join(KILL_FILE)).expect("rm");
        fs::remove_file(stamp_path(&r)).expect("rm stamp");
        symlink("/dev/zero", stamp_path(&r)).expect("symlink");
        assert_eq!(check_kill(&m, &r), Kill::Killed(String::new()));
        // Any signed clear lifts an unreadable stamp.
        put(&m, &key, json!({"v": 1, "decision": "clear", "id": "c1", "clears": "whatever"}));
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        assert!(!stamp_path(&r).exists());
        // A symlinked kill.json and an oversized one are ignored, not read.
        fs::remove_file(m.join(KILL_FILE)).expect("rm");
        symlink("/dev/zero", m.join(KILL_FILE)).expect("symlink");
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        fs::remove_file(m.join(KILL_FILE)).expect("rm");
        fs::write(m.join(KILL_FILE), vec![b'x'; (MAX_READ + 1) as usize]).expect("big");
        assert_eq!(check_kill(&m, &r), Kill::Clear);
        let _ = fs::remove_dir_all(m.parent().expect("base"));
    }

    /// Real root-owned paths, no uid override: the kernel, not a test shim, decides these.
    /// Skipped when the test itself runs as root (it can write anywhere).
    #[cfg(unix)]
    #[test]
    fn root_only_on_real_root_owned_paths() {
        use std::os::unix::fs::MetadataExt;
        let probe = std::env::temp_dir().join(format!("fairlead-uid-probe-{}", std::process::id()));
        fs::write(&probe, b"x").expect("probe");
        let me = fs::metadata(&probe).expect("meta").uid();
        assert!(root_only(&probe, false).is_err() || me == 0, "user-owned file is not root-only");
        let _ = fs::remove_file(&probe);
        if me == 0 {
            return;
        }
        assert!(std::env::var("FAIRLEAD_MANAGED_UID").is_err(), "uid override leaked into the process");
        root_only(Path::new("/usr"), true).expect("/usr is root-only");
        root_only(Path::new("/usr/bin/true"), false).expect("/usr/bin/true is root-only");
        // The enforcement the pin relies on: a non-root uid can neither rewrite nor unlink there.
        let w = OpenOptions::new().write(true).open("/usr/bin/true").expect_err("write");
        assert_eq!(w.kind(), ErrorKind::PermissionDenied);
        let d = fs::remove_file("/usr/bin/true").expect_err("unlink");
        assert!(matches!(d.kind(), ErrorKind::PermissionDenied) || d.raw_os_error().is_some(), "{d}");
    }
}
