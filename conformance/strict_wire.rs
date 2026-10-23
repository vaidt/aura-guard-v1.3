//! Strict BC-02.1 JSON wire consumer, experimental C6 surface only.
//! This parser validates receipt JSON transport; it is not a protocol verdict.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SCHEMA_ID: &str = "BC-02.1-COMMON-RECEIPT";
const TOP: &[&str] = &["schema_id", "schema_version", "fixture", "handoff", "received", "receiver", "adapter", "environment"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireReceipt { pub value: Value, pub raw_octets: Vec<u8> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

fn expected(parent: &str) -> &'static [&'static str] {
    match parent {
        "fixture" => &["fixture_id", "fixture_artifact_identity"],
        "handoff" => &["status", "method"],
        "received" => &["octet_length", "raw_octets", "recomputed_sha256"],
        "receiver" => &["receiver_id", "implementation_id", "language", "implementation_version", "source_commit"],
        "adapter" => &["adapter_id", "adapter_version"],
        "environment" => &["environment_id", "platform", "runtime"],
        _ => &[],
    }
}
fn forbidden(key: &str) -> bool {
    matches!(key.to_ascii_lowercase().as_str(), "conformance_result" | "conformance" |
        "acceptance_state" | "expected_acceptance" | "digest_output_state" |
        "expected_digest_output" | "result" | "verdict" | "outcome" | "pass" | "fail")
}
fn scan_authority(v: &Value) -> Result<(), WireError> {
    match v {
        Value::Object(m) => for (k, child) in m { if forbidden(k) { return Err(WireError("forbidden-authority-key")); } scan_authority(child)?; },
        Value::Array(a) => for child in a { scan_authority(child)?; },
        _ => {}
    }
    Ok(())
}
fn exact_keys(m: &Map<String, Value>, fields: &[&str]) -> bool {
    let actual: BTreeSet<&str> = m.keys().map(String::as_str).collect();
    let wanted: BTreeSet<&str> = fields.iter().copied().collect();
    actual == wanted
}
fn nonempty_string<'a>(m: &'a Map<String, Value>, key: &str) -> Result<&'a str, WireError> {
    match m.get(key).and_then(Value::as_str) { Some(s) if !s.is_empty() => Ok(s), _ => Err(WireError("required-nonempty-string")) }
}
fn no_nulls(v: &Value) -> bool {
    match v { Value::Null => false, Value::Object(m) => m.values().all(no_nulls), Value::Array(a) => a.iter().all(no_nulls), _ => true }
}

// Serde's Value parser uses last-key-wins; this scanner rejects duplicate
// decoded property names before interpreting the JSON as a map.
fn reject_duplicate_keys(input: &str) -> Result<(), WireError> {
    struct S<'a> { b: &'a [u8], i: usize }
    impl<'a> S<'a> {
        fn ws(&mut self) { while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() { self.i += 1; } }
        fn string(&mut self) -> Result<String, WireError> {
            let start = self.i;
            if self.b.get(self.i) != Some(&b'"') { return Err(WireError("malformed-json")); }
            self.i += 1;
            while self.i < self.b.len() {
                match self.b[self.i] {
                    b'\\' => { self.i += 2; if self.i > self.b.len() { return Err(WireError("malformed-json")); } },
                    b'"' => { self.i += 1; let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| WireError("invalid-utf8"))?; return serde_json::from_str(s).map_err(|_| WireError("malformed-json")); },
                    0..=31 => return Err(WireError("malformed-json")),
                    _ => self.i += 1,
                }
            }
            Err(WireError("malformed-json"))
        }
        fn value(&mut self) -> Result<(), WireError> {
            self.ws();
            match self.b.get(self.i) {
                Some(b'{') => self.object(), Some(b'[') => self.array(),
                Some(b'"') => { self.string()?; Ok(()) },
                Some(_) => { let start = self.i; while self.i < self.b.len() && !b",]} \r\n\t".contains(&self.b[self.i]) { self.i += 1; }
                    if start == self.i { Err(WireError("malformed-json")) } else { Ok(()) } },
                None => Err(WireError("malformed-json")),
            }
        }
        fn object(&mut self) -> Result<(), WireError> {
            self.i += 1; self.ws(); let mut keys = BTreeSet::new();
            if self.b.get(self.i) == Some(&b'}') { self.i += 1; return Ok(()); }
            loop {
                self.ws(); let k = self.string()?; if !keys.insert(k) { return Err(WireError("duplicate-key")); }
                self.ws(); if self.b.get(self.i) != Some(&b':') { return Err(WireError("malformed-json")); }
                self.i += 1; self.value()?; self.ws();
                match self.b.get(self.i) { Some(b',') => self.i += 1, Some(b'}') => { self.i += 1; return Ok(()); }, _ => return Err(WireError("malformed-json")) }
            }
        }
        fn array(&mut self) -> Result<(), WireError> {
            self.i += 1; self.ws(); if self.b.get(self.i) == Some(&b']') { self.i += 1; return Ok(()); }
            loop { self.value()?; self.ws(); match self.b.get(self.i) { Some(b',') => self.i += 1, Some(b']') => { self.i += 1; return Ok(()); }, _ => return Err(WireError("malformed-json")) } }
        }
    }
    let mut s = S { b: input.as_bytes(), i: 0 }; s.value()?; s.ws();
    if s.i != s.b.len() { return Err(WireError("malformed-json")); } Ok(())
}

pub fn parse_receipt_json(input: &[u8]) -> Result<WireReceipt, WireError> {
    let text = std::str::from_utf8(input).map_err(|_| WireError("invalid-utf8"))?;
    reject_duplicate_keys(text)?;
    let value: Value = serde_json::from_str(text).map_err(|_| WireError("malformed-json"))?;
    scan_authority(&value)?;
    if !no_nulls(&value) { return Err(WireError("null-prohibited")); }
    let root = value.as_object().ok_or(WireError("top-level-object-required"))?;
    if !exact_keys(root, TOP) { return Err(WireError("top-level-field-set")); }
    if nonempty_string(root, "schema_id")? != SCHEMA_ID || root.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(WireError("schema-identity-or-version"));
    }
    for parent in ["fixture", "handoff", "received", "receiver", "adapter", "environment"] {
        let child = root.get(parent).and_then(Value::as_object).ok_or(WireError("nested-object-required"))?;
        if !exact_keys(child, expected(parent)) { return Err(WireError("nested-field-set")); }
        for field in expected(parent) {
            if parent == "received" && *field == "octet_length" { continue; }
            nonempty_string(child, field)?;
        }
    }
    if !matches!(nonempty_string(root["handoff"].as_object().ok_or(WireError("handoff-object"))?, "status")?, "TRANSFERRED" | "NOT_TRANSFERRED" | "ERROR") {
        return Err(WireError("handoff-status-domain"));
    }
    let received = root["received"].as_object().ok_or(WireError("received-object"))?;
    let length = received["octet_length"].as_u64().ok_or(WireError("octet-length-nonnegative-integer"))?;
    let encoded = nonempty_string(received, "raw_octets")?;
    let raw = B64.decode(encoded).map_err(|_| WireError("invalid-base64"))?;
    if B64.encode(&raw) != encoded { return Err(WireError("noncanonical-base64")); }
    if length != raw.len() as u64 { return Err(WireError("octet-length-mismatch")); }
    let digest = nonempty_string(received, "recomputed_sha256")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(WireError("digest-format"));
    }
    let actual = Sha256::digest(&raw).iter().map(|b| format!("{b:02x}")).collect::<String>();
    if actual != digest { return Err(WireError("digest-mismatch")); }
    Ok(WireReceipt { value, raw_octets: raw })
}
