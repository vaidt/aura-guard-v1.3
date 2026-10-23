//! Strict BC-02.1 JSON wire consumer, experimental C6 surface only.
//! This parser validates receipt JSON transport; it is not a protocol verdict.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SCHEMA_ID: &str = "BC-02.1-COMMON-RECEIPT";
const TOP: &[&str] = &[
    "schema_id",
    "schema_version",
    "fixture",
    "handoff",
    "received",
    "receiver",
    "adapter",
    "environment",
];

/// A strictly parsed BC-02.1 receipt envelope and its decoded opaque artifact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireReceipt {
    /// Parsed receipt JSON value, after strict envelope validation.
    pub value: Value,
    /// Decoded raw artifact octets. These bytes are not interpreted as UTF-8.
    pub raw_octets: Vec<u8>,
}

/// A transport-level BC-02.1 receipt rejection reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError(pub &'static str);

fn expected(parent: &str) -> &'static [&'static str] {
    match parent {
        "fixture" => &["fixture_id", "fixture_artifact_identity"],
        "handoff" => &["status", "method"],
        "received" => &["octet_length", "raw_octets", "recomputed_sha256"],
        "receiver" => &[
            "receiver_id",
            "implementation_id",
            "language",
            "implementation_version",
            "source_commit",
        ],
        "adapter" => &["adapter_id", "adapter_version"],
        "environment" => &["environment_id", "platform", "runtime"],
        _ => &[],
    }
}

fn forbidden(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "conformance_result"
            | "conformance"
            | "acceptance_state"
            | "expected_acceptance"
            | "digest_output_state"
            | "expected_digest_output"
            | "result"
            | "verdict"
            | "outcome"
            | "pass"
            | "fail"
    )
}

fn scan_authority(value: &Value) -> Result<(), WireError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if forbidden(key) {
                    return Err(WireError("forbidden-authority-key"));
                }
                scan_authority(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                scan_authority(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn exact_keys(map: &Map<String, Value>, fields: &[&str]) -> bool {
    let actual: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = fields.iter().copied().collect();
    actual == expected
}

fn nonempty_string<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, WireError> {
    match map.get(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(WireError("required-nonempty-string")),
    }
}

fn no_nulls(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Object(map) => map.values().all(no_nulls),
        Value::Array(values) => values.iter().all(no_nulls),
        _ => true,
    }
}

// Serde's Value parser uses last-key-wins; this scanner rejects duplicate
// decoded property names before interpreting the JSON as a map.
fn reject_duplicate_keys(input: &str) -> Result<(), WireError> {
    struct Scanner<'a> {
        bytes: &'a [u8],
        index: usize,
    }

    impl Scanner<'_> {
        fn skip_whitespace(&mut self) {
            while self.index < self.bytes.len()
                && self.bytes[self.index].is_ascii_whitespace()
            {
                self.index += 1;
            }
        }

        fn parse_string(&mut self) -> Result<String, WireError> {
            let start = self.index;
            if self.bytes.get(self.index) != Some(&b'"') {
                return Err(WireError("malformed-json"));
            }
            self.index += 1;

            while self.index < self.bytes.len() {
                match self.bytes[self.index] {
                    b'\\' => {
                        self.index += 2;
                        if self.index > self.bytes.len() {
                            return Err(WireError("malformed-json"));
                        }
                    }
                    b'"' => {
                        self.index += 1;
                        let raw = std::str::from_utf8(&self.bytes[start..self.index])
                            .map_err(|_| WireError("invalid-utf8"))?;
                        return serde_json::from_str(raw)
                            .map_err(|_| WireError("malformed-json"));
                    }
                    0..=31 => return Err(WireError("malformed-json")),
                    _ => self.index += 1,
                }
            }
            Err(WireError("malformed-json"))
        }

        fn parse_value(&mut self) -> Result<(), WireError> {
            self.skip_whitespace();
            match self.bytes.get(self.index) {
                Some(b'{') => self.parse_object(),
                Some(b'[') => self.parse_array(),
                Some(b'"') => {
                    self.parse_string()?;
                    Ok(())
                }
                Some(_) => {
                    let start = self.index;
                    while self.index < self.bytes.len()
                        && !b",]} \r\n\t".contains(&self.bytes[self.index])
                    {
                        self.index += 1;
                    }
                    if start == self.index {
                        Err(WireError("malformed-json"))
                    } else {
                        Ok(())
                    }
                }
                None => Err(WireError("malformed-json")),
            }
        }

        fn parse_object(&mut self) -> Result<(), WireError> {
            self.index += 1;
            self.skip_whitespace();
            let mut keys = BTreeSet::new();

            if self.bytes.get(self.index) == Some(&b'}') {
                self.index += 1;
                return Ok(());
            }

            loop {
                self.skip_whitespace();
                let key = self.parse_string()?;
                if !keys.insert(key) {
                    return Err(WireError("duplicate-key"));
                }
                self.skip_whitespace();
                if self.bytes.get(self.index) != Some(&b':') {
                    return Err(WireError("malformed-json"));
                }
                self.index += 1;
                self.parse_value()?;
                self.skip_whitespace();

                match self.bytes.get(self.index) {
                    Some(b',') => self.index += 1,
                    Some(b'}') => {
                        self.index += 1;
                        return Ok(());
                    }
                    _ => return Err(WireError("malformed-json")),
                }
            }
        }

        fn parse_array(&mut self) -> Result<(), WireError> {
            self.index += 1;
            self.skip_whitespace();

            if self.bytes.get(self.index) == Some(&b']') {
                self.index += 1;
                return Ok(());
            }

            loop {
                self.parse_value()?;
                self.skip_whitespace();

                match self.bytes.get(self.index) {
                    Some(b',') => self.index += 1,
                    Some(b']') => {
                        self.index += 1;
                        return Ok(());
                    }
                    _ => return Err(WireError("malformed-json")),
                }
            }
        }
    }

    let mut scanner = Scanner {
        bytes: input.as_bytes(),
        index: 0,
    };
    scanner.parse_value()?;
    scanner.skip_whitespace();

    if scanner.index != scanner.bytes.len() {
        return Err(WireError("malformed-json"));
    }
    Ok(())
}

/// Strictly parses and validates the BC-02.1 JSON receipt transport envelope.
///
/// Rejects duplicate and unknown fields, nulls, authority-bearing keys,
/// malformed JSON/UTF-8, invalid Base64, length mismatches and digest mismatches.
/// Returns decoded raw octets without interpreting those bytes as text.
pub fn parse_receipt_json(input: &[u8]) -> Result<WireReceipt, WireError> {
    let text = std::str::from_utf8(input).map_err(|_| WireError("invalid-utf8"))?;
    reject_duplicate_keys(text)?;

    let value: Value =
        serde_json::from_str(text).map_err(|_| WireError("malformed-json"))?;
    scan_authority(&value)?;

    if !no_nulls(&value) {
        return Err(WireError("null-prohibited"));
    }

    let root = value
        .as_object()
        .ok_or(WireError("top-level-object-required"))?;

    if !exact_keys(root, TOP) {
        return Err(WireError("top-level-field-set"));
    }

    if nonempty_string(root, "schema_id")? != SCHEMA_ID
        || root.get("schema_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(WireError("schema-identity-or-version"));
    }

    for parent in [
        "fixture",
        "handoff",
        "received",
        "receiver",
        "adapter",
        "environment",
    ] {
        let child = root
            .get(parent)
            .and_then(Value::as_object)
            .ok_or(WireError("nested-object-required"))?;
        if !exact_keys(child, expected(parent)) {
            return Err(WireError("nested-field-set"));
        }
        for field in expected(parent) {
            if parent == "received" && *field == "octet_length" {
                continue;
            }
            nonempty_string(child, field)?;
        }
    }

    let handoff = root["handoff"]
        .as_object()
        .ok_or(WireError("handoff-object"))?;
    if !matches!(
        nonempty_string(handoff, "status")?,
        "TRANSFERRED" | "NOT_TRANSFERRED" | "ERROR"
    ) {
        return Err(WireError("handoff-status-domain"));
    }

    let received = root["received"]
        .as_object()
        .ok_or(WireError("received-object"))?;
    let length = received["octet_length"]
        .as_u64()
        .ok_or(WireError("octet-length-nonnegative-integer"))?;
    let encoded = nonempty_string(received, "raw_octets")?;
    let raw = B64
        .decode(encoded)
        .map_err(|_| WireError("invalid-base64"))?;

    if B64.encode(&raw) != encoded {
        return Err(WireError("noncanonical-base64"));
    }
    if length != raw.len() as u64 {
        return Err(WireError("octet-length-mismatch"));
    }

    let digest = nonempty_string(received, "recomputed_sha256")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WireError("digest-format"));
    }

    let actual = Sha256::digest(&raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != digest {
        return Err(WireError("digest-mismatch"));
    }

    Ok(WireReceipt {
        value,
        raw_octets: raw,
    })
}
