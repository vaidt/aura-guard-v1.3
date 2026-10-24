//! Strict consumer for the BC-02.1 Common Receipt JSON envelope.
//!
//! The public parser accepts the original receipt-envelope bytes so duplicate
//! object members can be detected before they are collapsed into a map. This
//! is a transport-boundary API; it does not parse raw artifact bytes as text,
//! assign a conformance verdict, or make a governance/release decision.

use base64::{engine::general_purpose::STANDARD as BC021_BASE64, Engine as _};
use serde::de::{self, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Number;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// The BC-02.1 receipt schema identifier.
pub const SCHEMA_ID: &str = "BC-02.1-COMMON-RECEIPT";
/// The supported BC-02.1 receipt schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// A stable, non-authoritative reason that a receipt JSON envelope was rejected.
///
/// `code` is intended for cross-implementation conformance diagnostics.
/// `detail` is diagnostic text only; callers must not treat it as a receipt
/// verdict, protocol conformance result, authorization, or release decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptParseError {
    /// Stable rejection category.
    pub code: &'static str,
    /// Human-readable diagnostic detail.
    pub detail: String,
}

impl ReceiptParseError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ReceiptParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ReceiptParseError {}

/// Closed BC-02.1 handoff status domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffStatus {
    /// Raw octets were transferred.
    Transferred,
    /// Raw octets were not transferred.
    NotTransferred,
    /// The handoff encountered an error.
    Error,
}

impl HandoffStatus {
    fn parse(value: &str) -> Result<Self, ReceiptParseError> {
        match value {
            "TRANSFERRED" => Ok(Self::Transferred),
            "NOT_TRANSFERRED" => Ok(Self::NotTransferred),
            "ERROR" => Ok(Self::Error),
            _ => Err(ReceiptParseError::new(
                "INVALID_VALUE",
                "handoff.status is outside the closed BC-02.1 domain",
            )),
        }
    }
}

/// Identity of the test fixture associated with a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureIdentity {
    /// Stable fixture identifier.
    pub fixture_id: String,
    /// Identity of the fixture artifact.
    pub fixture_artifact_identity: String,
}

/// Handoff state and method preserved by the receiving implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    /// Closed BC-02.1 handoff status.
    pub status: HandoffStatus,
    /// Handoff method identifier.
    pub method: String,
}

/// Raw artifact material as received and independently hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMaterial {
    /// Number of decoded raw artifact octets.
    pub octet_length: usize,
    /// Exact raw artifact octets. May contain arbitrary non-UTF-8 bytes.
    pub raw_octets: Vec<u8>,
    /// Lowercase SHA-256 over `raw_octets`, not the Base64 transport text.
    pub recomputed_sha256: String,
}

/// Identity and source provenance of a receipt receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverIdentity {
    /// Receiver identifier.
    pub receiver_id: String,
    /// Implementation identifier, distinct from `receiver_id`.
    pub implementation_id: String,
    /// Implementation language.
    pub language: String,
    /// Implementation version.
    pub implementation_version: String,
    /// Source commit for the implementation.
    pub source_commit: String,
}

/// Adapter identity and version used at the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterIdentity {
    /// Adapter identifier, distinct from receiver and implementation IDs.
    pub adapter_id: String,
    /// Adapter version.
    pub adapter_version: String,
}

/// Execution environment recorded by a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentIdentity {
    /// Environment identifier.
    pub environment_id: String,
    /// Platform identifier.
    pub platform: String,
    /// Runtime identifier.
    pub runtime: String,
}

/// A strictly parsed BC-02.1 receipt.
///
/// This type deliberately has no conformance-result/verdict field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryReceipt {
    /// BC-02.1 schema identifier.
    pub schema_id: String,
    /// BC-02.1 schema version.
    pub schema_version: u32,
    /// Fixture identity.
    pub fixture: FixtureIdentity,
    /// Handoff state and method.
    pub handoff: Handoff,
    /// Exact received raw octets and receiver-derived digest.
    pub received: ReceivedMaterial,
    /// Receiver identity and provenance.
    pub receiver: ReceiverIdentity,
    /// Adapter identity and version.
    pub adapter: AdapterIdentity,
    /// Runtime environment identity.
    pub environment: EnvironmentIdentity,
}

/// Strictly parse original BC-02.1 receipt JSON bytes.
///
/// This function rejects duplicate object keys at any depth, wrong or missing
/// fields, unknown fields, null required fields, invalid primitive types,
/// invalid schema/status values, malformed or non-canonical Base64, inconsistent
/// octet lengths, digest mismatches, prohibited result-authority values, and
/// aliased receiver/implementation/adapter identities.
///
/// The receipt JSON envelope must be UTF-8. The decoded `received.raw_octets`
/// remain opaque bytes and may contain NUL or arbitrary non-UTF-8 octets.
///
/// Successful parsing only means the receipt matches this bounded transport
/// schema. It is not a conformance verdict or a governance/release decision.
pub fn parse_receipt_json(raw_json: &[u8]) -> Result<BoundaryReceipt, ReceiptParseError> {
    std::str::from_utf8(raw_json).map_err(|_| {
        ReceiptParseError::new("INVALID_UTF8", "receipt envelope is not valid UTF-8")
    })?;

    let document: StrictJsonValue = serde_json::from_slice(raw_json).map_err(|error| {
        let message = error.to_string();
        if message.contains("DUPLICATE_KEY") {
            ReceiptParseError::new("DUPLICATE_KEY", message)
        } else {
            ReceiptParseError::new("INVALID_JSON", "receipt envelope is not valid JSON")
        }
    })?;

    if matches!(&document, StrictJsonValue::Null) {
        return Err(ReceiptParseError::new(
            "NULL_NOT_ALLOWED",
            "receipt must not be null",
        ));
    }

    let mut top = take_object(
        document,
        &[
            "schema_id",
            "schema_version",
            "fixture",
            "handoff",
            "received",
            "receiver",
            "adapter",
            "environment",
        ],
        "receipt",
    )?;

    // Validate every exact field set before inspecting semantic string values.
    // This ordering makes conformance_result: "PASS" an UNKNOWN_FIELD error.
    let mut fixture = take_object(
        take(&mut top, "fixture"),
        &["fixture_id", "fixture_artifact_identity"],
        "fixture",
    )?;
    let mut handoff = take_object(take(&mut top, "handoff"), &["status", "method"], "handoff")?;
    let mut received = take_object(
        take(&mut top, "received"),
        &["octet_length", "raw_octets", "recomputed_sha256"],
        "received",
    )?;
    let mut receiver = take_object(
        take(&mut top, "receiver"),
        &[
            "receiver_id",
            "implementation_id",
            "language",
            "implementation_version",
            "source_commit",
        ],
        "receiver",
    )?;
    let mut adapter = take_object(
        take(&mut top, "adapter"),
        &["adapter_id", "adapter_version"],
        "adapter",
    )?;
    let mut environment = take_object(
        take(&mut top, "environment"),
        &["environment_id", "platform", "runtime"],
        "environment",
    )?;

    let schema_id = required_string(take(&mut top, "schema_id"), "schema_id")?;
    if schema_id != SCHEMA_ID {
        return Err(ReceiptParseError::new(
            "SCHEMA_ID_MISMATCH",
            "unsupported schema_id",
        ));
    }
    let schema_version = required_u32(take(&mut top, "schema_version"), "schema_version")?;
    if schema_version != SCHEMA_VERSION {
        return Err(ReceiptParseError::new(
            "SCHEMA_VERSION_MISMATCH",
            "unsupported schema_version",
        ));
    }

    let fixture_id = required_string(take(&mut fixture, "fixture_id"), "fixture.fixture_id")?;
    let fixture_artifact_identity = required_string(
        take(&mut fixture, "fixture_artifact_identity"),
        "fixture.fixture_artifact_identity",
    )?;

    let status_text = required_string(take(&mut handoff, "status"), "handoff.status")?;
    let status = HandoffStatus::parse(&status_text)?;
    let method = required_string(take(&mut handoff, "method"), "handoff.method")?;

    let octet_length =
        required_usize(take(&mut received, "octet_length"), "received.octet_length")?;
    let encoded_octets =
        required_string_allow_empty(take(&mut received, "raw_octets"), "received.raw_octets")?;
    let raw_octets = BC021_BASE64
        .decode(encoded_octets.as_bytes())
        .map_err(|_| {
            ReceiptParseError::new("INVALID_BASE64", "received.raw_octets is not strict Base64")
        })?;
    if BC021_BASE64.encode(&raw_octets) != encoded_octets {
        return Err(ReceiptParseError::new(
            "INVALID_BASE64",
            "received.raw_octets is not canonical padded Base64",
        ));
    }
    if octet_length != raw_octets.len() {
        return Err(ReceiptParseError::new(
            "LENGTH_MISMATCH",
            "octet_length differs from decoded raw_octets length",
        ));
    }
    let recomputed_sha256 = required_string(
        take(&mut received, "recomputed_sha256"),
        "received.recomputed_sha256",
    )?;
    if !is_lower_hex_sha256(&recomputed_sha256) {
        return Err(ReceiptParseError::new(
            "INVALID_VALUE",
            "recomputed_sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    let actual_digest = hex_lower(&Sha256::digest(&raw_octets));
    if actual_digest != recomputed_sha256 {
        return Err(ReceiptParseError::new(
            "DIGEST_MISMATCH",
            "recomputed_sha256 does not match decoded raw_octets",
        ));
    }

    let receiver_id =
        required_semantic_string(take(&mut receiver, "receiver_id"), "receiver.receiver_id")?;
    let implementation_id = required_semantic_string(
        take(&mut receiver, "implementation_id"),
        "receiver.implementation_id",
    )?;
    let language = required_semantic_string(take(&mut receiver, "language"), "receiver.language")?;
    let implementation_version = required_semantic_string(
        take(&mut receiver, "implementation_version"),
        "receiver.implementation_version",
    )?;
    let source_commit = required_semantic_string(
        take(&mut receiver, "source_commit"),
        "receiver.source_commit",
    )?;

    let adapter_id =
        required_semantic_string(take(&mut adapter, "adapter_id"), "adapter.adapter_id")?;
    let adapter_version = required_semantic_string(
        take(&mut adapter, "adapter_version"),
        "adapter.adapter_version",
    )?;

    let environment_id = required_semantic_string(
        take(&mut environment, "environment_id"),
        "environment.environment_id",
    )?;
    let platform =
        required_semantic_string(take(&mut environment, "platform"), "environment.platform")?;
    let runtime =
        required_semantic_string(take(&mut environment, "runtime"), "environment.runtime")?;

    // BC-02.1 R-INV-04: semantic receipt values must not carry a result verdict.
    // Base64 transport text, hashes and fixed schema identifiers are not semantic
    // result fields and are therefore not scanned as ordinary string values.
    for (field, value) in [
        ("fixture.fixture_id", fixture_id.as_str()),
        (
            "fixture.fixture_artifact_identity",
            fixture_artifact_identity.as_str(),
        ),
        ("handoff.method", method.as_str()),
        ("receiver.receiver_id", receiver_id.as_str()),
        ("receiver.implementation_id", implementation_id.as_str()),
        ("receiver.language", language.as_str()),
        (
            "receiver.implementation_version",
            implementation_version.as_str(),
        ),
        ("receiver.source_commit", source_commit.as_str()),
        ("adapter.adapter_id", adapter_id.as_str()),
        ("adapter.adapter_version", adapter_version.as_str()),
        ("environment.environment_id", environment_id.as_str()),
        ("environment.platform", platform.as_str()),
        ("environment.runtime", runtime.as_str()),
    ] {
        reject_result_value(field, value)?;
    }

    if receiver_id == implementation_id {
        return Err(ReceiptParseError::new(
            "INVALID_VALUE",
            "implementation identity must differ from receiver identity",
        ));
    }
    if adapter_id == receiver_id || adapter_id == implementation_id {
        return Err(ReceiptParseError::new(
            "INVALID_VALUE",
            "adapter identity must differ from receiver and implementation identities",
        ));
    }

    Ok(BoundaryReceipt {
        schema_id,
        schema_version,
        fixture: FixtureIdentity {
            fixture_id,
            fixture_artifact_identity,
        },
        handoff: Handoff { status, method },
        received: ReceivedMaterial {
            octet_length,
            raw_octets,
            recomputed_sha256,
        },
        receiver: ReceiverIdentity {
            receiver_id,
            implementation_id,
            language,
            implementation_version,
            source_commit,
        },
        adapter: AdapterIdentity {
            adapter_id,
            adapter_version,
        },
        environment: EnvironmentIdentity {
            environment_id,
            platform,
            runtime,
        },
    })
}

fn reject_result_value(field: &str, value: &str) -> Result<(), ReceiptParseError> {
    const FORBIDDEN: [&str; 4] = ["PASS", "FAIL", "CONFORMANT", "NON_CONFORMANT"];
    if FORBIDDEN
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        return Err(ReceiptParseError::new(
            "INVALID_VALUE",
            format!("{field} contains a prohibited result-authority value"),
        ));
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn required_string(value: StrictJsonValue, field: &str) -> Result<String, ReceiptParseError> {
    required_string_impl(value, field, false, false)
}

fn required_string_allow_empty(
    value: StrictJsonValue,
    field: &str,
) -> Result<String, ReceiptParseError> {
    required_string_impl(value, field, true, false)
}

fn required_semantic_string(
    value: StrictJsonValue,
    field: &str,
) -> Result<String, ReceiptParseError> {
    required_string_impl(value, field, false, true)
}

fn required_string_impl(
    value: StrictJsonValue,
    field: &str,
    allow_empty: bool,
    semantic: bool,
) -> Result<String, ReceiptParseError> {
    let value = match value {
        StrictJsonValue::Null => {
            return Err(ReceiptParseError::new(
                "NULL_NOT_ALLOWED",
                format!("{field} must not be null"),
            ));
        }
        StrictJsonValue::String(value) => value,
        _ => {
            return Err(ReceiptParseError::new(
                "TYPE_MISMATCH",
                format!("{field} must be a string"),
            ));
        }
    };
    if !allow_empty && value.is_empty() {
        return Err(ReceiptParseError::new(
            "INVALID_VALUE",
            format!("{field} must not be empty"),
        ));
    }
    if semantic {
        reject_result_value(field, &value)?;
    }
    Ok(value)
}

fn required_usize(value: StrictJsonValue, field: &str) -> Result<usize, ReceiptParseError> {
    match value {
        StrictJsonValue::Null => Err(ReceiptParseError::new(
            "NULL_NOT_ALLOWED",
            format!("{field} must not be null"),
        )),
        StrictJsonValue::Number(number) => {
            if number.as_i64().is_some_and(|number| number < 0) {
                return Err(ReceiptParseError::new(
                    "INVALID_VALUE",
                    format!("{field} must be non-negative"),
                ));
            }
            number
                .as_u64()
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(|| {
                    ReceiptParseError::new(
                        "TYPE_MISMATCH",
                        format!("{field} must be a non-negative JSON integer fitting usize"),
                    )
                })
        }
        _ => Err(ReceiptParseError::new(
            "TYPE_MISMATCH",
            format!("{field} must be a non-negative JSON integer"),
        )),
    }
}

fn required_u32(value: StrictJsonValue, field: &str) -> Result<u32, ReceiptParseError> {
    match value {
        StrictJsonValue::Null => Err(ReceiptParseError::new(
            "NULL_NOT_ALLOWED",
            format!("{field} must not be null"),
        )),
        StrictJsonValue::Number(number) => {
            if number.as_i64().is_some_and(|number| number < 0) {
                return Err(ReceiptParseError::new(
                    "INVALID_VALUE",
                    format!("{field} must be non-negative"),
                ));
            }
            number
                .as_u64()
                .and_then(|number| u32::try_from(number).ok())
                .ok_or_else(|| {
                    ReceiptParseError::new(
                        "TYPE_MISMATCH",
                        format!("{field} must be a non-negative JSON integer fitting u32"),
                    )
                })
        }
        _ => Err(ReceiptParseError::new(
            "TYPE_MISMATCH",
            format!("{field} must be a non-negative JSON integer"),
        )),
    }
}

fn take_object(
    value: StrictJsonValue,
    required: &[&str],
    field: &str,
) -> Result<BTreeMap<String, StrictJsonValue>, ReceiptParseError> {
    let mut map = match value {
        StrictJsonValue::Object(map) => map,
        StrictJsonValue::Null => {
            return Err(ReceiptParseError::new(
                "NULL_NOT_ALLOWED",
                format!("{field} must not be null"),
            ));
        }
        _ => {
            return Err(ReceiptParseError::new(
                "INVALID_SHAPE",
                format!("{field} must be an object"),
            ));
        }
    };

    if let Some(key) = map.keys().find(|key| !required.contains(&key.as_str())) {
        return Err(ReceiptParseError::new(
            "UNKNOWN_FIELD",
            format!("{field} has unknown field {key:?}"),
        ));
    }
    if let Some(key) = required.iter().find(|key| !map.contains_key(**key)) {
        return Err(ReceiptParseError::new(
            "MISSING_FIELD",
            format!("{field} lacks field {key:?}"),
        ));
    }
    Ok(std::mem::take(&mut map))
}

fn take(map: &mut BTreeMap<String, StrictJsonValue>, key: &str) -> StrictJsonValue {
    map.remove(key)
        .expect("exact BC-02.1 field set checked before extraction")
}

#[derive(Debug, Clone, PartialEq)]
enum StrictJsonValue {
    Null,
    Bool,
    Number(Number),
    String(String),
    Array,
    Object(BTreeMap<String, StrictJsonValue>),
}

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictValueVisitor;

        impl<'de> Visitor<'de> for StrictValueVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object members")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::Null)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::Null)
            }

            fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::Bool)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(StrictJsonValue::Number)
                    .ok_or_else(|| E::custom("INVALID_JSON: non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue::String(value))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while sequence.next_element::<StrictJsonValue>()?.is_some() {}
                Ok(StrictJsonValue::Array)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "DUPLICATE_KEY: duplicate object member {key:?}"
                        )));
                    }
                    let value = map.next_value::<StrictJsonValue>()?;
                    values.insert(key, value);
                }
                Ok(StrictJsonValue::Object(values))
            }
        }

        deserializer.deserialize_any(StrictValueVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_receipt(raw: &[u8]) -> Vec<u8> {
        let raw_b64 = BC021_BASE64.encode(raw);
        let digest = hex_lower(&Sha256::digest(raw));
        format!(
            concat!(
                "{{",
                "\"schema_id\":\"{}\",\"schema_version\":1,",
                "\"fixture\":{{\"fixture_id\":\"FIX-1\",\"fixture_artifact_identity\":\"fixture.bin\"}},",
                "\"handoff\":{{\"status\":\"TRANSFERRED\",\"method\":\"in-memory\"}},",
                "\"received\":{{\"octet_length\":{},\"raw_octets\":\"{}\",\"recomputed_sha256\":\"{}\"}},",
                "\"receiver\":{{\"receiver_id\":\"RI-RS\",\"implementation_id\":\"aura-ri-rs\",\"language\":\"Rust\",\"implementation_version\":\"1.0\",\"source_commit\":\"deadbeef\"}},",
                "\"adapter\":{{\"adapter_id\":\"BC-02.3-RS-P01-HANDOFF-ADAPTER\",\"adapter_version\":\"1.0\"}},",
                "\"environment\":{{\"environment_id\":\"unit-test\",\"platform\":\"linux\",\"runtime\":\"rust\"}}",
                "}}"
            ),
            SCHEMA_ID,
            raw.len(),
            raw_b64,
            digest
        )
        .into_bytes()
    }

    #[test]
    fn accepts_arbitrary_raw_octets_and_recomputes_digest() {
        let octets = [0x43, 0x36, 0x00, 0xfe, 0xff];
        let receipt = parse_receipt_json(&valid_receipt(&octets)).expect("valid receipt");
        assert_eq!(receipt.received.raw_octets, octets);
        assert_eq!(receipt.received.octet_length, octets.len());
        assert_eq!(
            receipt.received.recomputed_sha256,
            hex_lower(&Sha256::digest(octets))
        );
    }

    #[test]
    fn accepts_empty_raw_octet_sequence() {
        let receipt = parse_receipt_json(&valid_receipt(b"")).expect("empty raw octets are valid");
        assert!(receipt.received.raw_octets.is_empty());
        assert_eq!(receipt.received.octet_length, 0);
    }

    #[test]
    fn rejects_duplicate_keys_before_object_interpretation() {
        let raw = valid_receipt(b"");
        let text = String::from_utf8(raw).expect("valid JSON");
        let duplicate = text.replacen(
            "\"schema_id\":\"BC-02.1-COMMON-RECEIPT\"",
            "\"schema_id\":\"BC-02.1-COMMON-RECEIPT\",\"schema_id\":\"BC-02.1-COMMON-RECEIPT\"",
            1,
        );
        assert_eq!(
            parse_receipt_json(duplicate.as_bytes()).unwrap_err().code,
            "DUPLICATE_KEY"
        );
    }

    #[test]
    fn rejects_unknown_authority_field_as_unknown_field() {
        let raw = valid_receipt(b"");
        let text = String::from_utf8(raw).expect("valid JSON");
        let extra = text.replacen(
            "\"schema_id\":\"BC-02.1-COMMON-RECEIPT\"",
            "\"schema_id\":\"BC-02.1-COMMON-RECEIPT\",\"conformance_result\":\"PASS\"",
            1,
        );
        assert_eq!(
            parse_receipt_json(extra.as_bytes()).unwrap_err().code,
            "UNKNOWN_FIELD"
        );
    }
}
