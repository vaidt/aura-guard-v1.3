//! Request / response data transfer objects (DTOs) shared by the HTTP API
//! and the audit log file format.

use serde::{Deserialize, Serialize};

/// Inbound `/v1/audit` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditRequest {
    /// Free-form context string (e.g. "Finance Bot", "MedTech Assistant").
    /// Used both in the evidence hash and to gate conditional rules.
    pub context: String,

    /// Optional policy pack to evaluate against. When omitted the server uses
    /// the `default_policy_set` from configuration.
    pub policy_set: Option<String>,

    /// The actual AI interaction being audited.
    pub payload: Payload,

    /// Optional pre-normalized fixed-point vector for the Python PoCA evaluator.
    /// Omission preserves the original text-policy-only request path.
    #[serde(default)]
    pub measurement_input: Option<MeasurementInput>,
}

/// Optional input forwarded to the configured AURA Core adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementInput {
    /// Pre-normalized integer vector, scaled by the Core's fixed-point factor.
    pub vector: Vec<i32>,
    /// Whether the caller's measurement schema passed validation.
    pub valid_schema: bool,
}

/// Execution state for the optional Core measurement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoreMeasurementStatus {
    /// The configured Core evaluator ran and returned both integer measures.
    Completed,
    /// No measurement_input was supplied with the audit request.
    Omitted,
    /// A measurement was requested but the adapter could not produce a result.
    Error,
}

/// Measurement output included in the response, JSONL record, and chain preimage.
///
/// Fields are serialized in declaration order as compact JSON for deterministic
/// hashing. measurement_input_hash binds the result (or error) to the exact
/// canonical JSON representation of the requested vector and schema flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreMeasurement {
    /// Whether a measure was computed, explicitly omitted, or failed.
    pub status: CoreMeasurementStatus,
    /// Raw integer ARI at the Core fixed-point scale; null unless COMPLETED.
    pub ari: Option<i64>,
    /// Raw integer drift at the Core fixed-point scale; null unless COMPLETED.
    pub drift: Option<i64>,
    /// Configured evaluator label used to interpret the result.
    pub evaluator_version: String,
    /// SHA-256 of compact measurement-input JSON; null for OMITTED.
    #[serde(default)]
    pub measurement_input_hash: Option<String>,
}

impl CoreMeasurement {
    /// Construct the explicit no-measurement observation for legacy text-only requests.
    pub fn omitted(evaluator_version: impl Into<String>) -> Self {
        Self {
            status: CoreMeasurementStatus::Omitted,
            ari: None,
            drift: None,
            evaluator_version: evaluator_version.into(),
            measurement_input_hash: None,
        }
    }

    /// Construct an error observation without changing the policy decision path.
    pub fn error(evaluator_version: impl Into<String>, input_hash: String) -> Self {
        Self {
            status: CoreMeasurementStatus::Error,
            ari: None,
            drift: None,
            evaluator_version: evaluator_version.into(),
            measurement_input_hash: Some(input_hash),
        }
    }

    /// Return whether status and result fields form a structurally valid combination.
    pub fn is_well_formed(&self) -> bool {
        let status_fields_match = match self.status {
            CoreMeasurementStatus::Completed => {
                self.ari.is_some()
                    && self.drift.is_some()
                    && self
                        .measurement_input_hash
                        .as_ref()
                        .is_some_and(|h| is_sha256_hex(h))
            }
            CoreMeasurementStatus::Omitted => {
                self.ari.is_none() && self.drift.is_none() && self.measurement_input_hash.is_none()
            }
            CoreMeasurementStatus::Error => {
                self.ari.is_none()
                    && self.drift.is_none()
                    && self.measurement_input_hash.as_ref().is_some_and(|h| is_sha256_hex(h))
            }
        };
        status_fields_match && !self.evaluator_version.trim().is_empty()
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Prompt / response pair being audited.
#[derive(Debug, Clone, Deserialize)]
pub struct Payload {
    /// Prompt sent to the LLM by the user / upstream system.
    pub prompt: String,
    /// Response returned by the LLM.
    pub response: String,
}

/// A single rule match recorded against an audit decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Rule identifier from the policy YAML.
    pub rule: String,
    /// Action declared by the rule (`deny`, `review`, `allow`).
    pub action: String,
    /// Confidence score (0.0–1.0) reported for compliance triage.
    pub confidence: f32,
    /// Optional semantic validator outcome (e.g. `"pesel_checksum_ok"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator: Option<String>,
}

/// Outbound `/v1/audit` response body and the canonical audit log entry.
///
/// The on-disk JSONL log uses the exact same shape, with the only addition of
/// `prev_hash` and `chain_hash` (both already present here). This guarantees
/// 1:1 replayability between the response and the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Stable schema version of this entry.
    pub schema: String,

    /// Monotonic sequence number assigned by the server (0-based).
    pub seq: u64,

    /// Unique per-request UUIDv4.
    pub audit_id: String,

    /// Caller-supplied correlation id echoed from the `X-Request-ID` HTTP
    /// request header when present and valid; omitted otherwise. Enables
    /// cross-service tracing.
    /// Caller-supplied (or server-generated) correlation id echoed from the
    /// `X-Request-ID` HTTP request header. Enables cross-service tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    /// RFC 3339 timestamp (UTC) when the decision was produced.
    pub timestamp: String,

    /// Final decision: `DENY`, `REVIEW`, or `ALLOW`.
    pub decision: String,

    /// Policy pack that was evaluated.
    pub policy_set: String,

    /// Hex-encoded SHA-256 of the loaded policy file (provenance pin).
    pub policy_hash: String,

    /// Echo of the request context (verbatim).
    pub context: String,

    /// SHA-256 of the original input (`context + prompt + response`).
    pub input_hash: String,

    /// SHA-256 of the SHADOW_SPEC-normalized input (regex evaluation surface).
    pub shadow_hash: String,

    /// Optional AURA Core measurement. Missing only in historical v1 audit records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_measurement: Option<CoreMeasurement>,

    /// Rule matches that contributed to the decision.
    pub violations: Vec<Violation>,

    /// `chain_hash` of the previous entry (or the genesis hash for entry #0).
    pub prev_hash: String,

    /// SHA-256 chain digest; v2 includes the length-prefixed canonical core_measurement JSON.
    pub chain_hash: String,
}
