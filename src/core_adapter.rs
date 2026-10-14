//! One-shot adapter from Aura-Guard to the configured AURA Core Python evaluator.
//!
//! The bridge is local-only and invokes Python without a shell. When measurement
//! is requested but Core is unavailable, the handler records an explicit ERROR
//! measurement while leaving the existing text-policy decision path unchanged.

use std::process::Stdio;

use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::crypto::sha256_hex;
use crate::models::MeasurementInput;

/// Default version label recorded for this integration target.
pub const DEFAULT_CORE_VERSION: &str = "core-v3.3";

/// Bound the incoming vector before starting an external process.
pub const MAX_MEASUREMENT_VECTOR_DIMENSION: usize = 4096;

const PYTHON_ADAPTER: &str = include_str!("../scripts/aura_core_adapter.py");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAdapterOutput {
    pub ari: i64,
    pub drift: i64,
    pub evaluator_version: String,
}

/// Hash the deterministic, compact JSON representation of the measurement input.
///
/// The input DTO contains only an ordered integer array and a boolean, so this
/// explicit representation is independent of map ordering and floating-point rules.
pub fn measurement_input_hash(input: &MeasurementInput) -> String {
    let vector = input
        .vector
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let valid_schema = if input.valid_schema { "true" } else { "false" };
    let canonical = format!("{{\"vector\":[{vector}],\"valid_schema\":{valid_schema}}}");
    sha256_hex(&canonical)
}

/// Return the version label used for explicit OMITTED and ERROR observations.
pub fn configured_evaluator_version() -> String {
    std::env::var("AURA_CORE_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CORE_VERSION.to_string())
}

/// Invoke the actual Core evaluator through the bundled one-shot Python adapter.
///
/// Required environment:
/// - AURA_CORE_PATH: repository root containing core/evaluator.py;
/// - AURA_CORE_CONSTITUTION_VECTOR: JSON array of fixed-point integers.
///
/// Optional environment:
/// - AURA_CORE_PYTHON: Python executable (defaults to python3);
/// - AURA_CORE_VERSION: audit label (defaults to core-v3.3).
pub async fn evaluate(input: &MeasurementInput) -> Result<CoreAdapterOutput, String> {
    if input.vector.is_empty() {
        return Err("measurement vector must not be empty".to_string());
    }
    if input.vector.len() > MAX_MEASUREMENT_VECTOR_DIMENSION {
        return Err(format!(
            "measurement vector has {} elements; limit is {}",
            input.vector.len(),
            MAX_MEASUREMENT_VECTOR_DIMENSION
        ));
    }

    let core_path = std::env::var("AURA_CORE_PATH")
        .map_err(|_| "AURA_CORE_PATH is not configured".to_string())?;
    let constitution = std::env::var("AURA_CORE_CONSTITUTION_VECTOR")
        .map_err(|_| "AURA_CORE_CONSTITUTION_VECTOR is not configured".to_string())?;
    let python = std::env::var("AURA_CORE_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let input_json = serde_json::to_vec(input)
        .map_err(|error| format!("cannot serialize measurement input: {error}"))?;

    let mut child = Command::new(python)
        .arg("-c")
        .arg(PYTHON_ADAPTER)
        .env("AURA_CORE_PATH", core_path)
        .env("AURA_CORE_CONSTITUTION_VECTOR", constitution)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| format!("cannot start Python Core adapter: {error}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Python Core adapter stdin was unavailable".to_string())?;
    stdin
        .write_all(&input_json)
        .await
        .map_err(|error| format!("cannot send measurement input to Core adapter: {error}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|error| format!("cannot wait for Python Core adapter: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.chars().take(500).collect::<String>();
        return Err(format!(
            "Python Core adapter exited with {}: {}",
            output.status,
            detail.trim()
        ));
    }

    let result: CoreAdapterOutput = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Core adapter returned invalid JSON: {error}"))?;
    if result.evaluator_version.trim().is_empty() {
        return Err("Core adapter returned an empty evaluator_version".to_string());
    }
    Ok(result)
}
