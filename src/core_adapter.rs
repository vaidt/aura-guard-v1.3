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

/// Validated result returned by the one-shot Python adapter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAdapterOutput {
    /// Raw integer ARI returned by PoCAEvaluator.
    pub ari: i64,
    /// Raw integer drift returned by PoCAEvaluator.
    pub drift: i64,
    /// Explicit version label for the evaluator that ran.
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::models::MeasurementInput;
    use std::fs;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[tokio::test]
    async fn invokes_configured_python_core_and_returns_integer_measures() {
        let _lock = ENV_LOCK.lock().expect("serialize environment-mutating test");
        let temp = tempdir().expect("create fake Core repository");
        let core_dir = temp.path().join("core");
        fs::create_dir_all(&core_dir).expect("create core package");
        fs::write(
            core_dir.join("evaluator.py"),
            r#"
class PoCAEvaluator:
    def __init__(self, constitution):
        self.constitution = constitution
    def evaluate(self, agent_id, vector, valid_schema):
        if len(vector) != len(self.constitution):
            raise ValueError('vector dimension mismatch')
        if not valid_schema:
            return {'ari': 0, 'drift': 100000}
        return {'ari': 100000, 'drift': 0}
"#,
        )
        .expect("write fake Core evaluator");

        let keys = [
            "AURA_CORE_PATH",
            "AURA_CORE_CONSTITUTION_VECTOR",
            "AURA_CORE_PYTHON",
            "AURA_CORE_VERSION",
        ];
        let _restore = RestoreEnv(
            keys.iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect(),
        );
        std::env::set_var("AURA_CORE_PATH", temp.path());
        std::env::set_var("AURA_CORE_CONSTITUTION_VECTOR", "[100000,0,0,0]");
        std::env::set_var("AURA_CORE_PYTHON", "python3");
        std::env::set_var("AURA_CORE_VERSION", "core-v3.3-test");

        let input = MeasurementInput {
            vector: vec![100000, 0, 0, 0],
            valid_schema: true,
        };
        let result = evaluate(&input).await.expect("configured adapter should succeed");
        assert_eq!(result.ari, 100000);
        assert_eq!(result.drift, 0);
        assert_eq!(result.evaluator_version, "core-v3.3-test");

        let invalid_schema = MeasurementInput {
            vector: vec![100000, 0, 0, 0],
            valid_schema: false,
        };
        let result = evaluate(&invalid_schema)
            .await
            .expect("Core should return a measurement for invalid-schema observation");
        assert_eq!(result.ari, 0);
        assert_eq!(result.drift, 100000);
    }

    #[test]
    fn measurement_input_hash_binds_vector_and_schema_flag() {
        let input = MeasurementInput {
            vector: vec![100000, 0, 0, 0],
            valid_schema: true,
        };
        let expected = sha256_hex("{\"vector\":[100000,0,0,0],\"valid_schema\":true}");
        assert_eq!(measurement_input_hash(&input), expected);
        assert_ne!(
            measurement_input_hash(&input),
            measurement_input_hash(&MeasurementInput {
                vector: vec![100000, 0, 0, 1],
                valid_schema: true,
            })
        );
    }
}
