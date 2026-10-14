//! End-to-end Gate 3 regression: API -> Core adapter -> JSONL/hash-chain -> replay.
//!
//! By default this test creates a minimal test-double Core interface, keeping cargo test
//! hermetic. CI may set AURA_CORE_PATH to the actual aura-poc-a-core-v3.3 checkout to
//! exercise the real Python evaluator using the same test vectors.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

use aura_guard::api::{build_router, AppState};
use aura_guard::config::Config;
use aura_guard::crypto::genesis_hash;
use aura_guard::log_writer::LogWriter;
use aura_guard::policy::{load_policy, CompiledPolicy, TrustedSigners};
use aura_guard::sealer::SegmentSealer;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

const API_KEY: &str = "gate3-core-measurement-api-key-0123456789abcdef";

struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl Drop for RestoreEnv {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            if let Some(value) = value {
                env::set_var(key, value);
            } else {
                env::remove_var(key);
            }
        }
    }
}

fn prepare_adapter_environment(temp: &TempDir) -> RestoreEnv {
    let keys = [
        "AURA_CORE_PATH",
        "AURA_CORE_CONSTITUTION_VECTOR",
        "AURA_CORE_PYTHON",
        "AURA_CORE_VERSION",
    ];
    let restore = RestoreEnv(keys.iter().map(|key| (*key, env::var_os(key))).collect());

    if env::var_os("AURA_CORE_PATH").is_none() {
        let core_root = temp.path().join("test-double-core");
        let core_dir = core_root.join("core");
        fs::create_dir_all(&core_dir).expect("create test-double Core package");
        fs::write(core_dir.join("__init__.py"), "").expect("write package marker");
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
        if vector == self.constitution:
            return {'ari': 100000, 'drift': 0}
        return {'ari': 30000, 'drift': 100000}
"#,
        )
        .expect("write test-double evaluator");
        env::set_var("AURA_CORE_PATH", core_root);
    }
    if env::var_os("AURA_CORE_CONSTITUTION_VECTOR").is_none() {
        env::set_var("AURA_CORE_CONSTITUTION_VECTOR", "[100000,0,0,0]");
    }
    if env::var_os("AURA_CORE_PYTHON").is_none() {
        env::set_var("AURA_CORE_PYTHON", "python3");
    }
    if env::var_os("AURA_CORE_VERSION").is_none() {
        env::set_var("AURA_CORE_VERSION", "core-v3.3-test");
    }
    restore
}

fn manifest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn build_state(root: &Path, log_path: &Path) -> AppState {
    let cfg = Config {
        bind: "127.0.0.1:0".parse().expect("valid bind address"),
        api_key: Some(API_KEY.to_string()),
        auth_disabled: false,
        policies_dir: manifest_root().join("policies"),
        trusted_signers_file: manifest_root().join("policies/trusted_signers.json"),
        default_policy_set: "finance-v1".to_string(),
        audit_log_path: log_path.to_path_buf(),
        max_body_bytes: 64 * 1024,
        request_timeout_ms: 10_000,
        metrics_enabled: true,
        allowed_origins: Vec::new(),
        segments_dir: root.join("segments"),
        segment_size: 2,
        segment_interval_seconds: 0,
        tsa_url: None,
        tsa_timeout_seconds: 10,
    };
    let signers = Arc::new(TrustedSigners::empty());
    let log =
        LogWriter::open(log_path.to_path_buf(), &genesis_hash()).expect("open temporary audit log");
    let sealer = SegmentSealer::new(
        cfg.segments_dir.clone(),
        cfg.segment_size,
        Duration::from_secs(cfg.segment_interval_seconds),
    )
    .expect("create test segment sealer");
    sealer
        .prime_from_log(log_path)
        .expect("prime sealer from empty audit log");
    let policies: DashMap<String, Arc<CompiledPolicy>> = DashMap::new();
    for name in ["finance-v1", "medtech-v1", "hr-bias-v1"] {
        let policy = load_policy(name, &cfg.policies_dir, &signers, false)
            .expect("load local policy for test");
        policies.insert(name.to_string(), Arc::new(policy));
    }
    AppState {
        config: Arc::new(cfg),
        policies: Arc::new(policies),
        log,
        signers,
        enforce_signatures: false,
        sealer: Some(sealer),
    }
}

async fn post_json(app: axum::Router, body: Value, request_id: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/audit")
        .header("Content-Type", "application/json")
        .header("X-API-Key", API_KEY)
        .header("X-Request-ID", request_id)
        .body(Body::from(body.to_string()))
        .expect("build request");
    let response = app.oneshot(req).await.expect("router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read response body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, json)
}

fn replay(log_path: &Path, segments_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aura-replay"))
        .arg("--log")
        .arg(log_path)
        .arg("--verify-segments")
        .arg("--segments-dir")
        .arg(segments_dir)
        .arg("--json")
        .output()
        .expect("run aura-replay")
}

#[tokio::test]
async fn request_measurement_is_hashed_and_ari_tampering_is_rejected() {
    let temp = tempfile::tempdir().expect("create temporary test directory");
    let _restore_env = prepare_adapter_environment(&temp);
    let log_path = temp.path().join("audit.jsonl");
    let app = build_router(build_state(temp.path(), &log_path));

    let base_request = json!({
        "context": "Finance Bot",
        "policy_set": "finance-v1",
        "payload": {
            "prompt": "Summarize the ordinary account activity.",
            "response": "The account activity is within the normal operating range."
        }
    });
    let mut malformed_request = base_request.clone();
    malformed_request["measurement_input"] = json!({
        "vector": [],
        "valid_schema": true
    });
    let (malformed_status, malformed_body) =
        post_json(app.clone(), malformed_request, "gate3-empty-vector").await;
    assert_eq!(
        malformed_status,
        StatusCode::BAD_REQUEST,
        "empty vector must be rejected before evaluation: {malformed_body}"
    );
    assert!(
        fs::read_to_string(&log_path)
            .expect("read log after invalid request")
            .is_empty(),
        "invalid measurement request must not create an audit record"
    );

    let (omitted_status, omitted_entry) =
        post_json(app.clone(), base_request.clone(), "gate3-omitted").await;
    assert_eq!(omitted_status, StatusCode::OK, "body={omitted_entry}");
    assert_eq!(omitted_entry["schema"], "aura-guard.audit.v2");
    assert_eq!(omitted_entry["core_measurement"]["status"], "OMITTED");
    assert!(omitted_entry["core_measurement"]["ari"].is_null());

    let mut measured_request = base_request;
    measured_request["measurement_input"] = json!({
        "vector": [100000, 0, 0, 0],
        "valid_schema": true
    });
    let (measured_status, measured_entry) =
        post_json(app, measured_request, "gate3-measured").await;
    assert_eq!(measured_status, StatusCode::OK, "body={measured_entry}");
    assert_eq!(measured_entry["decision"], omitted_entry["decision"]);
    assert_eq!(measured_entry["core_measurement"]["status"], "COMPLETED");
    assert_eq!(measured_entry["core_measurement"]["ari"], 100000);
    assert_eq!(measured_entry["core_measurement"]["drift"], 0);
    assert_eq!(
        measured_entry["core_measurement"]["evaluator_version"],
        env::var("AURA_CORE_VERSION").expect("version label is configured")
    );

    let log_text = fs::read_to_string(&log_path).expect("read persisted JSONL");
    let mut lines: Vec<String> = log_text.lines().map(str::to_string).collect();
    assert_eq!(lines.len(), 2, "both requests must be durably logged");
    let recorded: Value =
        serde_json::from_str(&lines[1]).expect("parse persisted measurement record");
    assert_eq!(recorded["core_measurement"]["ari"], 100000);
    assert_eq!(
        recorded["core_measurement"]["measurement_input_hash"]
            .as_str()
            .expect("measurement input hash present")
            .len(),
        64
    );

    let clean = replay(&log_path, &temp.path().join("segments"));
    assert!(
        clean.status.success(),
        "clean log did not verify: stdout={}, stderr={}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr)
    );
    let clean_summary: Value =
        serde_json::from_slice(&clean.stdout).expect("clean replay emits JSON summary");
    assert_eq!(clean_summary["status"], "ok");
    assert_eq!(clean_summary["entries"], 2);
    assert_eq!(clean_summary["core_measurements"], 2);
    assert_eq!(clean_summary["verified_segments"], true);
    assert_eq!(clean_summary["segments"], 1);

    // Mutate the exact persisted ARI while retaining the original chain_hash.
    let mut tampered: Value = serde_json::from_str(&lines[1]).expect("parse recorded line");
    let original_chain_hash = tampered["chain_hash"]
        .as_str()
        .expect("recorded chain_hash present")
        .to_string();
    assert_eq!(tampered["core_measurement"]["ari"], 100000);
    tampered["core_measurement"]["ari"] = json!(99999);
    assert_eq!(tampered["chain_hash"], original_chain_hash);
    println!(
        "TAMPER PROBE: core_measurement.ari 100000 -> 99999; original chain_hash retained ({original_chain_hash})"
    );
    lines[1] = serde_json::to_string(&tampered).expect("serialize tampered measurement record");
    fs::write(&log_path, format!("{}\n", lines.join("\n"))).expect("persist tampered log");

    let rejected = replay(&log_path, &temp.path().join("segments"));
    assert_eq!(
        rejected.status.code(),
        Some(2),
        "aura-replay must reject changed ARI: stdout={}, stderr={}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    println!(
        "TAMPER PROBE RESULT: aura-replay exit={:?}; {}",
        rejected.status.code(),
        stderr.trim()
    );
    assert!(
        stderr.contains("CHAIN BREAK DETECTED at entry #1"),
        "expected a chain-break refusal for the measured record, got: {stderr}"
    );
}
