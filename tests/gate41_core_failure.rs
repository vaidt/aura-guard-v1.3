//! Gate 4.1 — deterministic Core adapter failure and raw JSONL privacy probes.
//!
//! This suite intentionally changes no production behavior. A controlled executable
//! stands in for the configured Python adapter so timeout/parser failures do not rely
//! on network conditions or an external Core checkout.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aura_guard::api::{build_router, AppState};
use aura_guard::chain::verify_chain;
use aura_guard::config::Config;
use aura_guard::crypto::genesis_hash;
use aura_guard::log_writer::LogWriter;
use aura_guard::models::AuditEntry;
use aura_guard::policy::{load_policy, CompiledPolicy, TrustedSigners};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const API_KEY: &str = "gate4.1-test-api-key-0123456789abcdef";
const SECRET_PROMPT: &str = "G41_SECRET_PROMPT_7F31";
const SECRET_RESPONSE: &str = "G41_SECRET_RESPONSE_9A62";

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

fn restore_core_environment() -> RestoreEnv {
    let keys = [
        "AURA_CORE_PATH",
        "AURA_CORE_CONSTITUTION_VECTOR",
        "AURA_CORE_PYTHON",
        "AURA_CORE_VERSION",
    ];
    RestoreEnv(keys.iter().map(|key| (*key, env::var_os(key))).collect())
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
        segment_size: 0,
        segment_interval_seconds: 0,
        tsa_url: None,
        tsa_timeout_seconds: 10,
    };

    let signers = Arc::new(TrustedSigners::empty());
    let log = LogWriter::open(log_path.to_path_buf(), &genesis_hash())
        .expect("open temporary JSONL audit log");
    let policies: DashMap<String, Arc<CompiledPolicy>> = DashMap::new();
    for name in ["finance-v1", "medtech-v1", "hr-bias-v1"] {
        let policy =
            load_policy(name, &cfg.policies_dir, &signers, false).expect("load local test policy");
        policies.insert(name.to_string(), Arc::new(policy));
    }

    AppState {
        config: Arc::new(cfg),
        policies: Arc::new(policies),
        log,
        signers,
        enforce_signatures: false,
        sealer: None,
    }
}

fn write_mock_python(root: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = root.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write mock adapter executable");
    let mut permissions = fs::metadata(&path)
        .expect("stat mock adapter")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("make mock adapter executable");
    path
}

fn measured_request(prompt: &str, response: &str) -> Value {
    json!({
        "context": "Finance Bot",
        "policy_set": "finance-v1",
        "payload": {
            "prompt": prompt,
            "response": response
        },
        "measurement_input": {
            "vector": [100000, 0, 0, 0],
            "valid_schema": true
        }
    })
}

fn plain_request() -> Value {
    json!({
        "context": "Finance Bot",
        "policy_set": "finance-v1",
        "payload": {
            "prompt": "Ordinary audit prompt.",
            "response": "Ordinary audit response."
        }
    })
}

async fn post_json(app: axum::Router, body: Value, request_id: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/audit")
        .header("Content-Type", "application/json")
        .header("X-API-Key", API_KEY)
        .header("X-Request-ID", request_id)
        .body(Body::from(body.to_string()))
        .expect("build POST request");
    let response = app.oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read response body")
        .to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, value)
}

fn assert_error_measurement(entry: &Value, baseline_decision: &str, scenario: &str) {
    assert_eq!(
        entry["decision"].as_str(),
        Some(baseline_decision),
        "{scenario}: Core failure changed the policy decision: {entry}"
    );
    assert_eq!(
        entry["core_measurement"]["status"], "ERROR",
        "{scenario}: failure was not recorded as ERROR: {entry}"
    );
    assert!(
        entry["core_measurement"]["ari"].is_null(),
        "{scenario}: ERROR measurement must not carry a fabricated ARI: {entry}"
    );
    assert!(
        entry["core_measurement"]["drift"].is_null(),
        "{scenario}: ERROR measurement must not carry a fabricated drift: {entry}"
    );
    assert!(
        entry["core_measurement"]["measurement_input_hash"]
            .as_str()
            .is_some_and(|value| value.len() == 64),
        "{scenario}: measurement input must remain bound to the ERROR observation: {entry}"
    );
}

#[tokio::test]
async fn gate41_core_failures_are_passive_and_raw_jsonl_excludes_prompt_response() {
    let _restore = restore_core_environment();
    let temp = tempfile::tempdir().expect("create isolated Gate 4.1 test directory");
    env::set_var("AURA_CORE_PATH", temp.path());
    env::set_var("AURA_CORE_CONSTITUTION_VECTOR", "[100000,0,0,0]");
    env::set_var("AURA_CORE_VERSION", "core-v3.3-gate4.1-test");

    let log_path = temp.path().join("audit.jsonl");
    let app = build_router(build_state(temp.path(), &log_path));

    // Control: policy decision without measurement establishes the unchanged
    // text-policy result that every Core failure must preserve.
    let (baseline_status, baseline) = post_json(app.clone(), plain_request(), "g41-baseline").await;
    assert_eq!(baseline_status, StatusCode::OK, "baseline={baseline}");
    let baseline_decision = baseline["decision"]
        .as_str()
        .expect("baseline decision is present")
        .to_string();

    // A second control exercises a hard negative policy outcome. The timeout
    // scenario below repeats this input to prove Core failure cannot erase DENY.
    let deny_request = json!({
        "context": "Finance Bot",
        "policy_set": "finance-v1",
        "payload": {
            "prompt": "Synthetic test card 4111111111111111",
            "response": "This dummy value is used only to exercise the policy rule."
        }
    });
    let (deny_status, deny_baseline) =
        post_json(app.clone(), deny_request, "g41-deny-baseline").await;
    assert_eq!(deny_status, StatusCode::OK, "DENY baseline={deny_baseline}");
    let deny_decision = deny_baseline["decision"]
        .as_str()
        .expect("DENY baseline decision is present")
        .to_string();
    assert_eq!(
        deny_decision, "DENY",
        "synthetic Luhn PAN must trigger DENY"
    );

    // G41-PRV-002 + happy-path control: successful mock output, then inspect raw
    // bytes of the persistent JSONL file rather than only the HTTP response.
    let valid = write_mock_python(
        temp.path(),
        "mock-core-valid",
        r#"printf '%s\n' '{"ari":100000,"drift":0,"evaluator_version":"gate4.1-mock"}'"#,
    );
    env::set_var("AURA_CORE_PYTHON", valid);
    let (privacy_status, privacy_entry) = post_json(
        app.clone(),
        measured_request(SECRET_PROMPT, SECRET_RESPONSE),
        "g41-privacy-marker-scan",
    )
    .await;
    assert_eq!(
        privacy_status,
        StatusCode::OK,
        "privacy entry={privacy_entry}"
    );
    assert_eq!(privacy_entry["core_measurement"]["status"], "COMPLETED");
    assert_eq!(
        privacy_entry["decision"].as_str(),
        Some(baseline_decision.as_str())
    );

    let raw = fs::read(&log_path).expect("read raw JSONL bytes");
    for marker in [SECRET_PROMPT.as_bytes(), SECRET_RESPONSE.as_bytes()] {
        assert!(
            !raw.windows(marker.len()).any(|window| window == marker),
            "G41-PRV-002 FAIL: secret marker was found in raw audit JSONL"
        );
    }
    let raw_text = String::from_utf8(raw.clone()).expect("JSONL is UTF-8");
    assert!(
        !raw_text.contains("\"prompt\""),
        "prompt field found in JSONL"
    );
    assert!(
        !raw_text.contains("\"response\""),
        "response field found in JSONL"
    );

    // G41-CORE-001: deterministic process timeout. The mocked executable directly
    // replaces itself with sleep; no socket, network, or external Core is used.
    // Core's production timeout remains the frozen 2-second constant.
    let timeout = write_mock_python(temp.path(), "mock-core-timeout", "exec sleep 30");
    env::set_var("AURA_CORE_PYTHON", timeout);
    let started = Instant::now();
    let pending = tokio::spawn(post_json(
        app.clone(),
        measured_request(
            "Synthetic test card 4111111111111111",
            "This dummy value is used only to exercise the policy rule.",
        ),
        "g41-core-timeout",
    ));

    // A health request should remain serviceable while the measurement process is
    // pending. This guards against accidentally blocking the async request runtime.
    let health_request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .expect("build health request");
    let health_response = app
        .clone()
        .oneshot(health_request)
        .await
        .expect("health route responds during Core timeout");
    assert_eq!(health_response.status(), StatusCode::OK);
    let (timeout_status, timeout_entry) = pending.await.expect("join timed-out request");
    assert_eq!(
        timeout_status,
        StatusCode::OK,
        "timeout entry={timeout_entry}"
    );
    assert_error_measurement(&timeout_entry, &deny_decision, "G41-CORE-001");
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "G41-CORE-001: request did not return within the 8-second test bound"
    );

    // G41-CORE-003: syntactically broken JSON must not be accepted as a result.
    let malformed_json = write_mock_python(
        temp.path(),
        "mock-core-bad-json",
        r#"printf '%s\n' '{"ari":'"#,
    );
    env::set_var("AURA_CORE_PYTHON", malformed_json);
    let (json_status, json_entry) = post_json(
        app.clone(),
        measured_request("malformed JSON probe", "ordinary response"),
        "g41-core-malformed-json",
    )
    .await;
    assert_eq!(
        json_status,
        StatusCode::OK,
        "malformed JSON entry={json_entry}"
    );
    assert_error_measurement(&json_entry, &baseline_decision, "G41-CORE-003");

    // G41-CORE-004a: valid JSON with a required field missing is a schema error.
    let missing_field = write_mock_python(
        temp.path(),
        "mock-core-missing-field",
        r#"printf '%s\n' '{"ari":100000}'"#,
    );
    env::set_var("AURA_CORE_PYTHON", missing_field);
    let (missing_status, missing_entry) = post_json(
        app.clone(),
        measured_request("missing field probe", "ordinary response"),
        "g41-core-missing-field",
    )
    .await;
    assert_eq!(
        missing_status,
        StatusCode::OK,
        "missing field entry={missing_entry}"
    );
    assert_error_measurement(&missing_entry, &baseline_decision, "G41-CORE-004a");

    // G41-CORE-004b: incorrect JSON types are rejected by the typed deserializer.
    let wrong_type = write_mock_python(
        temp.path(),
        "mock-core-wrong-type",
        r#"printf '%s\n' '{"ari":"100000","drift":0,"evaluator_version":"gate4.1-mock"}'"#,
    );
    env::set_var("AURA_CORE_PYTHON", wrong_type);
    let (type_status, type_entry) = post_json(
        app.clone(),
        measured_request("wrong type probe", "ordinary response"),
        "g41-core-wrong-type",
    )
    .await;
    assert_eq!(type_status, StatusCode::OK, "wrong type entry={type_entry}");
    assert_error_measurement(&type_entry, &baseline_decision, "G41-CORE-004b");

    // G41-CORE-002: spawn failure is contained as an ERROR observation.
    env::set_var(
        "AURA_CORE_PYTHON",
        temp.path().join("no-such-python-executable"),
    );
    let (spawn_status, spawn_entry) = post_json(
        app.clone(),
        measured_request("spawn failure probe", "ordinary response"),
        "g41-core-spawn-failure",
    )
    .await;
    assert_eq!(
        spawn_status,
        StatusCode::OK,
        "spawn failure entry={spawn_entry}"
    );
    assert_error_measurement(&spawn_entry, &baseline_decision, "G41-CORE-002");

    // Every successful HTTP audit operation is persisted as a complete, replayable
    // chain entry, including ERROR observations. Validate the actual deserialized
    // JSONL chain after all failure injections.
    let final_text = fs::read_to_string(&log_path).expect("read final JSONL");
    let entries: Vec<AuditEntry> = final_text
        .lines()
        .map(|line| serde_json::from_str(line).expect("every JSONL line parses as AuditEntry"))
        .collect();
    assert_eq!(
        entries.len(),
        8,
        "two baselines + privacy + five failure probes"
    );
    verify_chain(&entries).expect("JSONL chain verifies after Core failures");
    assert!(
        entries.iter().any(|entry| {
            entry.core_measurement.as_ref().is_some_and(|measurement| {
                measurement.status == aura_guard::models::CoreMeasurementStatus::Error
            })
        }),
        "at least one explicit ERROR observation should be persisted"
    );

    // Re-scan final bytes so negative-path logging cannot bypass the privacy check.
    let final_raw = fs::read(&log_path).expect("read final JSONL binary");
    for marker in [SECRET_PROMPT.as_bytes(), SECRET_RESPONSE.as_bytes()] {
        assert!(
            !final_raw
                .windows(marker.len())
                .any(|window| window == marker),
            "G41-PRV-002 FAIL: secret marker appeared after negative-path probes"
        );
    }
}
