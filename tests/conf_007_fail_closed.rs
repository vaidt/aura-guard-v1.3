#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! CONF-007 / FIX-ERROR integration probes.
//!
//! These are test-only probes through the actual Axum audit route and LogWriter.
//! They verify that request/schema and policy-resolution failures return before
//! any decision or JSONL audit entry is produced.

use aura_guard::api::{build_router, AppState};
use aura_guard::config::Config;
use aura_guard::crypto::genesis_hash;
use aura_guard::log_writer::LogWriter;
use aura_guard::policy::{load_policy, CompiledPolicy, TrustedSigners};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dashmap::DashMap;
use http_body_util::BodyExt;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

const FIXTURE: &str = include_str!("fixtures/FIX-ERROR.json");
const API_KEY: &str = "conf007-fix-error-test-api-key-0123456789";

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
        request_timeout_ms: 2_000,
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
        .expect("open fresh isolated audit log");
    let policies: DashMap<String, Arc<CompiledPolicy>> = DashMap::new();
    for name in ["finance-v1", "medtech-v1", "hr-bias-v1"] {
        let policy = load_policy(name, &cfg.policies_dir, &signers, false)
            .expect("load repository policy for isolated test");
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

fn audit_entry_count(log_path: &Path) -> usize {
    match fs::read_to_string(log_path) {
        Ok(contents) => contents.lines().count(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("read audit log {}: {error}", log_path.display()),
    }
}

async fn post_raw(
    app: axum::Router,
    body: &str,
    request_id: &str,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/audit")
        .header("Content-Type", "application/json")
        .header("X-API-Key", API_KEY)
        .header("X-Request-ID", request_id)
        .body(Body::from(body.to_owned()))
        .expect("build raw HTTP request");
    let response = app.oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read response body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn conf007_fix_error_rejects_malformed_and_unregistered_requests_without_appending() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("FIX-ERROR fixture is valid JSON");
    assert_eq!(fixture["fixture_id"], "FIX-ERROR");

    let temp = TempDir::new().expect("create isolated CONF-007 test directory");
    let log_path = temp.path().join("audit.jsonl");
    let app = build_router(build_state(temp.path(), &log_path));

    assert_eq!(audit_entry_count(&log_path), 0, "fresh log must be empty");

    for case in fixture["http_cases"]
        .as_array()
        .expect("fixture http_cases array")
    {
        let id = case["id"].as_str().expect("case id");
        let body = case["request_body_raw"]
            .as_str()
            .expect("raw request body");
        let before = audit_entry_count(&log_path);

        let (status, response_body) = post_raw(app.clone(), body, id).await;

        assert!(
            (400..500).contains(&status.as_u16()),
            "{id}: expected HTTP 4xx rejection; status={status}, body={response_body:?}"
        );
        assert!(
            !response_body.contains("ALLOW")
                && !response_body.contains("\"decision\""),
            "{id}: rejected input must not receive a decision response: {response_body:?}"
        );
        let after = audit_entry_count(&log_path);
        assert_eq!(
            after, before,
            "{id}: rejected input appended a partial or complete audit record"
        );
        assert_eq!(
            after, 0,
            "{id}: there must be no persistent evidence for a rejected request"
        );
    }
}

#[test]
fn conf007_fix_error_rejects_unknown_policy_actions_at_load_time() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("FIX-ERROR fixture is valid JSON");
    let policy_case = &fixture["startup_cases"][0];
    assert_eq!(policy_case["id"], "FIX-ERROR-005");

    let temp = TempDir::new().expect("create isolated policy directory");
    let policy_yaml = policy_case["policy_yaml"]
        .as_str()
        .expect("invalid policy YAML fixture");
    fs::write(temp.path().join("finance-v1.yaml"), policy_yaml)
        .expect("write invalid policy fixture");

    let error = load_policy(
        "finance-v1",
        temp.path(),
        &TrustedSigners::empty(),
        false,
    )
    .expect_err("unknown decision action must not compile into a runtime policy");

    assert!(
        error.to_string().contains("invalid policy action"),
        "expected explicit invalid-action error, got: {error}"
    );
}
