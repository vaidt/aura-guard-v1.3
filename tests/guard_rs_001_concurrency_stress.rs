//! Gate 1 integration stress test for atomic audit-chain append.
//!
//! Drives the real Axum router concurrently, then verifies the persisted JSONL
//! using the independent `aura-replay` executable built by Cargo.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use regex::Regex;
use serde_json::{json, Value};
use tempfile::tempdir;
use tower::ServiceExt;

use aura_guard::api::{build_router, AppState};
use aura_guard::chain::verify_chain;
use aura_guard::config::Config;
use aura_guard::crypto::{genesis_hash, sha256_hex};
use aura_guard::log_writer::{read_all_entries, LogWriter};
use aura_guard::models::AuditEntry;
use aura_guard::policy::{CompiledPolicy, CompiledRule, TrustedSigners};

const REQUESTS: usize = 500;
const API_KEY: &str = "guard-rs-001-stress-api-key-0123456789abcdef";

fn test_state(log_path: PathBuf, temp_root: &std::path::Path) -> AppState {
    let mut config = Config::default();
    config.api_key = Some(API_KEY.to_string());
    config.auth_disabled = false;
    config.audit_log_path = log_path;
    config.default_policy_set = "stress-policy".to_string();
    config.policies_dir = temp_root.join("policies");
    config.trusted_signers_file = temp_root.join("trusted_signers.json");
    config.segments_dir = temp_root.join("segments");
    config.segment_size = 0;
    config.segment_interval_seconds = 0;
    config.validate().expect("test config is valid");

    let policy = CompiledPolicy {
        name: "stress-policy".to_string(),
        version: "1".to_string(),
        policy_hash: sha256_hex("stress-policy-v1"),
        rules: vec![CompiledRule {
            id: "NO_MATCH".to_string(),
            pattern: Regex::new("NEVER_MATCH_AURA_GUARD_RS_001").expect("test regex is valid"),
            action: "deny".to_string(),
            score: 1.0,
            validator: None,
            context_pattern: None,
        }],
    };

    let policies = dashmap::DashMap::new();
    policies.insert("stress-policy".to_string(), Arc::new(policy));

    AppState {
        config: Arc::new(config),
        policies: Arc::new(policies),
        log: LogWriter::open(
            temp_root.join("audit.jsonl"),
            &genesis_hash(),
        )
        .expect("open temporary audit log"),
        signers: Arc::new(TrustedSigners::empty()),
        enforce_signatures: false,
        sealer: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn five_hundred_parallel_audit_requests_form_one_replayable_chain() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("audit.jsonl");
    let app = build_router(test_state(log_path.clone(), directory.path()));
    let mut tasks = tokio::task::JoinSet::new();

    for index in 0..REQUESTS {
        let app = app.clone();
        tasks.spawn(async move {
            let request_id = format!("guard-rs-001-{index:05}");
            let body = json!({
                "context": "AURA-GUARD-RS-001-STRESS",
                "policy_set": "stress-policy",
                "payload": {
                    "prompt": format!("Synthetic concurrent request {index}."),
                    "response": format!("Harmless deterministic test response {index}.")
                }
            });
            let request = Request::builder()
                .method("POST")
                .uri("/v1/audit")
                .header("content-type", "application/json")
                .header("x-api-key", API_KEY)
                .header("x-request-id", &request_id)
                .body(Body::from(body.to_string()))
                .expect("request is valid");

            let response = app.oneshot(request).await.expect("router response");
            assert_eq!(response.status(), StatusCode::OK, "request {index}");
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("response body")
                .to_bytes();
            let entry: AuditEntry =
                serde_json::from_slice(&bytes).expect("response is an audit entry");
            assert_eq!(entry.request_id.as_deref(), Some(request_id.as_str()));
            entry
        });
    }

    let mut response_sequences = Vec::with_capacity(REQUESTS);
    let mut response_ids = HashSet::with_capacity(REQUESTS);
    while let Some(result) = tasks.join_next().await {
        let entry = result.expect("request task completes");
        response_sequences.push(entry.seq);
        assert!(response_ids.insert(entry.audit_id), "duplicate audit_id");
    }

    response_sequences.sort_unstable();
    assert_eq!(
        response_sequences,
        (0..REQUESTS as u64).collect::<Vec<_>>(),
        "HTTP response sequence numbers must be unique and contiguous"
    );
    assert_eq!(response_ids.len(), REQUESTS);

    let entries = read_all_entries(&log_path).expect("read persisted JSONL");
    assert_eq!(entries.len(), REQUESTS);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64);
    }
    verify_chain(&entries).expect("in-process verifier accepts the entire chain");

    let replay = Command::new(env!("CARGO_BIN_EXE_aura-replay"))
        .arg("--log")
        .arg(&log_path)
        .arg("--json")
        .output()
        .expect("run aura-replay");
    assert!(
        replay.status.success(),
        "aura-replay failed: stdout={} stderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );

    let summary: Value =
        serde_json::from_slice(&replay.stdout).expect("aura-replay emits JSON summary");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["entries"], REQUESTS);
}
