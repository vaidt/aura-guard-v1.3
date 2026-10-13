//! Gate 1 stress test for atomic audit-chain append.
//!
//! Starts the real Axum HTTP server on loopback, drives hundreds of concurrent
//! HTTP requests, and verifies the persisted JSONL using `aura-replay`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use regex::Regex;
use serde_json::{json, Value};
use tempfile::tempdir;

use aura_guard::api::{build_router, AppState};
use aura_guard::chain::verify_chain;
use aura_guard::config::Config;
use aura_guard::crypto::{genesis_hash, sha256_hex};
use aura_guard::log_writer::{read_all_entries, LogWriter};
use aura_guard::models::AuditEntry;
use aura_guard::policy::{CompiledPolicy, CompiledRule, TrustedSigners};

const REQUESTS: usize = 500;
const WORKERS: usize = 200;
const API_KEY: &str = "guard-rs-001-stress-api-key-0123456789abcdef";

fn test_state(log_path: PathBuf, temp_root: &Path) -> AppState {
    let mut config = Config::default();
    config.api_key = Some(API_KEY.to_string());
    config.auth_disabled = false;
    config.audit_log_path = log_path.clone();
    config.default_policy_set = "stress-policy".to_string();
    config.policies_dir = temp_root.join("policies");
    config.trusted_signers_file = temp_root.join("trusted_signers.json");
    config.segments_dir = temp_root.join("segments");
    config.segment_size = 0;
    config.segment_interval_seconds = 0;
    config.request_timeout_ms = 60_000;
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
        log: LogWriter::open(log_path, &genesis_hash()).expect("open temporary audit log"),
        signers: Arc::new(TrustedSigners::empty()),
        enforce_signatures: false,
        sealer: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn five_hundred_parallel_http_requests_form_one_replayable_chain() {
    let directory = tempdir().expect("temporary directory");
    let log_path = directory.path().join("audit.jsonl");
    let app = build_router(test_state(log_path.clone(), directory.path()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral loopback port");
    let address = listener.local_addr().expect("read bound address");
    let url = format!("http://{address}/v1/audit");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let next_request = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let next_request = next_request.clone();
        let url = url.clone();
        workers.push(tokio::task::spawn_blocking(move || {
            let mut entries = Vec::new();
            loop {
                let index = next_request.fetch_add(1, Ordering::Relaxed);
                if index >= REQUESTS {
                    break;
                }
                let request_id = format!("guard-rs-001-{index:05}");
                let body = json!({
                    "context": "AURA-GUARD-RS-001-STRESS",
                    "policy_set": "stress-policy",
                    "payload": {
                        "prompt": format!("Synthetic concurrent request {index}."),
                        "response": format!("Harmless deterministic test response {index}.")
                    }
                })
                .to_string();

                let response = ureq::post(&url)
                    .set("Content-Type", "application/json")
                    .set("X-API-Key", API_KEY)
                    .set("X-Request-ID", &request_id)
                    .send_string(&body)
                    .unwrap_or_else(|error| panic!("HTTP request {index} failed: {error}"));
                assert_eq!(response.status(), 200, "request {index}");
                let response_body = response
                    .into_string()
                    .expect("read HTTP response body");
                let entry: AuditEntry =
                    serde_json::from_str(&response_body).expect("response is an audit entry");
                assert_eq!(entry.request_id.as_deref(), Some(request_id.as_str()));
                entries.push(entry);
            }
            entries
        }));
    }

    let mut entries = Vec::with_capacity(REQUESTS);
    for worker in workers {
        entries.extend(worker.await.expect("HTTP worker completes"));
    }

    let _ = shutdown_tx.send(());
    server
        .await
        .expect("HTTP server task completes")
        .expect("HTTP server shutdown succeeds");

    assert_eq!(entries.len(), REQUESTS);
    let mut sequences: Vec<u64> = entries.iter().map(|entry| entry.seq).collect();
    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (0..REQUESTS as u64).collect::<Vec<_>>(),
        "HTTP response sequence numbers must be unique and contiguous"
    );
    let response_ids: HashSet<&str> = entries.iter().map(|entry| entry.audit_id.as_str()).collect();
    assert_eq!(response_ids.len(), REQUESTS, "audit_id values must be unique");

    let persisted = read_all_entries(&log_path).expect("read persisted JSONL");
    assert_eq!(persisted.len(), REQUESTS);
    for (index, entry) in persisted.iter().enumerate() {
        assert_eq!(entry.seq, index as u64);
    }
    verify_chain(&persisted).expect("in-process verifier accepts the entire chain");

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
