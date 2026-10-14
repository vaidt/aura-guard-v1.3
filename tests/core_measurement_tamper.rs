//! Tamper-evidence regression for the Gate 3 Core measurement block.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::process::Command;

use aura_guard::chain::compute_chain_hash_with_measurement;
use aura_guard::crypto::genesis_hash;
use aura_guard::models::{AuditEntry, CoreMeasurement, CoreMeasurementStatus};
use serde_json::Value;
use tempfile::tempdir;

fn measured_entry() -> AuditEntry {
    let core_measurement = CoreMeasurement {
        status: CoreMeasurementStatus::Completed,
        ari: Some(100_000),
        drift: Some(0),
        evaluator_version: "core-v3.3".into(),
        measurement_input_hash: Some("a".repeat(64)),
    };
    assert!(core_measurement.is_well_formed());

    let prev_hash = genesis_hash();
    let decision = "ALLOW";
    let policy_set = "finance-v1";
    let policy_hash = "b".repeat(64);
    let context = "Finance Bot";
    let input_hash = "c".repeat(64);
    let shadow_hash = "d".repeat(64);
    let seq = 0;
    let timestamp = "2026-10-14T22:30:00Z";
    let chain_hash = compute_chain_hash_with_measurement(
        &prev_hash,
        decision,
        policy_set,
        &policy_hash,
        context,
        &input_hash,
        &shadow_hash,
        seq,
        timestamp,
        &core_measurement,
    );

    AuditEntry {
        schema: "aura-guard.audit.v2".into(),
        seq,
        audit_id: "gate3-tamper-test-0001".into(),
        request_id: Some("gate3-tamper-test".into()),
        timestamp: timestamp.into(),
        decision: decision.into(),
        policy_set: policy_set.into(),
        policy_hash,
        context: context.into(),
        input_hash: input_hash.into(),
        shadow_hash: shadow_hash.into(),
        core_measurement: Some(core_measurement),
        violations: vec![],
        prev_hash,
        chain_hash,
    }
}

#[test]
fn aura_replay_rejects_ari_mutation_from_100000_to_99999() {
    let temp = tempdir().expect("create temporary test directory");
    let log = temp.path().join("audit.jsonl");
    let entry = measured_entry();
    let clean_line = serde_json::to_string(&entry).expect("serialize clean audit entry");
    fs::write(&log, format!("{clean_line}\n")).expect("write clean audit log");

    let replay = || {
        Command::new(env!("CARGO_BIN_EXE_aura-replay"))
            .arg("--log")
            .arg(&log)
            .arg("--json")
            .output()
            .expect("run aura-replay")
    };

    let clean = replay();
    assert!(
        clean.status.success(),
        "untampered log must verify: stdout={}, stderr={}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr)
    );
    let summary: Value =
        serde_json::from_slice(&clean.stdout).expect("clean replay emits JSON summary");
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["core_measurements"], 1);

    let mut tampered: Value = serde_json::from_str(&clean_line).expect("parse audit entry");
    assert_eq!(tampered["core_measurement"]["ari"], 100000);
    tampered["core_measurement"]["ari"] = serde_json::json!(99999);
    fs::write(
        &log,
        format!(
            "{}\n",
            serde_json::to_string(&tampered).expect("serialize tampered entry")
        ),
    )
    .expect("write tampered audit log");

    let rejected = replay();
    assert_eq!(
        rejected.status.code(),
        Some(2),
        "aura-replay must exit 2 on measurement tampering; stdout={}, stderr={}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        stderr.contains("CHAIN BREAK DETECTED at entry #0"),
        "expected chain-break refusal, got: {stderr}"
    );
}
