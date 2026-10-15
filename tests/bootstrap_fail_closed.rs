#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Bootstrap fail-closed contract tests.
//!
//! Spawns the real `aura-guard` binary in a hermetic environment and verifies
//! it refuses to start (exit code **78**, `sysexits.h::EX_CONFIG`) when the
//! enforcement boundary is incomplete:
//!
//! * a policy listed in `EXPECTED_POLICIES` is missing,
//! * the trusted-signers file is missing,
//! * the policy signature does not verify against any trusted signer.
//!
//! These tests pin the architectural invariant that gave rise to the v1.3
//! review feedback: there is no "warn and lazy-load" path; the runtime
//! either starts with a fully validated enforcement boundary or not at all.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

/// `sysexits.h::EX_CONFIG`.
const EX_CONFIG: i32 = 78;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_aura-guard")
}

/// Run `aura-guard` with the given env vars, give it a brief window to fail,
/// kill it if it did manage to bind, and return the exit code.
fn run_and_collect_exit(env: &[(&str, String)]) -> i32 {
    let mut cmd = Command::new(binary());
    cmd.env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn aura-guard");

    // Boot failure is synchronous and fast (<200 ms). Poll briefly.
    for _ in 0..30 {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code().unwrap_or(-1);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // The binary did NOT fail fast — it probably bound a socket. That itself
    // means the fail-closed contract is broken, but we still need to clean
    // up so the test runner doesn't leak processes.
    let _ = child.kill();
    let _ = child.wait();
    panic!("aura-guard did not exit within 3 seconds; expected boot failure");
}

#[test]
fn refuses_to_start_when_policy_missing() {
    let tmp = TempDir::new().unwrap();
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    std::fs::write(policies_dir.join("trusted_signers.json"), b"{}").unwrap();

    let code = run_and_collect_exit(&[
        ("AURA_BIND", "127.0.0.1:0".into()),
        ("AURA_POLICIES_DIR", policies_dir.display().to_string()),
        (
            "AURA_TRUSTED_SIGNERS_FILE",
            policies_dir
                .join("trusted_signers.json")
                .display()
                .to_string(),
        ),
        (
            "AURA_AUDIT_LOG_PATH",
            tmp.path().join("audit.jsonl").display().to_string(),
        ),
        ("AURA_AUTH_DISABLED", "true".into()),
    ]);

    assert_eq!(
        code, EX_CONFIG,
        "missing finance-v1.yaml must surface as exit 78 (EX_CONFIG), got {code}"
    );
}

#[test]
fn refuses_to_start_when_trusted_signers_missing() {
    let tmp = TempDir::new().unwrap();
    let policies_dir = tmp.path().join("policies");
    std::fs::create_dir_all(&policies_dir).unwrap();
    // Note: no trusted_signers.json. Auth is NOT disabled.

    let code = run_and_collect_exit(&[
        ("AURA_BIND", "127.0.0.1:0".into()),
        ("AURA_API_KEY", "bootstrap-signers-test-key-00000000".into()),
        ("AURA_POLICIES_DIR", policies_dir.display().to_string()),
        (
            "AURA_TRUSTED_SIGNERS_FILE",
            policies_dir
                .join("trusted_signers.json")
                .display()
                .to_string(),
        ),
        (
            "AURA_AUDIT_LOG_PATH",
            tmp.path().join("audit.jsonl").display().to_string(),
        ),
    ]);

    assert_eq!(
        code, EX_CONFIG,
        "missing trusted_signers.json under enforce must surface as exit 78, got {code}"
    );
}


#[test]
fn refuses_to_start_when_policy_action_is_invalid() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/FIX-ERROR.json"))
            .expect("FIX-ERROR fixture is valid JSON");
    let policy_case = &fixture["startup_cases"][0];
    let policy_yaml = policy_case["policy_yaml"]
        .as_str()
        .expect("invalid policy fixture body");

    let tmp = TempDir::new().unwrap();
    let policies_dir = tmp.path().join("policies");
    fs::create_dir_all(&policies_dir).unwrap();

    // Provide the complete expected policy set so the tested failure is the
    // malformed finance-v1 action, not an unrelated missing-pack condition.
    let repository_policies = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies");
    for name in ["medtech-v1.yaml", "hr-bias-v1.yaml"] {
        fs::copy(repository_policies.join(name), policies_dir.join(name)).unwrap();
    }
    fs::write(policies_dir.join("trusted_signers.json"), b"{}").unwrap();
    fs::write(policies_dir.join("finance-v1.yaml"), policy_yaml).unwrap();

    let audit_log = tmp.path().join("audit.jsonl");
    let code = run_and_collect_exit(&[
        ("AURA_BIND", "127.0.0.1:0".into()),
        ("AURA_POLICIES_DIR", policies_dir.display().to_string()),
        (
            "AURA_TRUSTED_SIGNERS_FILE",
            policies_dir
                .join("trusted_signers.json")
                .display()
                .to_string(),
        ),
        ("AURA_AUDIT_LOG_PATH", audit_log.display().to_string()),
        ("AURA_AUTH_DISABLED", "true".into()),
    ]);

    assert_eq!(
        code, EX_CONFIG,
        "an invalid policy action must abort bootstrap with exit 78, got {code}"
    );

    let persisted = match fs::read_to_string(&audit_log) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => panic!("read failed-startup audit log: {error}"),
    };
    assert!(
        persisted.lines().next().is_none(),
        "failed policy bootstrap must persist no audit record: {persisted:?}"
    );
}
