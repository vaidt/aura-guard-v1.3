//! Stage C isolated Rust JCS invocation shim.
//!
//! This is a non-production example target. It reuses the existing
//! conformance-only JCS engine without touching src/ or the production
//! serializer/Merkle path. It does not implement BC-02 receiver semantics and
//! cannot assign protocol-conformance or release status.

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

const REQUEST_SCHEMA: &str = "AURA-STAGE-C-ADAPTER-REQUEST/0.1";
const RESPONSE_SCHEMA: &str = "AURA-STAGE-C-ADAPTER-RESPONSE/0.1";
const ADAPTER_ID: &str = "STAGE-C-RUST-JCS-PROBE";
const ADAPTER_VERSION: &str = "0.1.0";
const JCS_ENGINE_VERSION: &str = "0.3.2";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    run_id: String,
    operation: String,
    fixture_id: String,
    input_path: String,
    json_pointer: String,
    source_commit: String,
}

#[derive(Debug)]
struct ProbeError {
    exit_code: u8,
    message: String,
}

impl ProbeError {
    fn input(message: impl Into<String>) -> Self {
        Self { exit_code: 2, message: message.into() }
    }

    fn execution(message: impl Into<String>) -> Self {
        Self { exit_code: 3, message: message.into() }
    }

    fn output(message: impl Into<String>) -> Self {
        Self { exit_code: 4, message: message.into() }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_request(raw: &[u8]) -> Result<Request, ProbeError> {
    let request: Request = serde_json::from_slice(raw)
        .map_err(|error| ProbeError::input(format!("request JSON/schema invalid: {error}")))?;

    if request.schema != REQUEST_SCHEMA {
        return Err(ProbeError::input(format!(
            "unsupported request schema: {}",
            request.schema
        )));
    }
    if request.operation != "jcs.canonicalize" {
        return Err(ProbeError::input(format!(
            "unsupported operation: {}",
            request.operation
        )));
    }
    if request.json_pointer != "/protocol_object" {
        return Err(ProbeError::input(
            "v0.1 supports only JSON Pointer /protocol_object",
        ));
    }
    for (name, value) in [
        ("run_id", request.run_id.as_str()),
        ("fixture_id", request.fixture_id.as_str()),
        ("input_path", request.input_path.as_str()),
    ] {
        if value.is_empty() {
            return Err(ProbeError::input(format!("{name} must be non-empty")));
        }
    }
    if !valid_git_sha(&request.source_commit) {
        return Err(ProbeError::input(
            "source_commit must be a 40-character lowercase Git SHA",
        ));
    }

    Ok(request)
}

fn resolve_input_path(repo_root: &Path, input_path: &str) -> Result<PathBuf, ProbeError> {
    let candidate = Path::new(input_path);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    {
        return Err(ProbeError::input(
            "input_path must be repository-relative and must not traverse outside repo root",
        ));
    }

    let root = repo_root
        .canonicalize()
        .map_err(|error| ProbeError::input(format!("cannot resolve repo root: {error}")))?;
    let resolved = root
        .join(candidate)
        .canonicalize()
        .map_err(|error| ProbeError::input(format!("cannot resolve input path: {error}")))?;
    if !resolved.starts_with(&root) {
        return Err(ProbeError::input(
            "input_path resolves outside the repository root",
        ));
    }
    Ok(resolved)
}

fn canonicalize_protocol_object(
    fixture_bytes: &[u8],
    expected_fixture_id: &str,
) -> Result<Vec<u8>, ProbeError> {
    let fixture: Value = serde_json::from_slice(fixture_bytes)
        .map_err(|error| ProbeError::input(format!("fixture is not valid JSON: {error}")))?;
    if fixture.get("fixture_id").and_then(Value::as_str) != Some(expected_fixture_id) {
        return Err(ProbeError::input(format!(
            "fixture identity mismatch: expected {expected_fixture_id:?}, got {:?}",
            fixture.get("fixture_id").and_then(Value::as_str)
        )));
    }
    let protocol_object = fixture
        .get("protocol_object")
        .ok_or_else(|| ProbeError::input("fixture does not contain JSON Pointer /protocol_object"))?;

    serde_json_canonicalizer::to_vec(protocol_object)
        .map_err(|error| ProbeError::execution(format!("JCS engine failed: {error}")))
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn execute(
    request_path: &Path,
    response_path: &Path,
    output_path: &Path,
    repo_root: &Path,
) -> Result<(), ProbeError> {
    let request_bytes = fs::read(request_path)
        .map_err(|error| ProbeError::input(format!("cannot read request: {error}")))?;
    let request = parse_request(&request_bytes)?;
    let input_path = resolve_input_path(repo_root, &request.input_path)?;
    let input_bytes = fs::read(&input_path)
        .map_err(|error| ProbeError::input(format!("cannot read fixture: {error}")))?;
    let canonical_bytes =
        canonicalize_protocol_object(&input_bytes, &request.fixture_id)?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ProbeError::output(format!("cannot create output directory: {error}")))?;
    }
    fs::write(output_path, &canonical_bytes)
        .map_err(|error| ProbeError::output(format!("cannot write raw output octets: {error}")))?;

    let response = serde_json::json!({
        "schema": RESPONSE_SCHEMA,
        "run_id": request.run_id,
        "operation": request.operation,
        "execution_status": "COMPLETED",
        "authority": "NONE",
        "adapter": {
            "adapter_id": ADAPTER_ID,
            "adapter_version": ADAPTER_VERSION,
            "language": "Rust",
            "source_commit": request.source_commit,
            "engine_distribution": "serde_json_canonicalizer",
            "engine_version": JCS_ENGINE_VERSION,
            "rust_runtime": rustc_version(),
            "platform": format!("{}-{}", env::consts::OS, env::consts::ARCH)
        },
        "input": {
            "fixture_id": request.fixture_id,
            "path": request.input_path,
            "json_pointer": request.json_pointer,
            "octet_length": input_bytes.len(),
            "sha256": sha256_hex(&input_bytes)
        },
        "output": {
            "path": output_path.to_string_lossy(),
            "octet_length": canonical_bytes.len(),
            "sha256": sha256_hex(&canonical_bytes)
        },
        "scope_note": "Isolated JCS probe only; no receiver handoff, Merkle decision, protocol conformance, acceptance, ratification, or release result."
    });

    let response_bytes = serde_json::to_vec(&response)
        .map_err(|error| ProbeError::output(format!("cannot serialize response envelope: {error}")))?;
    if let Some(parent) = response_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ProbeError::output(format!("cannot create response directory: {error}")))?;
    }
    fs::write(response_path, response_bytes)
        .map_err(|error| ProbeError::output(format!("cannot write response envelope: {error}")))?;

    println!("execution_status=COMPLETED");
    println!("adapter_id={ADAPTER_ID}");
    println!("engine=serde_json_canonicalizer {JCS_ENGINE_VERSION}");
    println!("input_sha256={}", sha256_hex(&input_bytes));
    println!("output_octet_length={}", canonical_bytes.len());
    println!("output_sha256={}", sha256_hex(&canonical_bytes));
    println!("authority=NONE");
    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let mut request = None;
    let mut response = None;
    let mut output_octets = None;
    let mut repo_root = None;

    while let Some(arg) = args.next() {
        let value = match args.next() {
            Some(value) => value,
            None => {
                eprintln!("INPUT_ERROR: missing value for {arg}");
                return ExitCode::from(2);
            }
        };
        match arg.as_str() {
            "--request" => request = Some(PathBuf::from(value)),
            "--response" => response = Some(PathBuf::from(value)),
            "--output-octets" => output_octets = Some(PathBuf::from(value)),
            "--repo-root" => repo_root = Some(PathBuf::from(value)),
            _ => {
                eprintln!("INPUT_ERROR: unknown argument {arg}");
                return ExitCode::from(2);
            }
        }
    }

    let request = match request {
        Some(path) => path,
        None => {
            eprintln!("INPUT_ERROR: --request is required");
            return ExitCode::from(2);
        }
    };
    let response = match response {
        Some(path) => path,
        None => {
            eprintln!("INPUT_ERROR: --response is required");
            return ExitCode::from(2);
        }
    };
    let output_octets = match output_octets {
        Some(path) => path,
        None => {
            eprintln!("INPUT_ERROR: --output-octets is required");
            return ExitCode::from(2);
        }
    };
    let repo_root = repo_root.unwrap_or_else(|| PathBuf::from("."));

    match execute(&request, &response, &output_octets, &repo_root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("PROBE_ERROR: {}", error.message);
            ExitCode::from(error.exit_code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_REQUEST: &str = r#"{
        "schema":"AURA-STAGE-C-ADAPTER-REQUEST/0.1",
        "run_id":"unit-test",
        "operation":"jcs.canonicalize",
        "fixture_id":"CANONICAL-003",
        "input_path":"fixtures/corpus/CANONICAL-003_jcs_full_discriminator.json",
        "json_pointer":"/protocol_object",
        "source_commit":"991274eed57d5b3308b0607feeb4d01e6a485974"
    }"#;

    #[test]
    fn request_contract_accepts_valid_request() {
        let parsed = parse_request(VALID_REQUEST.as_bytes()).expect("valid request accepted");
        assert_eq!(parsed.fixture_id, "CANONICAL-003");
        assert_eq!(parsed.operation, "jcs.canonicalize");
    }

    #[test]
    fn request_contract_rejects_unknown_fields() {
        let invalid = VALID_REQUEST.replace(
            "\"source_commit\":",
            "\"unexpected\":\"nope\",\"source_commit\":",
        );
        assert!(parse_request(invalid.as_bytes()).is_err());
    }

    #[test]
    fn request_contract_rejects_duplicate_fields() {
        let invalid = VALID_REQUEST.replace(
            "\"run_id\":\"unit-test\"",
            "\"run_id\":\"unit-test\",\"run_id\":\"shadow\"",
        );
        assert!(parse_request(invalid.as_bytes()).is_err());
    }

    #[test]
    fn request_contract_rejects_bad_source_commit() {
        let invalid = VALID_REQUEST.replace(
            "991274eed57d5b3308b0607feeb4d01e6a485974",
            "not-a-git-sha",
        );
        assert!(parse_request(invalid.as_bytes()).is_err());
    }

    #[test]
    fn request_contract_rejects_parent_path() {
        assert!(resolve_input_path(Path::new("."), "../outside.json").is_err());
    }

    #[test]
    fn canonicalizer_matches_the_pinned_canonical003_oracle() {
        let specification_root = env::var_os("AURA_SPECIFICATION_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("../aura-specification"));
        let fixture = specification_root.join("fixtures/corpus/CANONICAL-003_jcs_full_discriminator.json");
        let expected = specification_root.join("fixtures/corpus/CANONICAL-003_jcs_full_discriminator.expected.jcs");
        let fixture_bytes = fs::read(&fixture).expect("fixture available in pinned specification checkout");
        let actual = canonicalize_protocol_object(&fixture_bytes, "CANONICAL-003")
            .expect("JCS canonicalization succeeds");
        let expected_bytes = fs::read(&expected).expect("oracle available in pinned specification checkout");
        assert_eq!(actual, expected_bytes);
        assert_eq!(actual.len(), 577);
        assert!(!actual.ends_with(b"\n"));
        assert_eq!(
            sha256_hex(&actual),
            "9fb648c388c4485575d25c1d6171ba691fec51c1b433b11f4d61197bbe2a5509"
        );
    }
}
