#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Negative-vector integration test for the production RFC 3161 verifier.
//! The generator-derived input is paired with its real expected message imprint.

use std::fs;
use std::path::Path;
use std::process::Command;

use aura_guard::tst_verify::{verify_tsr, TrustAnchors};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct CorpusManifest {
    schema: String,
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    source_file: String,
    target_path: String,
    target_sha256: String,
    target_bytes_base64: String,
    expected_message_imprint_sha256: String,
    expected_disposition: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn generated_der_negative_vectors_are_rejected_by_production_verifier() {
    // The corpus is created in a fresh temporary directory. No tracked fixture
    // or caller working tree is modified by this test.
    let temp = tempfile::tempdir().expect("temporary directory");
    let generated = temp.path().join("generated");
    let command = Command::new("python3")
        .arg("tools/crypto_regression/generate_der_mutations.py")
        .arg("--fixtures-dir")
        .arg("tests/fixtures/tsa")
        .arg("--output-dir")
        .arg(&generated)
        .output()
        .expect("python3 must be available in the Guard CI environment");
    assert!(
        command.status.success(),
        "DER corpus generation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&command.stdout),
        String::from_utf8_lossy(&command.stderr),
    );

    let manifest_bytes =
        fs::read(generated.join("manifest.json")).expect("generated manifest exists");
    let manifest: CorpusManifest =
        serde_json::from_slice(&manifest_bytes).expect("generated manifest is valid JSON");
    assert_eq!(manifest.schema, "aura.crypto-regression.v1");
    assert_eq!(manifest.cases.len(), 20, "unexpected corpus size");

    let roots = TrustAnchors::from_pem_file(Path::new("tests/fixtures/tsa/freetsa-cacert.pem"))
        .expect("load pinned FreeTSA root");
    for case in manifest.cases {
        assert_eq!(case.expected_disposition, "REJECT", "case {}", case.id);
        let bytes = STANDARD
            .decode(&case.target_bytes_base64)
            .expect("mutated input is valid base64");
        assert_eq!(
            sha256_hex(&bytes),
            case.target_sha256,
            "hash mismatch for case {} from {} at {}",
            case.id,
            case.source_file,
            case.target_path,
        );
        let imprint_vec = hex::decode(&case.expected_message_imprint_sha256)
            .expect("expected imprint is hex");
        let imprint: [u8; 32] = imprint_vec
            .try_into()
            .expect("SHA-256 imprint must contain exactly 32 bytes");

        let result = verify_tsr(&bytes, &imprint, &roots);
        assert!(
            result.is_err(),
            "malformed DER case unexpectedly passed strict verification: {}",
            case.id,
        );
    }
}
