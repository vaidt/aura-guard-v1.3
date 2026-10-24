//! Stage C C6 shared wire corpus against Aura-Guard's exported RI-RS consumer.
//!
//! The single corpus test is ignored by default: the dedicated read-only
//! preflight supplies the exact shared corpus, expected source pins and result
//! directory, and enables it with --include-ignored.

use aura_guard::strict_wire::parse_receipt_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[test]
#[ignore = "requires the exact shared C6 wire corpus; run in the pinned Stage C preflight"]
fn c6_shared_wire_corpus_matches_expected_receipt_contract() {
    let corpus_dir = PathBuf::from(
        std::env::var_os("AURA_C6_WIRE_CORPUS_DIR")
            .expect("C6 workflow must set AURA_C6_WIRE_CORPUS_DIR"),
    );
    let results_dir = PathBuf::from(
        std::env::var_os("AURA_C6_WIRE_RESULTS_DIR")
            .expect("C6 workflow must set AURA_C6_WIRE_RESULTS_DIR"),
    );
    let source_commit =
        std::env::var("AURA_RI_RS_COMMIT").expect("C6 workflow must set AURA_RI_RS_COMMIT");
    let source_blob = std::env::var("AURA_RI_RS_SOURCE_BLOB")
        .expect("C6 workflow must set AURA_RI_RS_SOURCE_BLOB");
    let lib_blob =
        std::env::var("AURA_RI_RS_LIB_BLOB").expect("C6 workflow must set AURA_RI_RS_LIB_BLOB");
    let cargo_blob = std::env::var("AURA_RI_RS_CARGO_BLOB")
        .expect("C6 workflow must set AURA_RI_RS_CARGO_BLOB");
    let test_blob =
        std::env::var("AURA_RI_RS_TEST_BLOB").expect("C6 workflow must set AURA_RI_RS_TEST_BLOB");

    let index_raw = fs::read(corpus_dir.join("index.json")).expect("shared corpus index");
    let index: Value = serde_json::from_slice(&index_raw).expect("valid materialized corpus index");
    assert_eq!(index["schema"], "AURA-BC021-MATERIALIZED-WIRE-CORPUS/0.1");
    assert_eq!(index["status"], "MATERIALIZED_FOR_TESTING_ONLY");
    assert_eq!(index["authority"], "NONE");
    assert_eq!(index["governance_effect"], "NONE");

    let cases = index["cases"].as_array().expect("case array");
    assert_eq!(cases.len(), index["case_count"].as_u64().unwrap() as usize);
    assert!(!cases.is_empty());

    let mut result_rows = Vec::new();
    let mut mismatches: Vec<String> = Vec::new();

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let file = case["input_file"].as_str().expect("input file");
        let raw = fs::read(corpus_dir.join(file)).expect("materialized input file");
        let actual_sha = sha256_hex(&raw);

        if raw.len() != case["input_bytes"].as_u64().unwrap() as usize {
            mismatches.push(format!("{id}: input byte length differs from index"));
        }
        if actual_sha != case["input_sha256"].as_str().unwrap() {
            mismatches.push(format!("{id}: input SHA-256 differs from index"));
        }

        let expected_result = case["expected_result"].as_str().expect("expected result");
        let expected_code = case["expected_code"].as_str().map(str::to_owned);
        let (actual_result, actual_code) = match parse_receipt_json(&raw) {
            Ok(receipt) => {
                if receipt.schema_id != aura_guard::strict_wire::SCHEMA_ID {
                    mismatches.push(format!("{id}: unexpected schema identifier after parse"));
                }
                ("ACCEPT", None)
            }
            Err(error) => ("REJECT", Some(error.code.to_owned())),
        };

        if actual_result != expected_result {
            mismatches.push(format!(
                "{id}: expected result={expected_result}; actual result={actual_result}"
            ));
        }
        if actual_code != expected_code {
            mismatches.push(format!(
                "{id}: expected code={expected_code:?}; actual code={actual_code:?}"
            ));
        }

        let code_text = actual_code.as_deref().unwrap_or("null");
        println!("C6_SHARED_WIRE_CASE id={id} input_sha256={actual_sha} result={actual_result} code={code_text}");
        result_rows.push(json!({
            "id": id,
            "input_sha256": actual_sha,
            "input_bytes": raw.len(),
            "expected_result": expected_result,
            "expected_code": expected_code,
            "actual_result": actual_result,
            "actual_code": actual_code,
            "matched": actual_result == expected_result && actual_code == expected_code
        }));
    }

    let index_sha = sha256_hex(&index_raw);
    let status = if mismatches.is_empty() { "PASS" } else { "MISMATCH" };
    let report = json!({
        "schema": "AURA-BC021-WIRE-CONSUMER-RESULTS/0.1",
        "status": status,
        "implementation": "RI-RS-AURA-GUARD",
        "source_commit": source_commit,
        "source_blob_sha256": source_blob,
        "lib_blob_sha256": lib_blob,
        "cargo_blob_sha256": cargo_blob,
        "test_blob_sha256": test_blob,
        "index_sha256": index_sha,
        "case_count": result_rows.len(),
        "cases": result_rows,
        "mismatches": mismatches.clone(),
        "authority": "NONE",
        "governance_effect": "NONE",
        "authorization_effect": "NONE",
        "release_effect": "NONE"
    });

    fs::create_dir_all(&results_dir).expect("create results directory");
    fs::write(
        results_dir.join("ri-rs-results.json"),
        format!("{}\n", serde_json::to_string_pretty(&report).expect("serialize report")),
    )
    .expect("write RI-RS result report");

    assert!(
        mismatches.is_empty(),
        "strict RI-RS receipt wire-corpus mismatch: {mismatches:?}"
    );
}
