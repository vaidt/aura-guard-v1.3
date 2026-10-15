#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! L2.1-B — experimental RI-RS execution of the 17-vector discriminating corpus.
//!
//! This test imports the existing conformance adapter at jcs.rs directly.
//! It does not modify or route production serialization through that adapter.
//! Parser rejection, JCS rejection, and successful JCS output are recorded as
//! distinct outcomes. Expected protocol dispositions are evidence labels, not
//! assertions, so mismatches are observed rather than masked by a failing test.

#[path = "jcs.rs"]
mod jcs;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

const CORPUS_BYTES: &[u8] = include_bytes!("L2_1_B_discriminating_corpus.json");
const CARGO_LOCK_BYTES: &[u8] = include_bytes!("../../Cargo.lock");

#[derive(Debug, Deserialize)]
struct Corpus {
    artifact_id: String,
    stage: String,
    mode: String,
    provenance: Value,
    protocol_boundary: Value,
    vectors: Vec<CorpusVector>,
}

#[derive(Debug, Deserialize)]
struct CorpusVector {
    id: String,
    class: String,
    raw_json: String,
    protocol_expectation: String,
    expectation_notes: Option<String>,
    reference_results_from_prior_l2_1_b_report: Value,
}

#[derive(Debug, Serialize)]
struct ExecutionRow {
    id: String,
    class: String,
    raw_json: String,
    raw_input_sha256: String,
    protocol_expectation: String,
    expectation_notes: Option<String>,
    prior_reference_results: Value,
    parser_status: String,
    parser_error: Option<String>,
    canonicalizer_invoked: bool,
    ri_rs_status: String,
    canonical_bytes_len: Option<usize>,
    canonical_bytes_utf8: Option<String>,
    canonical_bytes_hex: Option<String>,
    sha256_canonical_bytes: Option<String>,
    leaf_preimage_hex: Option<String>,
    leaf_preimage_len: Option<usize>,
    leaf_sha256_independent: Option<String>,
    production_leaf_sha256: Option<String>,
    production_leaf_matches_independent_rfc6962: Option<bool>,
    mismatch_class: String,
}

#[derive(Debug, Serialize)]
struct ExecutionReport {
    artifact_id: String,
    stage: String,
    mode: String,
    provenance: Value,
    protocol_boundary: Value,
    repository: String,
    commit_sha: String,
    rustc_version: Option<String>,
    cargo_version: Option<String>,
    corpus_sha256: String,
    cargo_lock_sha256: String,
    dependency_pin: String,
    adapter_path: String,
    result_boundary: String,
    rows: Vec<ExecutionRow>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn mismatch_class(expectation: &str, actual: &str) -> String {
    if expectation == "REJECT" {
        if actual == "ACCEPTED_BY_RI_RS" {
            "TYPE_II_MISMATCH_PROTOCOL_EXPECTS_REJECT_RI_RS_ACCEPTS".to_string()
        } else if actual == "REJECTED_BY_SERDE_JSON" {
            "REJECTION_OBSERVED_AT_PARSER_BOUNDARY".to_string()
        } else {
            "REJECTION_OBSERVED_AT_CANONICALIZER_BOUNDARY".to_string()
        }
    } else if expectation == "ACCEPT_BYTES_SEMANTICS_UNRESOLVED" {
        if actual == "ACCEPTED_BY_RI_RS" {
            "BYTE_PATH_ACCEPTED_TIMESTAMP_SEMANTICS_UNRESOLVED".to_string()
        } else {
            "EXPECTED_BYTE_PATH_ACCEPTANCE_NOT_REACHED_TIMESTAMP_SEMANTICS_UNRESOLVED".to_string()
        }
    } else if actual == "ACCEPTED_BY_RI_RS" {
        "ACCEPTED_BY_RI_RS_EXPECTED_ACCEPTANCE".to_string()
    } else {
        "UNEXPECTED_REJECTION_PROTOCOL_EXPECTS_ACCEPTANCE".to_string()
    }
}

fn execute_vector(vector: &CorpusVector) -> ExecutionRow {
    // This digest identifies the test input as evidence; it is not a protocol
    // hash and is computed independently before parsing.
    let raw_input_sha256 = sha256_hex(vector.raw_json.as_bytes());

    let parsed: Value = match serde_json::from_str(&vector.raw_json) {
        Ok(value) => value,
        Err(error) => {
            let status = "REJECTED_BY_SERDE_JSON".to_string();
            return ExecutionRow {
                id: vector.id.clone(),
                class: vector.class.clone(),
                raw_json: vector.raw_json.clone(),
                raw_input_sha256,
                protocol_expectation: vector.protocol_expectation.clone(),
                expectation_notes: vector.expectation_notes.clone(),
                prior_reference_results: vector.reference_results_from_prior_l2_1_b_report.clone(),
                parser_status: status.clone(),
                parser_error: Some(error.to_string()),
                canonicalizer_invoked: false,
                ri_rs_status: status.clone(),
                canonical_bytes_len: None,
                canonical_bytes_utf8: None,
                canonical_bytes_hex: None,
                sha256_canonical_bytes: None,
                leaf_preimage_hex: None,
                leaf_preimage_len: None,
                leaf_sha256_independent: None,
                production_leaf_sha256: None,
                production_leaf_matches_independent_rfc6962: None,
                mismatch_class: mismatch_class(&vector.protocol_expectation, &status),
            };
        }
    };

    let canonical_bytes = match jcs::canonical_bytes(&parsed) {
        Ok(bytes) => bytes,
        Err(error) => {
            let status = "REJECTED_BY_CANONICALIZER".to_string();
            return ExecutionRow {
                id: vector.id.clone(),
                class: vector.class.clone(),
                raw_json: vector.raw_json.clone(),
                raw_input_sha256,
                protocol_expectation: vector.protocol_expectation.clone(),
                expectation_notes: vector.expectation_notes.clone(),
                prior_reference_results: vector.reference_results_from_prior_l2_1_b_report.clone(),
                parser_status: "PARSED_BY_SERDE_JSON".to_string(),
                parser_error: None,
                canonicalizer_invoked: true,
                ri_rs_status: status.clone(),
                canonical_bytes_len: None,
                canonical_bytes_utf8: None,
                canonical_bytes_hex: None,
                sha256_canonical_bytes: None,
                leaf_preimage_hex: None,
                leaf_preimage_len: None,
                leaf_sha256_independent: None,
                production_leaf_sha256: None,
                production_leaf_matches_independent_rfc6962: None,
                mismatch_class: format!(
                    "{}; canonicalizer_error={}",
                    mismatch_class(&vector.protocol_expectation, &status),
                    error
                ),
            };
        }
    };

    let mut leaf_preimage = Vec::with_capacity(canonical_bytes.len() + 1);
    leaf_preimage.push(0x00);
    leaf_preimage.extend_from_slice(&canonical_bytes);

    let sha256_canonical_bytes = sha256_hex(&canonical_bytes);
    let leaf_sha256_independent = sha256_hex(&leaf_preimage);
    let production_leaf = aura_guard::merkle::leaf_hash(&canonical_bytes);
    let production_leaf_sha256 = hex::encode(&production_leaf);
    let production_leaf_matches_independent_rfc6962 =
        production_leaf_sha256 == leaf_sha256_independent;

    let status = "ACCEPTED_BY_RI_RS".to_string();
    ExecutionRow {
        id: vector.id.clone(),
        class: vector.class.clone(),
        raw_json: vector.raw_json.clone(),
        raw_input_sha256,
        protocol_expectation: vector.protocol_expectation.clone(),
        expectation_notes: vector.expectation_notes.clone(),
        prior_reference_results: vector.reference_results_from_prior_l2_1_b_report.clone(),
        parser_status: "PARSED_BY_SERDE_JSON".to_string(),
        parser_error: None,
        canonicalizer_invoked: true,
        ri_rs_status: status.clone(),
        canonical_bytes_len: Some(canonical_bytes.len()),
        canonical_bytes_utf8: String::from_utf8(canonical_bytes.clone()).ok(),
        canonical_bytes_hex: Some(hex::encode(&canonical_bytes)),
        sha256_canonical_bytes: Some(sha256_canonical_bytes),
        leaf_preimage_hex: Some(hex::encode(&leaf_preimage)),
        leaf_preimage_len: Some(leaf_preimage.len()),
        leaf_sha256_independent: Some(leaf_sha256_independent),
        production_leaf_sha256: Some(production_leaf_sha256),
        production_leaf_matches_independent_rfc6962: Some(
            production_leaf_matches_independent_rfc6962
        ),
        mismatch_class: mismatch_class(&vector.protocol_expectation, &status),
    }
}

#[test]
fn execute_all_17_l2_1_b_vectors_through_the_ri_rs_adapter() {
    let corpus: Corpus =
        serde_json::from_slice(CORPUS_BYTES).expect("the checked-in corpus JSON must parse");
    assert_eq!(
        corpus.vectors.len(),
        17,
        "the reconstructed L2.1-B corpus must contain exactly 17 vectors"
    );

    let rows: Vec<ExecutionRow> = corpus.vectors.iter().map(execute_vector).collect();
    assert_eq!(rows.len(), 17, "every corpus vector must yield one execution row");

    let report = ExecutionReport {
        artifact_id: corpus.artifact_id,
        stage: corpus.stage,
        mode: corpus.mode,
        provenance: corpus.provenance,
        protocol_boundary: corpus.protocol_boundary,
        repository: "vaidt/aura-guard-v1.3".to_string(),
        commit_sha: std::env::var("GITHUB_SHA").unwrap_or_else(|_| "UNAVAILABLE_OUTSIDE_CI".to_string()),
        rustc_version: std::env::var("RUSTC_VERSION").ok(),
        cargo_version: std::env::var("CARGO_VERSION").ok(),
        corpus_sha256: sha256_hex(CORPUS_BYTES),
        cargo_lock_sha256: sha256_hex(CARGO_LOCK_BYTES),
        dependency_pin: "serde_json_canonicalizer = \"=0.3.2\"".to_string(),
        adapter_path: "conformance/canonical/jcs.rs".to_string(),
        result_boundary: "RI-RS observed execution only; no normative effect; parser rejection prevents canonicalizer and protocol hash stages; raw_input_sha256 is provenance-only.".to_string(),
        rows,
    };

    let report_json =
        serde_json::to_string_pretty(&report).expect("execution report must serialize to JSON");
    fs::write("L2_1_B_RI_RS_EXECUTION_RESULTS.json", &report_json)
        .expect("write the experimental evidence report");
    println!("L2_1_B_RI_RS_RESULT_BEGIN");
    println!("{report_json}");
    println!("L2_1_B_RI_RS_RESULT_END");
}
