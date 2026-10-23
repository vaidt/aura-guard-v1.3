//! Stage C C5 tests against the production RI-RS Merkle primitives.
//!
//! This integration target is ignored by default because it requires the
//! external, draft corpus at AURA_C5_MERKLE_CORPUS. The dedicated C5 workflow
//! supplies that exact file and invokes this target explicitly. It does not
//! change runtime source or confer protocol/governance/release status.

use aura_guard::merkle::{audit_path, empty_root, leaf_hash, merkle_root, node_hash, verify_audit_path};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: String,
    leaf_payloads_utf8: Vec<String>,
    expected_roots: Vec<RootCase>,
    domain_separation_case: DomainCase,
}

#[derive(Debug, Deserialize)]
struct RootCase {
    tree_size: usize,
    expected_root_sha256: String,
}

#[derive(Debug, Deserialize)]
struct DomainCase {
    left_payload_utf8: String,
    right_payload_utf8: String,
    expected_left_leaf_sha256: String,
    expected_right_leaf_sha256: String,
    expected_node_sha256: String,
    raw_left_payload_sha256_not_expected: String,
    undomain_separated_node_sha256_not_expected: String,
}

fn digest_hex(digest: &[u8; 32]) -> String {
    hex::encode(digest)
}

fn decode_digest(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("corpus digest must be hex");
    bytes.try_into().expect("corpus digest must be 32 bytes")
}

fn read_corpus() -> Corpus {
    let path = std::env::var_os("AURA_C5_MERKLE_CORPUS")
        .map(PathBuf::from)
        .expect("C5 workflow must set AURA_C5_MERKLE_CORPUS to the pinned draft corpus");
    let bytes = fs::read(&path).expect("C5 corpus must be readable");
    let corpus: Corpus = serde_json::from_slice(&bytes).expect("C5 corpus schema must parse");
    assert_eq!(corpus.schema, "AURA-STAGE-C-MERKLE-C5-CORPUS/0.1");
    corpus
}

#[test]
#[ignore = "requires the external C5 corpus; run explicitly in the Stage C C5 workflow"]
fn c5_domain_separation_matches_fixed_vectors() {
    let corpus = read_corpus();
    let case = corpus.domain_separation_case;
    let left = leaf_hash(case.left_payload_utf8.as_bytes());
    let right = leaf_hash(case.right_payload_utf8.as_bytes());
    let node = node_hash(&left, &right);
    assert_eq!(digest_hex(&left), case.expected_left_leaf_sha256);
    assert_eq!(digest_hex(&right), case.expected_right_leaf_sha256);
    assert_eq!(digest_hex(&node), case.expected_node_sha256);

    let raw_left = sha2::Sha256::digest(case.left_payload_utf8.as_bytes());
    assert_ne!(digest_hex(&<[u8; 32]>::from(raw_left)), case.raw_left_payload_sha256_not_expected);
    let undomain_node = sha2::Sha256::digest([left.as_slice(), right.as_slice()].concat());
    assert_ne!(digest_hex(&<[u8; 32]>::from(undomain_node)), case.undomain_separated_node_sha256_not_expected);
    assert_eq!(empty_root(), sha2::Sha256::digest([]).into());
}

#[test]
#[ignore = "requires the external C5 corpus; run explicitly in the Stage C C5 workflow"]
fn c5_tree_roots_and_shape_match_all_fixed_vectors() {
    let corpus = read_corpus();
    let leaves: Vec<[u8; 32]> = corpus.leaf_payloads_utf8.iter()
        .map(|payload| leaf_hash(payload.as_bytes()))
        .collect();
    assert_eq!(corpus.expected_roots.len(), corpus.leaf_payloads_utf8.len() + 1);

    for case in corpus.expected_roots {
        assert!(case.tree_size <= leaves.len(), "tree size exceeds corpus payload count");
        let root = merkle_root(&leaves[..case.tree_size]);
        assert_eq!(digest_hex(&root), case.expected_root_sha256, "tree_size={}", case.tree_size);
        if case.tree_size > 0 {
            assert_eq!(digest_hex(&leaves[0]), corpus.expected_roots_leaf_zero_not_used());
        }
    }
}

trait RootCaseHelper {
    fn expected_roots_leaf_zero_not_used(&self) -> String;
}
impl RootCaseHelper for Corpus {
    fn expected_roots_leaf_zero_not_used(&self) -> String {
        // Sentinel that prevents accidentally turning a root test into a leaf-only test.
        "C5_ROOT_CASES_ARE_CHECKED_ABOVE".to_owned()
    }
}

#[test]
#[ignore = "requires the external C5 corpus; run explicitly in the Stage C C5 workflow"]
fn c5_inclusion_proofs_verify_and_tampering_fails_closed() {
    let corpus = read_corpus();
    let leaves: Vec<[u8; 32]> = corpus.leaf_payloads_utf8.iter()
        .map(|payload| leaf_hash(payload.as_bytes()))
        .collect();

    for case in corpus.expected_roots {
        let size = case.tree_size;
        if size == 0 {
            continue;
        }
        let tree_leaves = &leaves[..size];
        let root = merkle_root(tree_leaves);
        for index in 0..size {
            let proof = audit_path(index, tree_leaves);
            assert!(verify_audit_path(&tree_leaves[index], index, size, &proof, &root),
                "valid proof rejected: tree_size={size}, leaf_index={index}");
            assert!(!verify_audit_path(&leaf_hash(b"AURA-C5-TAMPERED"), index, size, &proof, &root),
                "tampered leaf accepted: tree_size={size}, leaf_index={index}");
            assert!(!verify_audit_path(&tree_leaves[index], index, size, &proof, &[0u8; 32]),
                "tampered root accepted: tree_size={size}, leaf_index={index}");
            assert!(!verify_audit_path(&tree_leaves[index], size, size, &proof, &root),
                "out-of-range index accepted: tree_size={size}");
            if !proof.is_empty() {
                let mut truncated = proof.clone();
                truncated.pop();
                assert!(!verify_audit_path(&tree_leaves[index], index, size, &truncated, &root),
                    "truncated proof accepted: tree_size={size}, leaf_index={index}");
                let mut extended = proof.clone();
                extended.push([0u8; 32]);
                assert!(!verify_audit_path(&tree_leaves[index], index, size, &extended, &root),
                    "extra proof element accepted: tree_size={size}, leaf_index={index}");
                let mut corrupted = proof.clone();
                corrupted[0][0] ^= 0x01;
                assert!(!verify_audit_path(&tree_leaves[index], index, size, &corrupted, &root),
                    "tampered sibling accepted: tree_size={size}, leaf_index={index}");
            }
            if size > 1 {
                let wrong_index = (index + 1) % size;
                assert!(!verify_audit_path(&tree_leaves[index], wrong_index, size, &proof, &root),
                    "proof accepted at a different index: tree_size={size}, original={index}, tested={wrong_index}");
            }
        }
    }
}
