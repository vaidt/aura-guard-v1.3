//! Stage C C5 tests against the production RI-RS Merkle primitives.
//!
//! This integration target is ignored by default because it requires the
//! external draft corpus at AURA_C5_MERKLE_CORPUS. The dedicated C5 workflow
//! supplies that exact file and invokes this target explicitly. Runtime
//! source and production dependency semantics are unchanged.

use aura_guard::merkle::{audit_path, empty_root, leaf_hash, merkle_root, node_hash, verify_audit_path};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: String,
    leaf_payloads_utf8: Vec<String>,
    expected_leaf_hashes_sha256: Vec<String>,
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
    expected_raw_left_payload_sha256: String,
    expected_undomain_separated_node_sha256: String,
}

fn digest_hex(digest: &[u8; 32]) -> String {
    hex::encode(digest)
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

    let raw_left = Sha256::digest(case.left_payload_utf8.as_bytes());
    assert_eq!(hex::encode(raw_left), case.expected_raw_left_payload_sha256);
    assert_ne!(digest_hex(&left), case.expected_raw_left_payload_sha256);

    let undomain_node = Sha256::digest([left.as_slice(), right.as_slice()].concat());
    assert_eq!(hex::encode(undomain_node), case.expected_undomain_separated_node_sha256);
    assert_ne!(digest_hex(&node), case.expected_undomain_separated_node_sha256);

    let expected_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(digest_hex(&empty_root()), expected_empty);
}

#[test]
#[ignore = "requires the external C5 corpus; run explicitly in the Stage C C5 workflow"]
fn c5_tree_roots_and_shape_match_all_fixed_vectors() {
    let corpus = read_corpus();
    let leaves: Vec<[u8; 32]> = corpus.leaf_payloads_utf8.iter()
        .map(|payload| leaf_hash(payload.as_bytes()))
        .collect();
    assert_eq!(corpus.expected_leaf_hashes_sha256.len(), leaves.len());
    assert_eq!(corpus.expected_roots.len(), leaves.len() + 1);

    for (index, (leaf, expected)) in leaves.iter().zip(corpus.expected_leaf_hashes_sha256.iter()).enumerate() {
        assert_eq!(digest_hex(leaf), *expected, "leaf_index={index}");
    }

    for case in corpus.expected_roots {
        assert!(case.tree_size <= leaves.len(), "tree size exceeds corpus payload count");
        let root = merkle_root(&leaves[..case.tree_size]);
        assert_eq!(digest_hex(&root), case.expected_root_sha256, "tree_size={}", case.tree_size);
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
