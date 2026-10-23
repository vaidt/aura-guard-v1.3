use aura_guard::strict_wire::parse_receipt_json;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: String,
    contract: String,
    raw_octets_hex: String,
    valid_receipt_json: String,
    mutations: Vec<Mutation>,
}

#[derive(Debug, Deserialize)]
struct Mutation {
    id: String,
    kind: String,
    find: Option<String>,
    replace: Option<String>,
    wire: Option<String>,
    wire_hex: Option<String>,
    expected: String,
}

fn corpus() -> Corpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance/STAGE-C-C6-BC02.1-WIRE-MUTATIONS-v0.1.json");
    let bytes = fs::read(&path).expect("shared C6 corpus must be available");
    println!("C6_SHARED_CORPUS_SHA256={}", hex::encode(Sha256::digest(&bytes)));
    let corpus: Corpus = serde_json::from_slice(&bytes).expect("shared C6 corpus must parse");
    assert_eq!(corpus.schema, "AURA-STAGE-C6-BC02.1-WIRE-MUTATION-CORPUS/0.1");
    assert_eq!(corpus.contract, "BC-02.1-COMMON-RECEIPT");
    corpus
}

fn apply_mutation(base: &str, case: &Mutation) -> Vec<u8> {
    match case.kind.as_str() {
        "replace" => {
            let find = case.find.as_ref().expect("replace case must define find");
            let replace = case.replace.as_ref().expect("replace case must define replacement");
            assert_eq!(base.matches(find).count(), 1, "{}: replacement target must occur once", case.id);
            base.replacen(find, replace, 1).into_bytes()
        }
        "literal" => case.wire.as_ref().expect("literal case must define wire").as_bytes().to_vec(),
        "hex" => hex::decode(case.wire_hex.as_ref().expect("hex case must define wire_hex"))
            .expect("wire hex in shared corpus must be well-formed"),
        other => panic!("{}: unsupported mutation kind {other}", case.id),
    }
}

#[test]
fn accepts_shared_valid_receipt_and_preserves_raw_octets() {
    let corpus = corpus();
    let parsed = parse_receipt_json(corpus.valid_receipt_json.as_bytes()).expect("shared valid receipt");
    assert_eq!(hex::encode(parsed.raw_octets), corpus.raw_octets_hex);
}

#[test]
fn rejects_every_mutation_in_the_shared_corpus() {
    let corpus = corpus();
    assert_eq!(corpus.mutations.len(), 18);
    for case in &corpus.mutations {
        assert_eq!(case.expected, "REJECT", "{}: unexpected positive disposition", case.id);
        let candidate = apply_mutation(&corpus.valid_receipt_json, case);
        assert!(parse_receipt_json(&candidate).is_err(), "{}: malformed receipt was accepted", case.id);
    }
}
