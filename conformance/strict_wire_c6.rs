use aura_guard::strict_wire::parse_receipt_json;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::json;
use sha2::{Digest, Sha256};

fn good() -> Vec<u8> {
    let raw = [0x43, 0x36, 0x00, 0xfe, 0xff];
    let digest = Sha256::digest(raw).iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(r#"{{"adapter":{{"adapter_id":"adapter","adapter_version":"1"}},"environment":{{"environment_id":"env","platform":"linux","runtime":"rust"}},"fixture":{{"fixture_artifact_identity":"fixture.bin","fixture_id":"FIX-C6"}},"handoff":{{"method":"local","status":"TRANSFERRED"}},"received":{{"octet_length":5,"raw_octets":"{}","recomputed_sha256":"{}"}},"receiver":{{"implementation_id":"impl","implementation_version":"1","language":"Rust","receiver_id":"RI-RS","source_commit":"abc"}},"schema_id":"BC-02.1-COMMON-RECEIPT","schema_version":1}}"#, B64.encode(raw), digest).into_bytes()
}
fn rejects(bytes: &[u8]) -> bool { parse_receipt_json(bytes).is_err() }

#[test]
fn accepts_valid_and_preserves_opaque_non_utf8_octets() {
    let parsed = parse_receipt_json(&good()).expect("valid BC-02.1 receipt");
    assert_eq!(parsed.raw_octets, vec![0x43, 0x36, 0, 0xfe, 0xff]);
}

#[test]
fn rejects_unknown_authority_status_length_hash_and_base64_mutations() {
    let base = String::from_utf8(good()).unwrap();
    let cases = [
      base.replace(r#""schema_id":"BC-02.1-COMMON-RECEIPT""#, r#""conformance_result":"PASS","schema_id":"BC-02.1-COMMON-RECEIPT""#),
      base.replace(r#""adapter_id":"adapter""#, r#""extension":"x","adapter_id":"adapter""#),
      base.replace(r#""status":"TRANSFERRED""#, r#""status":"PASS""#),
      base.replace(r#""octet_length":5"#, r#""octet_length":true"#),
      base.replace(r#""octet_length":5"#, r#""octet_length":4"#),
      base.replace(r#""raw_octets":"QzYA/v8=""#, r#""raw_octets":"%%%""#),
    ];
    for (i, item) in cases.iter().enumerate() { assert!(rejects(item.as_bytes()), "case {i} accepted"); }
}

#[test]
fn rejects_duplicate_keys_top_and_nested() {
    let base = String::from_utf8(good()).unwrap();
    let top = base.replace(r#""schema_id":"BC-02.1-COMMON-RECEIPT""#, r#""schema_id":"bad","schema_id":"BC-02.1-COMMON-RECEIPT""#);
    let nested = base.replace(r#""method":"local""#, r#""method":"local","method":"other""#);
    assert!(rejects(top.as_bytes()));
    assert!(rejects(nested.as_bytes()));
}

#[test]
fn rejects_malformed_json_envelope() {
    assert!(rejects(b"{"));
    assert!(rejects(&[0xff, 0xfe]));
}
