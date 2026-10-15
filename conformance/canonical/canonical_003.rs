#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! CANONICAL-003 — RI-RS execution against the pinned specification fixture.
//!
//! The fixture is read from a separate checkout of vaidt/aura-specification.
//! This test exercises the existing conformance-only JCS adapter; it does not
//! wire JCS into the production runtime or change any production hash domain.

mod jcs;

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const SPECIFICATION_COMMIT: &str = "b3a6e784d9a6ea2e0b554310e3de80e7d13de859";
const FIXTURE_PATH: &str = "fixtures/corpus/CANONICAL-003_jcs_full_discriminator.json";
const EXPECTED_PATH: &str = "fixtures/corpus/CANONICAL-003_jcs_full_discriminator.expected.jcs";

const EXPECTED_FIXTURE_SHA256: &str =
    "1cde8282d6df99defc16b8652cb0f43a8f327c35b8f356a8612b835ed996ec73";
const EXPECTED_CANONICAL_BYTES: usize = 577;
const EXPECTED_CANONICAL_SHA256: &str =
    "9fb648c388c4485575d25c1d6171ba691fec51c1b433b11f4d61197bbe2a5509";
const EXPECTED_LEAF_SHA256: &str =
    "38672ea2bd0ea87b2446efce8d4ba4adeb822e0baaecee4a54b73179198d2b3e";

fn specification_root() -> PathBuf {
    if let Some(root) = env::var_os("AURA_SPECIFICATION_ROOT") {
        return PathBuf::from(root);
    }

    // Local fallback for sibling checkouts of aura-guard-v1.3 and
    // aura-specification.
    PathBuf::from("../aura-specification")
}

#[test]
fn canonical_003_ri_rs_matches_oracle_bytes_and_hash_domains() {
    let specification_root = specification_root();
    let fixture_path = specification_root.join(FIXTURE_PATH);
    let expected_path = specification_root.join(EXPECTED_PATH);

    let fixture_bytes = fs::read(&fixture_path).unwrap_or_else(|error| {
        panic!(
            "Cannot read specification fixture at {} (set AURA_SPECIFICATION_ROOT): {error}",
            fixture_path.display()
        )
    });

    let fixture_sha256 = hex::encode(Sha256::digest(&fixture_bytes));
    assert_eq!(
        fixture_sha256, EXPECTED_FIXTURE_SHA256,
        "the specification fixture bytes changed from the pinned CANONICAL-003 input"
    );

    let fixture: Value =
        serde_json::from_slice(&fixture_bytes).expect("CANONICAL-003 fixture must be valid JSON");
    let protocol_object = fixture
        .get("protocol_object")
        .expect("CANONICAL-003 must contain /protocol_object");

    // Execute the Rust JCS adapter on the actual object from the specification
    // repository. Metadata around protocol_object is intentionally excluded.
    let actual = jcs::canonical_bytes(protocol_object)
        .expect("the Rust JCS adapter must serialize /protocol_object");

    let expected = fs::read(&expected_path).unwrap_or_else(|error| {
        panic!(
            "Cannot read Oracle expected bytes at {}: {error}",
            expected_path.display()
        )
    });

    assert_eq!(
        expected.len(),
        EXPECTED_CANONICAL_BYTES,
        "the expected JCS artifact must be exactly 577 bytes"
    );
    assert!(
        !expected.ends_with(b"\n"),
        "the expected JCS artifact must not have a trailing LF"
    );

    assert_eq!(
        actual.len(),
        EXPECTED_CANONICAL_BYTES,
        "RI-RS canonical byte length differs from the Oracle"
    );
    assert_eq!(
        actual, expected,
        "RI-RS canonical bytes differ byte-for-byte from the specification Oracle artifact"
    );

    let canonical_sha256 = hex::encode(Sha256::digest(&actual));
    assert_eq!(
        canonical_sha256, EXPECTED_CANONICAL_SHA256,
        "SHA-256(canonical_bytes) differs from the Oracle"
    );

    // RFC 6962 leaf domain: SHA-256(raw 0x00 octet || exact canonical bytes).
    let mut leaf_preimage = Vec::with_capacity(1 + actual.len());
    leaf_preimage.push(0x00);
    leaf_preimage.extend_from_slice(&actual);
    assert_eq!(leaf_preimage[0], 0x00);
    assert_eq!(&leaf_preimage[1..], actual.as_slice());

    let leaf_sha256 = hex::encode(Sha256::digest(&leaf_preimage));
    assert_eq!(
        leaf_sha256, EXPECTED_LEAF_SHA256,
        "RFC 6962 leaf SHA-256 differs from the Oracle"
    );

    println!("CANONICAL-003 specification commit = {SPECIFICATION_COMMIT}");
    println!("CANONICAL-003 fixture path          = {}", fixture_path.display());
    println!("CANONICAL-003 fixture SHA-256       = {fixture_sha256}");
    println!("CANONICAL-003 canonical byte length = {}", actual.len());
    println!(
        "CANONICAL-003 canonical UTF-8       = {}",
        String::from_utf8_lossy(&actual)
    );
    println!("CANONICAL-003 canonical SHA-256     = {canonical_sha256}");
    println!("CANONICAL-003 RFC6962 leaf SHA-256  = {leaf_sha256}");
}
