//! CK-003 / DQ-002 reference checks for the Rust RI-RS Merkle implementation.

use std::error::Error;
use std::io;

use aura_guard::merkle::{leaf_hash, node_hash};

fn decode_hex(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes = hex::decode(s)?;
    let digest = bytes.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture digest must be 32 bytes",
        )
    })?;
    Ok(digest)
}

#[test]
fn ri_rs_matches_ck003_dq002_fixture() -> Result<(), Box<dyn Error>> {
    let canonical = b"agent_id=MACHINE_ACCOUNT_001|ari=95000|drift=5000|ts=2026-01-01T00:00:00Z";
    let expected_leaf =
        decode_hex("f7acc9aaf8937e3bdc02a2d39ac661a742343abcd3d4a76807a2f1585a158e4b")?;
    let expected_node =
        decode_hex("1b3ff765c9dc0659880dff1f051ee4c22b9476a6275dcf3b2437f9e1feec9dd6")?;

    let leaf = leaf_hash(canonical);
    assert_eq!(
        leaf, expected_leaf,
        "RI-RS leaf hash diverges from CK-003 fixture"
    );

    let node = node_hash(&leaf, &leaf);
    assert_eq!(
        node, expected_node,
        "RI-RS node hash diverges from CK-003 fixture"
    );
    Ok(())
}
