# AURA Guard — deterministic DER negative corpus

**Status:** test-only draft work. Not a protocol change, release decision, or governance ratification.

## Purpose

Provide deterministic malformed-encoding tests for the strict RFC 3161 verifier before the ECC dependency migration. The generator derives cases from the existing FreeTSA TSR fixtures; it does not call the network or generate new signing keys.

## Baseline integrity

The following SHA-256 values were computed from the fixture files copied from the supplied source archive and were independently matched to the current GitHub main path using Git blob SHA-1 values.

| Fixture | Bytes | SHA-256 | Git blob SHA-1 |
|---|---:|---|---|
| segment-001.tsr | 4632 | 5237ca7c8b2c989a058055bc386b8b6eac0a74ff1476dfc7f7c2799fe2f185cc | 0b05fb6fab2ddb66444ae143715a97349fb41447 |
| segment-002.tsr | 4632 | a9927143b09469761504df56a7ce2068ed59dc10d03b4be467c3b1c02f81f42f | 62377f87703a97d6fa2b94371d8fe470cd404007 |
| segment-001.manifest.json | 585 | faf51548478cf086762c40c4eecd31b1d71f54282f89fd8a7c9f4f4f6c8793ed | 8c45209f9bc6b63819044ecf6a4d79a32708623a |
| segment-002.manifest.json | 649 | 8094eca8364f8447fbe90503a72545ef8e7c47f2660c5b44c443bcfdd39ad67f | a4a411bbd42d83c5021837c9a9f3611bda59df6b |

These are per-file identities, not a signed attestation of a particular commit. The test must continue to verify the fixture bytes through the manifest hashes.

## Generator and corpus

The Python generator parses a baseline DER value, applies deterministic mutations, checks that its own DER parser rejects each mutated value, writes the byte strings and SHA-256 values into a manifest, and exits non-zero if a generated mutation remains valid according to that checker.

The initial version creates 10 cases for each of two sources (20 total):

- final-byte truncation and half-input truncation;
- trailing octet after the top-level value;
- top-level length overrun and underrun;
- non-minimal nested length form;
- nested TLV length overrun;
- unterminated OBJECT IDENTIFIER subidentifier;
- invalid BIT STRING unused-bits count;
- redundant INTEGER sign octets.

The manifest includes target_bytes_base64, target_sha256, the source fixture hash, the SHA-256 message imprint derived from the paired segment manifest, and the expected disposition REJECT. This makes the inputs reproducible without committing 20 separate binary files.

## What the tests prove — and what they do not

The Python suite proves generator repeatability, hash binding, and rejection by the harness DER checker. It does **not** prove that the production Guard verifier rejects those inputs.

The Rust integration test regenerates the corpus into a temporary directory, decodes each input, validates its SHA-256, computes the correct expected message imprint from the paired manifest, and calls the production verify_tsr() implementation with the existing pinned root. The test fails if any malformed input is accepted. The Rust integration test invokes python3, so CI must provide Python 3.

Commands to run:

    python3 -m unittest tools.crypto_regression.test_generate_der_mutations -v
    cargo test --test tst_der_mutations
    cargo test --test tst_verify

## Scope limits

This DER corpus does not prove ECDSA P-256/P-384 high-S/low-S semantics, SEC1 invalid-point rejection, or constant-time arithmetic. Those need a separate, independently sourced cryptographic vector set.

The crypto-bigint advisory states that versions before 0.7.6 have timing variability in operations intended to be constant-time, and identifies 0.7.6 as the fixed line. The upstream advisory also describes BINSEC-based checks using cargo checkct; functional tests alone are not side-channel proof: https://rustsec.org/advisories/RUSTSEC-2026-0387.html

No dependency, protocol, deny.toml, or governance state is changed by this test-only proposal. Do not merge until the production Rust test passes in CI. A successful run is technical evidence only; it does not unblock M1, G0, G1, or P-008.
