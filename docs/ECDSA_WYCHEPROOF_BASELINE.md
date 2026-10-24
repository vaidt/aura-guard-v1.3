# AURA Guard — ECDSA baseline and low-S migration gate

**Status:** Draft test evidence; not a protocol-specification change and not a governance decision.

## Scope

This patch introduces full, pinned C2SP/Wycheproof ECDSA verification vectors for the two NIST curves used by the strict timestamp verifier:
- P-256 with SHA-256: 484 cases (174 upstream-valid, 310 upstream-invalid).
- P-384 with SHA-384: 504 cases (194 upstream-valid, 310 upstream-invalid).

The source data is copied verbatim from C2SP/Wycheproof commit
`d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`. The upstream blob IDs and Apache 2.0 license are preserved next to the fixtures. The vector files remain test-only; they are not loaded at runtime.

The tests are located in a `#[cfg(test)]` module within `src/tst_verify.rs`. This permits calling the exact production helper `verify_ecdsa()` without widening its visibility or changing runtime code. Every test vector is passed through the current production verification path, not a parallel test-only verifier.

## Current dependency baseline

The pinned `main` lockfile observed when this branch was created contains:
- `crypto-bigint 0.5.5`
- `elliptic-curve 0.13.8`
- `ecdsa 0.16.9`
- `p256 0.13.2`
- `p384 0.13.1`
- `signature 2.2.0`

The corresponding lockfile blob SHA-1 was `20e1751ac062c84732e82885ce97fdcca5b5bd70`. This documents the base dependency state; it is not a signed attestation.

## Explicit high-S / low-S probe

A separate fixture, `tests/fixtures/crypto-regression/ecdsa-high-low-s.json`, is derived deterministically from Wycheproof P-256 and P-384 test case 1 in each pinned source file. For each valid base signature, it preserves (r) and constructs (s_{low}=min(s,n-s)) and (s_{high}=max(s,n-s)), where (n) is the order of the curve. The two variants are mathematically equivalent ECDSA signatures for the same message and key.

The accompanying baseline test expects both variants to verify under the pre-migration verifier. That expectation is deliberate: this commit measures current behavior and is not an assertion that AURA's normative protocol must always accept high-S signatures.

The source for the current `ecdsa 0.16.9` implementation's `verify_prehashed` path performs the ECDSA equation check without a low-S check. In `ecdsa 0.17.0`, the upstream implementation includes a high-S rejection when `C::NORMALIZE_S` is set. Thus, moving to `p256/p384 0.14` and `ecdsa 0.17` can change externally observable verification behavior. This must be documented as a semantic delta, not disguised as a routine dependency-only upgrade.

Upstream references:
- Wycheproof project and test-vector methodology: https://github.com/C2SP/wycheproof
- Pinned P-256 vectors: https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp256r1_sha256_test.json
- Pinned P-384 vectors: https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp384r1_sha384_test.json
- ecdsa 0.17.0 changelog (low-S validation moved into `verify_prehashed`, plus upstream API/dependency changes): https://docs.rs/crate/ecdsa/0.17.0/source/CHANGELOG.md
- RUSTSEC-2026-0387 and fixed `crypto-bigint >= 0.7.6`: https://rustsec.org/advisories/RUSTSEC-2026-0387.html

## Required result

On the current dependency baseline, all 988 original test vectors and both equivalent-signature pairs must match the recorded expectations. If a test fails, do not weaken assertions: record the exact curve, source test ID, expected status, and actual result, then investigate.

During the separate ECC migration, rerun this exact corpus and compare results against the baseline. Any high-S acceptance change must appear in a dedicated baseline/candidate comparison and be resolved against the authoritative AURA contract. Do not silently flip expected values only to make CI green.

## Out of scope

This patch does not update dependencies, modify `deny.toml`, suppress advisories, claim a constant-time proof, or resolve RUSTSEC-2026-0387. It does not change protocol serialization or authorize release/governance states. The DER negative corpus remains in Draft PR #23; this is an independent ECDSA baseline branch.
