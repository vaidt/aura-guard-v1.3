# AURA Guard — ECC stack migration plan for RUSTSEC-2026-0387

**Status: isolated draft migration branch. Not release authorization and not a governance amendment.**

## Baseline evidence

The stacked baseline branch contains the full pinned C2SP/Wycheproof ECDSA suite:
- P-256/SHA-256: 484 test vectors (174 upstream-valid, 310 upstream-invalid).
- P-384/SHA-384: 504 test vectors (194 upstream-valid, 310 upstream-invalid).
- Explicit high-S/low-S equivalent signature pair for each curve.

The recorded baseline run passed all three tests. The ECDSA corpus is test-only and invokes the actual production `verify_ecdsa()` helper. The source vectors and upstream Apache-2.0 license are pinned in `tests/fixtures/crypto-regression/wycheproof`.

## Candidate dependency change

This branch changes:
- `p256 = 0.14.0`
- `p384 = 0.14.0`
- direct `ecdsa = 0.17.0`
- the declared minimum supported Rust version from 1.86 to 1.87, with functional CI pins updated to 1.87.

**Why the MSRV change is necessary:** the upstream `crypto-bigint 0.7.6` manifest declares `rust-version = "1.87"`; the Rust-1.86-compatible resolver therefore selected `crypto-bigint 0.7.5`, which remains inside the vulnerable range. Keeping Rust 1.86 while claiming RUSTSEC-2026-0387 is fixed would be false. The MSRV change is explicit in Cargo.toml, README and CI and remains subject to compatibility review. The resolver uses Cargo's incompatible-Rust-version fallback so dependencies requiring Rust 1.88 (notably `sha2 0.11.1`) should be kept at an MSRV-compatible release such as `sha2 0.11.0`; the lockfile must prove the final choice.

The direct `signature = 2` dependency is intentionally retained because the existing RSA verifier uses the `signature 2` trait ecosystem. The ECDSA curve APIs re-export their corresponding `signature 3` prehash trait, which is imported locally in the relevant P-256/P-384 verification branches.

The exact lockfile is not accepted from a guessed or hand-edited dependency graph. A branch-scoped resolver workflow runs `cargo update` for the ECC stack with `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`, then asserts that `crypto-bigint 0.7.6` is present and `crypto-bigint 0.5.5` is absent. It publishes the resulting Cargo.lock as a short-lived artifact for review. The artifact must be checked for:
- exact package versions and checksums;
- no remaining `crypto-bigint 0.5.x` in the resolved graph;
- no unexpected unrelated upgrades;
- the entire ECDSA dependency path resolving to `crypto-bigint >= 0.7.6`;
- no dependency that forces Rust 1.88 when the documented MSRV remains 1.87.

The resolver workflow is temporary tooling and must be removed from the final PR after the lockfile is recovered and reviewed. It does not push commits or mutate the branch.

## Semantics gate

The baseline test expects the valid and invalid Wycheproof results to match the pinned upstream corpus. During candidate testing, do not rewrite these expected results merely to obtain a green build.

The high-S/low-S probes record the current baseline behavior. Upstream `ecdsa 0.17.0` rejects high-S only when the curve's `EcdsaCurve::NORMALIZE_S` setting is true. The pinned `p256 0.14.0` and `p384 0.14.0` sources set `NORMALIZE_S = false`; therefore a behavioral change is a hypothesis to verify in the candidate, not an assumption. The candidate must execute the same vectors and report the observed outcome.

## Mandatory verification sequence

1. Generate and review the dependency lockfile; verify the selected `crypto-bigint` version is at least 0.7.6.
2. Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and the full `cargo test --locked --all-targets`.
3. Require all 988 Wycheproof vectors and both high-S/low-S pairs to pass according to recorded baseline expectations, or stop and produce an exact baseline/candidate difference report.
4. Run `cargo audit --deny warnings` and `cargo deny check` without advisory suppressions. These currently fail on other advisories too (`rustls-webpki`, `webpki-roots`, and `tokio`), so their results must be reported separately from the ECC migration.
5. Execute the upstream constant-time regression approach documented by RUSTSEC-2026-0387, including `cargo checkct`/BINSEC on the targets supported by that tooling. Record tool versions, target details, stdout/stderr, and limitations. A passing functional test suite is not proof of constant-time behavior.
6. Compare release-mode outputs and canonical audit bytes on x86_64 and aarch64. The ECDSA verifier is a public-key verification path; do not claim CPU-specific arithmetic is deterministic until the cross-target replay evidence says so.
7. Run strict-wire only after the source SHA and lockfile digest are frozen; verify artifacts independently.

## Known separate blockers

The October 24 baseline audit reports:
- RUSTSEC-2026-0387: `crypto-bigint 0.5.5`, fixed in `>=0.7.6`;
- RUSTSEC-2026-0382: `rustls-webpki 0.103.15`, fixed in `>=0.103.16`;
- RUSTSEC-2026-0381: `webpki-roots 1.0.7`, fixed in `>=1.0.10`;
- RUSTSEC-2026-0386: `tokio 1.52.3`, unsoundness advisory.

These are not to be ignored or suppressed. Resolving the ECC advisory may remove only the first finding; Guard remains blocked until the other findings are handled by separately reviewed dependency updates.

## Governance boundary

This PR is an engineering candidate only. No merge is authorized by the existence of this patch. M1, G0, G1, and P-008 remain unchanged. A green ECC regression suite does not authorize any normative change to AURA's signature acceptance policy.
