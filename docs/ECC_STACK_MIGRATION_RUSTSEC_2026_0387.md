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

The final candidate `Cargo.lock` was produced by Cargo in a temporary, branch-scoped resolver workflow, reviewed as a minimal dependency delta, committed, and read back byte-for-byte. Lockfile SHA-256:
`9ac7d3f54bee3d050603be6ad7338ebd15ff5c63009074a81298487ceeca481d` (80,264 bytes).

The exact set of package version changes in the security delta was limited to:
- `rustls-webpki 0.103.15 -> 0.103.16`;
- `webpki-roots 1.0.7 -> 1.0.10`;
- `tokio 1.52.3 -> 1.54.1`.

The reviewed candidate resolves `crypto-bigint 0.7.7`, `elliptic-curve 0.14.2`, `ecdsa 0.17.0`, `p256 0.14.0`, `p384 0.14.0`, and `sha2 0.11.0`; it has no `crypto-bigint 0.5.x`, `rustls-webpki 0.103.15`, `webpki-roots 1.0.7`, or `tokio 1.52.3`. The temporary lockfile resolver has been removed from the branch.

## Semantics gate

The baseline test expects the valid and invalid Wycheproof results to match the pinned upstream corpus. During candidate testing, do not rewrite these expected results merely to obtain a green build.

The high-S/low-S probes record the current baseline behavior. Upstream `ecdsa 0.17.0` rejects high-S only when the curve's `EcdsaCurve::NORMALIZE_S` setting is true. The pinned `p256 0.14.0` and `p384 0.14.0` sources set `NORMALIZE_S = false`; therefore a behavioral change is a hypothesis to verify in the candidate, not an assumption. The candidate must execute the same vectors and report the observed outcome.

The test module also has two audit-focused tests that explicitly name and execute scalar-boundary cases from the pinned corpus for each curve: zero `r`, zero `s`, `r > n`, `s > n`, `s = 1`, and near-order cases. They call the production `verify_ecdsa()` helper, assert the upstream expected disposition, and fail if a required vector comment disappears from the pinned file.

## Mandatory verification sequence

1. Generate and review the dependency lockfile; verify the selected `crypto-bigint` version is at least 0.7.6.
2. Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and the full `cargo test --locked --all-targets`.
3. Require all 988 Wycheproof vectors and both high-S/low-S pairs to pass according to recorded baseline expectations, or stop and produce an exact baseline/candidate difference report.
4. Require `cargo audit --deny warnings` and `cargo deny check` to pass without adding advisory exceptions. On the candidate lockfile, both checks have passed in CI using the repository's pre-existing, documented `RUSTSEC-2023-0071` exception only; the three additional October 2026 findings are removed by the reviewed lock delta.
5. Run the added upstream BINSEC gate: `.github/workflows/constant-time-regression.yml` checks out `RustCrypto/crypto-bigint` at exact commit `f17d82ad761de4140c6c22f835ddaead1a434f57` (v0.7.7) and uses `Ledger-Donjon/cargo-checkct` pinned to `85271e5ce9eab9ba895c62c8b5d4129810a635a0`. It runs the upstream `checkct` harness with `control-flow,memory-access`, `skip-unknown=false`, and all-leaks reporting. The upstream harness targets `riscv32imac-unknown-none-elf`, `thumbv6m-none-eabi`, `thumbv7em-none-eabihf`, and `x86_64-unknown-linux-gnu`.
6. Interpret the BINSEC result within its documented limits. The upstream tool analyzes the `no_std` crypto-bigint harness, not the complete AURA process; control-flow and memory-access checks assume data-independent instruction latency. It does not directly prove the full Guard verifier constant-time, and it does not cover AURA's x86_64/aarch64 output determinism. Additional arithmetic-operation checks (`multiplication`, `dividend`, `divisor`) are documented as experimental by the tool and are not silently treated as covered by this workflow. See https://github.com/Ledger-Donjon/cargo-checkct and the advisory https://rustsec.org/advisories/RUSTSEC-2026-0387.html.
7. Compare release-mode outputs and canonical audit bytes on x86_64 and aarch64. The ECDSA verifier is a public-key verification path; do not claim CPU-specific arithmetic is deterministic until the cross-target replay evidence says so.
8. Run strict-wire only after the source SHA and lockfile digest are frozen; verify artifacts independently.

## Security gate status

The original baseline had four findings relevant to this work: RUSTSEC-2026-0387 (`crypto-bigint`), RUSTSEC-2026-0382 (`rustls-webpki`), RUSTSEC-2026-0381 (`webpki-roots`), and RUSTSEC-2026-0386 (`tokio`). All four dependency-version findings are addressed in this candidate lockfile without editing `deny.toml` or adding ignores. CI reports `cargo-audit` and `cargo-deny` as PASS on the updated candidate commit. The full build/test and upstream BINSEC gate remain separately tracked; no constant-time or release-readiness claim is made until their final results are recorded.

## Governance boundary

This PR is an engineering candidate only. No merge is authorized by the existence of this patch. M1, G0, G1, and P-008 remain unchanged. A green ECC regression suite does not authorize any normative change to AURA's signature acceptance policy.
