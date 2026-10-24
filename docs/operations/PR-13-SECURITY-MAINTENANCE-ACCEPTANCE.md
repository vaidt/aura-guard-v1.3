# PR #13 — Security Dependency Maintenance Acceptance

**Status:** Review checklist, non-normative. This file does not merge or approve PR #13.
**Target PR:** https://github.com/vaidt/aura-guard-v1.3/pull/13
**Expected reviewed head:** `dd08cf46677153295511b2691e3da0aea5d13c25` (re-read before use).

## Scope observed in the current report

The change should remain limited to `Cargo.lock`, with the reported upgrades to rustls-webpki, webpki-roots, and Tokio. Any scope expansion requires renewed review.

## Acceptance checklist

- [ ] Re-read PR state, exact head SHA, base SHA, changed-file list, and full diff.
- [ ] Confirm the change is lockfile-only and no audit/deny exceptions were added.
- [ ] Verify lockfile package versions and checksums against the source registry for the exact committed graph.
- [ ] Confirm `cargo-audit` passes for the exact PR head without newly suppressed advisories.
- [ ] Confirm `cargo-deny` passes for the exact PR head with existing policy intact.
- [ ] Confirm `cargo build --locked --release --all-targets` passes.
- [ ] Confirm `cargo test --locked --all-targets` and required integration/E2E/conformance jobs pass.
- [ ] Confirm SBOM corresponds to the exact head and its resolved dependency graph.
- [ ] Obtain independent review; do not treat the author’s own CI as independent review.
- [ ] Confirm effective `main` protections and required checks before any merge decision.
- [ ] After any authorized merge, record merge SHA and new `main` SHA, inspect the resulting diff, and re-run mandatory security/build/test checks on that SHA.
- [ ] Revalidate dependent experimental PRs against the updated base; do not transfer prior green status.

## Fail-closed conditions

Leave the PR open and do not promote if the head changed without rerun, any required job is missing/skipped, advisory exceptions changed, lockfile provenance is unclear, independent review is absent, or branch protection is not effective.

## Explicit non-effects

This maintenance PR does not establish CANONICAL-003 full conformance, close DQ-006/CONF-003/C6, ratify P-008, establish M1/G1, or authorize release.
