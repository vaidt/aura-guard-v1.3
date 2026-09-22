# D1_V02_V03_RI_RS_EXECUTION_DISPOSITION

## A. Environment

- rustc: `rustc 1.98.1 (48a229cea 2026-09-01)`
- cargo: `cargo 1.98.1 (797e8a9bc 2026-08-05)`
- active toolchain: `stable-x86_64-unknown-linux-gnu (default)`
- OS: `Linux runnervmlun5p 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`
- repository: `/home/runner/work/aura-guard-v1.3/aura-guard-v1.3`
- HEAD: `35082d7b4880dad780fb55a1a5f3ac0ef4322674`
- git status --short (captured before artifact creation): `?? D1_V02_V03_RI_RS_RAW_EXECUTION.log`
- dependency version: `0.3.2` (required `0.3.2`; verification output: `├── serde_json_canonicalizer v0.3.2`)

## Interpretation boundaries

- AS-IS / SPECIFICATION / TO-BE / RESULT are preserved as distinct categories.
- EXISTS ≠ REACHABLE ≠ CURRENT ≠ AUTHORITATIVE ≠ NORMATIVE ≠ EFFECTIVE.
- EXHAUSTED ≠ RESOLVED.
- This run is technical evidence only; it does not ratify, authorize, or change governance state.

## D1-V02

- RI-RS status: `EXECUTION_NOT_AVAILABLE`
- input: `{"é":1,"z":2,"😀":3,"ﬀ":4}`
- input_sha256: `bab5b288c44fe005acb0d0e4818374014211f42ebb827d7c1ad3fa5d4c86e3f2`
- execution error: `failed to parse Rust output JSON: Expecting value: line 1 column 1 (char 0)`
- RI-PY reference:
  - canonical_bytes_len: `31`
  - canonical_bytes_utf8: `{"z":2,"é":1,"😀":3,"ﬀ":4}`
  - canonical_bytes_hex: `7b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`
  - sha256_canonical_bytes: `25923e60a4925e624410384f0acd91615434406b590cdf2782c86adf3230bc4d`
  - leaf_preimage_hex: `007b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`
  - leaf_preimage_len: `32`
  - leaf_sha256: `aceeb8e4c88a30d4cd35d12da58e3023a63bb13b11c0ef266b8d743f2236cc4f`
  - naive_sorted_json_utf8: `{"z":2,"é":1,"ﬀ":4,"😀":3}`
  - naive_equal_to_jcs: `false`
- Field-by-field comparison:
  - canonical_bytes_len: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `31`)
  - canonical_bytes_utf8: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `{"z":2,"é":1,"😀":3,"ﬀ":4}`)
  - canonical_bytes_hex: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `7b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`)
  - sha256_canonical_bytes: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `25923e60a4925e624410384f0acd91615434406b590cdf2782c86adf3230bc4d`)
  - leaf_preimage_hex: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `007b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`)
  - leaf_preimage_len: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `32`)
  - leaf_sha256: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `aceeb8e4c88a30d4cd35d12da58e3023a63bb13b11c0ef266b8d743f2236cc4f`)
- Vector result: `NOT COMPARABLE`

## D1-V03

- RI-RS status: `EXECUTION_NOT_AVAILABLE`
- input: `{"a":-0.0}`
- input_sha256: `952b7dc455870c265da6a6fb15ef60891abf562f0e3327f095914610b3d00811`
- execution error: `failed to parse Rust output JSON: Expecting value: line 1 column 1 (char 0)`
- RI-PY reference:
  - canonical_bytes_len: `7`
  - canonical_bytes_utf8: `{"a":0}`
  - canonical_bytes_hex: `7b2261223a307d`
  - sha256_canonical_bytes: `45b619e97b5d9b029af4522e9ffb02fa99ff2bf226c82ee22a7cc10269a557e8`
  - leaf_preimage_hex: `007b2261223a307d`
  - leaf_preimage_len: `8`
  - leaf_sha256: `94f89ffdde40b0f7deace6ae4b5f614641e970da2cff10639b159f7749e87dd6`
  - naive_sorted_json_utf8: `{"a":-0.0}`
  - naive_equal_to_jcs: `false`
- Field-by-field comparison:
  - canonical_bytes_len: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `7`)
  - canonical_bytes_utf8: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `{"a":0}`)
  - canonical_bytes_hex: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `7b2261223a307d`)
  - sha256_canonical_bytes: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `45b619e97b5d9b029af4522e9ffb02fa99ff2bf226c82ee22a7cc10269a557e8`)
  - leaf_preimage_hex: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `007b2261223a307d`)
  - leaf_preimage_len: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `8`)
  - leaf_sha256: `EXECUTION_NOT_AVAILABLE` (RI-RS: `None` | RI-PY: `94f89ffdde40b0f7deace6ae4b5f614641e970da2cff10639b159f7749e87dd6`)
- Vector result: `NOT COMPARABLE`

## D. Cross-Language Agreement

- Status: `NOT ESTABLISHED`

## E. D1 Phase 2 status

- Status: `PARTIAL`

## Governance / normative preservation

- M1: `OPEN / BLOCKED`
- G0: `OPEN / BLOCKED`
- P-001 / P-002 / P-003 / P-008: `PROPOSED / NOT RATIFIED`
- DQ-003: `OPEN`
- DQ-006: `OPEN`
- Implementation Authorization: `NOT GRANTED`
- Normative Effect: `NONE`
- Governance changes: `NONE`

## Evidence artifacts

- Raw execution log: `/home/runner/work/aura-guard-v1.3/aura-guard-v1.3/D1_V02_V03_RI_RS_RAW_EXECUTION.log`
- Evidence JSON: `/home/runner/work/aura-guard-v1.3/aura-guard-v1.3/D1_V02_V03_RI_RS_RAW_EXECUTION_EVIDENCE.json`
- Evidence JSON SHA-256: `703a1d107a1347b7a5268776b60896508cfeb7a1f9ad34014fe15ab5c4a0f84c`

