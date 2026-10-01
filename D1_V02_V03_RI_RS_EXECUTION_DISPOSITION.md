# D1_V02_V03_RI_RS_EXECUTION_DISPOSITION

## A. Environment

- rustc: `rustc 1.98.1 (48a229cea 2026-09-01)`
- cargo: `cargo 1.98.1 (797e8a9bc 2026-08-05)`
- active toolchain: `stable-x86_64-unknown-linux-gnu (default)`
- OS: `Linux runnervmlun5p 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux`
- repository: `/home/runner/work/aura-guard-v1.3/aura-guard-v1.3`
- HEAD: `35082d7b4880dad780fb55a1a5f3ac0ef4322674`
- git status --short (captured command output): `?? D1_V02_V03_RI_RS_RAW_EXECUTION.log`
- dependency version: `0.3.2` (required `0.3.2`; verification output: `├── serde_json_canonicalizer v0.3.2`)

## Interpretation boundaries

- AS-IS / SPECIFICATION / TO-BE / RESULT are preserved as distinct categories.
- EXISTS ≠ REACHABLE ≠ CURRENT ≠ AUTHORITATIVE ≠ NORMATIVE ≠ EFFECTIVE.
- EXHAUSTED ≠ RESOLVED.
- Failed attempts are preserved in the raw execution log; they are not evidence of successful execution.
- This run is technical evidence only; it does not ratify, authorize, or change governance state.

## Failed attempts preserved

- Initial isolated harness compile failed with Rust borrow checker error `E0505`; raw log preserved the exact compiler output.
- Subsequent isolated harness execution succeeded and produced the RI-RS values reported below.

## D1-V02

- RI-RS status: `EXECUTED`
- input: `{"é":1,"z":2,"😀":3,"ﬀ":4}`
- input_sha256: `bab5b288c44fe005acb0d0e4818374014211f42ebb827d7c1ad3fa5d4c86e3f2`
- RI-RS canonical_bytes_len: `31`
- RI-RS canonical_bytes_utf8: `{"z":2,"é":1,"😀":3,"ﬀ":4}`
- RI-RS canonical_bytes_hex: `7b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`
- RI-RS sha256_canonical_bytes: `25923e60a4925e624410384f0acd91615434406b590cdf2782c86adf3230bc4d`
- RI-RS leaf_preimage_hex: `007b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`
- RI-RS leaf_preimage_len: `32`
- RI-RS leaf_sha256: `aceeb8e4c88a30d4cd35d12da58e3023a63bb13b11c0ef266b8d743f2236cc4f`
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
  - canonical_bytes_len: `MATCH` (RI-RS: `31` | RI-PY: `31`)
  - canonical_bytes_utf8: `MATCH` (RI-RS: `{"z":2,"é":1,"😀":3,"ﬀ":4}` | RI-PY: `{"z":2,"é":1,"😀":3,"ﬀ":4}`)
  - canonical_bytes_hex: `MATCH` (RI-RS: `7b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d` | RI-PY: `7b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`)
  - sha256_canonical_bytes: `MATCH` (RI-RS: `25923e60a4925e624410384f0acd91615434406b590cdf2782c86adf3230bc4d` | RI-PY: `25923e60a4925e624410384f0acd91615434406b590cdf2782c86adf3230bc4d`)
  - leaf_preimage_hex: `MATCH` (RI-RS: `007b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d` | RI-PY: `007b227a223a322c22c3a9223a312c22f09f9880223a332c22efac80223a347d`)
  - leaf_preimage_len: `MATCH` (RI-RS: `32` | RI-PY: `32`)
  - leaf_sha256: `MATCH` (RI-RS: `aceeb8e4c88a30d4cd35d12da58e3023a63bb13b11c0ef266b8d743f2236cc4f` | RI-PY: `aceeb8e4c88a30d4cd35d12da58e3023a63bb13b11c0ef266b8d743f2236cc4f`)
- Vector result: `MATCH`

## D1-V03

- RI-RS status: `EXECUTED`
- input: `{"a":-0.0}`
- input_sha256: `952b7dc455870c265da6a6fb15ef60891abf562f0e3327f095914610b3d00811`
- RI-RS canonical_bytes_len: `7`
- RI-RS canonical_bytes_utf8: `{"a":0}`
- RI-RS canonical_bytes_hex: `7b2261223a307d`
- RI-RS sha256_canonical_bytes: `45b619e97b5d9b029af4522e9ffb02fa99ff2bf226c82ee22a7cc10269a557e8`
- RI-RS leaf_preimage_hex: `007b2261223a307d`
- RI-RS leaf_preimage_len: `8`
- RI-RS leaf_sha256: `94f89ffdde40b0f7deace6ae4b5f614641e970da2cff10639b159f7749e87dd6`
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
  - canonical_bytes_len: `MATCH` (RI-RS: `7` | RI-PY: `7`)
  - canonical_bytes_utf8: `MATCH` (RI-RS: `{"a":0}` | RI-PY: `{"a":0}`)
  - canonical_bytes_hex: `MATCH` (RI-RS: `7b2261223a307d` | RI-PY: `7b2261223a307d`)
  - sha256_canonical_bytes: `MATCH` (RI-RS: `45b619e97b5d9b029af4522e9ffb02fa99ff2bf226c82ee22a7cc10269a557e8` | RI-PY: `45b619e97b5d9b029af4522e9ffb02fa99ff2bf226c82ee22a7cc10269a557e8`)
  - leaf_preimage_hex: `MATCH` (RI-RS: `007b2261223a307d` | RI-PY: `007b2261223a307d`)
  - leaf_preimage_len: `MATCH` (RI-RS: `8` | RI-PY: `8`)
  - leaf_sha256: `MATCH` (RI-RS: `94f89ffdde40b0f7deace6ae4b5f614641e970da2cff10639b159f7749e87dd6` | RI-PY: `94f89ffdde40b0f7deace6ae4b5f614641e970da2cff10639b159f7749e87dd6`)
- Vector result: `MATCH`

## D. Cross-Language Agreement

- Status: `PROVEN`

## E. D1 Phase 2 status

- Status: `TECHNICALLY COMPLETE`

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
- Evidence JSON SHA-256: `34c79788e92650b73f473ead5abb61e89ab02f99c3589c12554f12cd965c9a1a`
