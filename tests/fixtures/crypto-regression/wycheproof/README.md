# Pinned ECDSA vectors

These files are copied verbatim from C2SP/Wycheproof at commit
`d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`.

| File | Git blob SHA-1 | Tests | Upstream valid | Upstream invalid |
|---|---|---:|---:|---:|
| `ecdsa_secp256r1_sha256_test.json` | `19c951dbd3b6e33ed5e28d9bbbeea30e5f0350d3` | 484 | 174 | 310 |
| `ecdsa_secp384r1_sha384_test.json` | `19df1b5614d68af884d9d197b0d123cc5d22807d` | 504 | 194 | 310 |

The complete upstream data is retained instead of selecting a few favorable
examples. The Guard test calls its actual private `verify_ecdsa()` function
through a `#[cfg(test)]` module and checks each source result. The vendor data
is test-only and does not become a runtime dependency.

Upstream project: https://github.com/C2SP/wycheproof
Pinned source listing: https://github.com/C2SP/wycheproof/tree/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1
The upstream Apache License 2.0 text is preserved in this directory.
