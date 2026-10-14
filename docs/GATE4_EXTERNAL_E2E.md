# Gate 4 — External-client black-box E2E

## Objective

Exercise the integrated AURA stack from the perspective of a client that knows only the HTTP contract and the filesystem evidence output:

1. A real `aura-guard` process binds a TCP listener with API-key authentication and signature-verified policy packs.
2. An external `curl` client sends `POST /v1/audit` with context, policy set, prompt/response, and the pre-normalized fixed-point measurement vector.
3. The synchronous HTTP response contains the Rust policy decision and nested `core_measurement` returned by the configured Python Core adapter.
4. The server's JSONL entry is compared with the HTTP response; prompt and response text must not be persisted.
5. `aura-replay --verify-segments` independently verifies the chain and the generated Merkle segment manifest from disk.

## CI evidence

The `gate4-external-e2e` job in `.github/workflows/ci.yml` checks out the AURA Core source at the pinned revision `cdf9bbf2b8420732f85a77197ea753809edbb029`, runs `scripts/gate4-external-e2e.sh`, and uploads the request, response, JSONL log, segment manifest, replay summary, setup log, and server log as the `gate4-external-e2e-evidence` artifact.

The test vector `[100000, 0, 0, 0]` and constitution vector `[100000,0,0,0]` are test fixtures, not production policy recommendations. The scenario expects `decision=ALLOW`, `core_measurement.status=COMPLETED`, `ari=100000`, and `drift=0`; the Rust policy engine remains responsible for the policy decision.

## Local execution

From the repository root, provide a path to a checkout of the AURA Core repo:

```bash
export AURA_CORE_PATH="/absolute/path/to/aura-poc-a-core-v3.3"
export AURA_CORE_CONSTITUTION_VECTOR='[100000,0,0,0]'
export AURA_CORE_VERSION='core-v3.3-gate4'
export AURA_CORE_PYTHON=python3
bash scripts/gate4-external-e2e.sh
```

The script builds the release binaries and signs the expected local policy packs using the repository setup script, starts a localhost-only service at `127.0.0.1:18089` by default, sends the HTTP request, and runs independent replay verification. Override the bind with `AURA_GATE4_BIND` if the default port is occupied.

Evidence is written to `artifacts/gate4/`. The script uses a generated API key and does not disable policy signature verification.

## Evidence boundary

A successful run establishes only that this particular end-to-end fixture passed on the tested revision. It does not demonstrate exhaustive security, high-load or failure-mode behaviour, protocol ratification, authority continuity, deployment authorization, complete normative conformance, or general production readiness. The evidence must be registered with the tags `TECHNICAL_EVIDENCE_ONLY / NORMATIVE_EFFECT_NONE`.
