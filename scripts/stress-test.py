#!/usr/bin/env python3
"""Concurrent HTTP stress test for GUARD-RS-001.

Runs against a live Aura-Guard instance, sends hundreds of parallel POST
/v1/audit requests, checks that each response owns a unique contiguous
sequence, and independently validates the final JSONL log with aura-replay.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("AURA_BIND", "http://127.0.0.1:8080"))
    parser.add_argument("--api-key", default=os.environ.get("AURA_API_KEY"))
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--workers", type=int, default=200)
    parser.add_argument("--log", type=Path, default=Path("logs/audit.jsonl"))
    parser.add_argument("--replay", type=Path, default=Path("target/release/aura-replay"))
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()
    if not args.api_key:
        parser.error("AURA_API_KEY or --api-key is required")
    if args.requests < 1 or args.workers < 1:
        parser.error("--requests and --workers must be positive")
    args.workers = min(args.workers, args.requests)
    return args


def read_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"audit log line {index} is not valid JSON: {exc}") from exc
    return records


def send_request(args: argparse.Namespace, index: int) -> dict:
    request_id = f"guard-rs-001-{index:05d}"
    body = {
        "context": "AURA-GUARD-RS-001-STRESS",
        "policy_set": "finance-v1",
        "payload": {
            "prompt": f"Deterministic concurrency stress probe {index}.",
            "response": f"Harmless synthetic response for probe {index}.",
        },
    }
    request = urllib.request.Request(
        args.base_url.rstrip("/") + "/v1/audit",
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": args.api_key,
            "X-Request-ID": request_id,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            response_body = response.read()
            if response.status != 200:
                raise RuntimeError(f"request {index}: unexpected HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"request {index}: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"request {index}: transport error: {exc}") from exc

    try:
        entry = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"request {index}: response is not JSON") from exc

    if entry.get("request_id") != request_id:
        raise RuntimeError(
            f"request {index}: request_id mismatch: {entry.get('request_id')!r}"
        )
    if not isinstance(entry.get("seq"), int):
        raise RuntimeError(f"request {index}: response has no integer seq")
    if not isinstance(entry.get("prev_hash"), str) or not isinstance(entry.get("chain_hash"), str):
        raise RuntimeError(f"request {index}: response has no chain linkage")
    return entry


def main() -> int:
    args = parse_args()
    baseline = read_log(args.log)
    baseline_count = len(baseline)
    first_seq = int(baseline[-1]["seq"]) + 1 if baseline else 0

    start = time.monotonic()
    results: list[dict] = []
    failures: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(send_request, args, i): i for i in range(args.requests)}
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # report every failed request instead of hiding later failures
                failures.append(f"request {index}: {exc}")

    elapsed = time.monotonic() - start
    if failures:
        print(f"STRESS FAIL: {len(failures)}/{args.requests} HTTP requests failed", file=sys.stderr)
        for failure in failures[:30]:
            print(f"  {failure}", file=sys.stderr)
        return 1
    if len(results) != args.requests:
        print(f"STRESS FAIL: expected {args.requests} results, got {len(results)}", file=sys.stderr)
        return 1

    response_seqs = [entry["seq"] for entry in results]
    expected_seqs = set(range(first_seq, first_seq + args.requests))
    if len(set(response_seqs)) != args.requests or set(response_seqs) != expected_seqs:
        print(
            "STRESS FAIL: response sequence values are duplicated, missing, or non-contiguous",
            file=sys.stderr,
        )
        return 1

    try:
        all_entries = read_log(args.log)
    except Exception as exc:
        print(f"STRESS FAIL: cannot read final log: {exc}", file=sys.stderr)
        return 1
    if len(all_entries) != baseline_count + args.requests:
        print(
            f"STRESS FAIL: expected {baseline_count + args.requests} log entries, "
            f"found {len(all_entries)}",
            file=sys.stderr,
        )
        return 1

    logged_ids = [entry.get("request_id") for entry in all_entries[baseline_count:]]
    expected_ids = {f"guard-rs-001-{i:05d}" for i in range(args.requests)}
    if len(set(logged_ids)) != args.requests or set(logged_ids) != expected_ids:
        print("STRESS FAIL: log does not contain every request exactly once", file=sys.stderr)
        return 1

    logged_seqs = [entry.get("seq") for entry in all_entries]
    if logged_seqs != list(range(len(all_entries))):
        print("STRESS FAIL: on-disk entries are not in contiguous sequence order", file=sys.stderr)
        return 1

    command = [
        str(args.replay),
        "--log", str(args.log),
        "--policies-dir", "policies",
        "--trusted-signers", "policies/trusted_signers.json",
        "--verify-lineage",
        "--json",
    ]
    replay = subprocess.run(command, capture_output=True, text=True, check=False)
    if replay.returncode != 0:
        print(f"STRESS FAIL: aura-replay exit={replay.returncode}", file=sys.stderr)
        print(replay.stdout, file=sys.stderr)
        print(replay.stderr, file=sys.stderr)
        return 1
    try:
        replay_result = json.loads(replay.stdout)
    except json.JSONDecodeError:
        print("STRESS FAIL: aura-replay did not emit a JSON summary", file=sys.stderr)
        print(replay.stdout, file=sys.stderr)
        print(replay.stderr, file=sys.stderr)
        return 1
    if replay_result.get("status") != "ok" or replay_result.get("entries") != len(all_entries):
        print(f"STRESS FAIL: unexpected aura-replay result: {replay_result}", file=sys.stderr)
        return 1

    print("GUARD-RS-001 STRESS PASS")
    print(f"  requests_sent: {args.requests}")
    print(f"  max_parallel_workers: {args.workers}")
    print(f"  http_requests_succeeded: {len(results)}")
    print(f"  response_sequences_unique_and_contiguous: true")
    print(f"  JSONL_entries: {len(all_entries)}")
    print(f"  log_request_ids_unique: true")
    print(f"  elapsed_seconds: {elapsed:.3f}")
    print(f"  aura_replay: {replay_result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
