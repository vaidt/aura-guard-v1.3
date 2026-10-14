#!/usr/bin/env python3
"""One-shot JSON adapter for the AURA Core v3.3 fixed-point evaluator.

The Rust service embeds this file into its adapter process. AURA_CORE_PATH must
point at the root of aura-poc-a-core-v3.3, and
AURA_CORE_CONSTITUTION_VECTOR must contain the configured reference vector as
JSON. The request is read from stdin; only integer measurements are written to
stdout. No network access or shell interpolation is used.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def require_int_vector(value: object, label: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty JSON array")
    if any(type(item) is not int for item in value):
        raise ValueError(f"{label} must contain only JSON integers")
    if any(item < -(2**31) or item > (2**31 - 1) for item in value):
        raise ValueError(f"{label} values must fit signed int32")
    return value


def main() -> int:
    try:
        core_path = Path(os.environ["AURA_CORE_PATH"]).resolve()
        constitution = require_int_vector(
            json.loads(os.environ["AURA_CORE_CONSTITUTION_VECTOR"]),
            "AURA_CORE_CONSTITUTION_VECTOR",
        )
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
        vector = require_int_vector(request.get("vector"), "vector")
        valid_schema = request.get("valid_schema")
        if type(valid_schema) is not bool:
            raise ValueError("valid_schema must be a JSON boolean")
        if not (core_path / "core" / "evaluator.py").is_file():
            raise ValueError("AURA_CORE_PATH does not contain core/evaluator.py")
        sys.path.insert(0, str(core_path))
        from core.evaluator import PoCAEvaluator  # imported from the configured Core source

        evaluator = PoCAEvaluator(constitution)
        measurement = evaluator.evaluate(
            agent_id="AURA-GUARD",
            vector=vector,
            valid_schema=valid_schema,
        )
        ari = measurement.get("ari")
        drift = measurement.get("drift")
        if type(ari) is not int or type(drift) is not int:
            raise TypeError("Core evaluator did not return integer ari/drift values")
        result = {
            "ari": ari,
            "drift": drift,
            "evaluator_version": os.environ.get("AURA_CORE_VERSION", "core-v3.3"),
        }
        json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except Exception as exc:  # errors are deliberately returned without raw input data
        print(f"AURA Core adapter error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
