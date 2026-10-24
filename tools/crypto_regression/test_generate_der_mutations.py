"""Python self-tests for the deterministic AURA DER corpus generator."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE = Path(__file__).with_name("generate_der_mutations.py")
spec = importlib.util.spec_from_file_location("aura_der_mutator", MODULE)
mutator = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mutator
spec.loader.exec_module(mutator)
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "tsa"


class DerMutationGeneratorTests(unittest.TestCase):
    def test_existing_sources_are_valid_der(self):
        for name in ("segment-001.tsr", "segment-002.tsr"):
            with self.subTest(name=name):
                node = mutator.parse_der((FIXTURES / name).read_bytes())
                self.assertEqual(node.tag, b"\x30")

    def test_all_mutations_are_rejected_by_harness_der_checker(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "generated"
            manifest = mutator.generate(FIXTURES, output)
            self.assertEqual(manifest["summary"]["baseline_inputs"], 2)
            self.assertEqual(manifest["summary"]["generated_cases"], 20)
            for case in manifest["cases"]:
                raw = base64.b64decode(case["target_bytes_base64"], validate=True)
                with self.subTest(case=case["id"]):
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), case["target_sha256"])
                    self.assertEqual(case["harness_der_validation"], "REJECTED_BY_HARNESS_DER_CHECK")
                    with self.assertRaises(mutator.DerError):
                        mutator.parse_der(raw)

    def test_generation_is_byte_for_byte_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            mutator.generate(FIXTURES, first)
            mutator.generate(FIXTURES, second)
            files1 = {p.relative_to(first).as_posix(): p.read_bytes() for p in first.rglob("*") if p.is_file()}
            files2 = {p.relative_to(second).as_posix(): p.read_bytes() for p in second.rglob("*") if p.is_file()}
            self.assertEqual(files1, files2)

    def test_expected_imprints_are_bound_to_paired_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = mutator.generate(FIXTURES, Path(directory) / "generated")
            source_index = {entry["source_file"]: entry for entry in manifest["inputs"]}
            for case in manifest["cases"]:
                with self.subTest(case=case["id"]):
                    self.assertEqual(
                        case["expected_message_imprint_sha256"],
                        source_index[case["source_file"]]["expected_message_imprint_sha256"],
                    )
                    self.assertEqual(case["source_sha256"], source_index[case["source_file"]]["source_sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
