#!/usr/bin/env python3
"""Deterministic DER negative-vector generator for AURA Guard; stdlib only."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

GENERATOR = "AURA-DER-MUTATOR-0.1.0"
SCHEMA = "aura.crypto-regression.v1"


class DerError(ValueError):
    pass


@dataclass
class Node:
    tag: bytes
    content: bytes = b""
    children: list["Node"] = field(default_factory=list)
    constructed: bool = False
    path: str = "$"
    original_length: int = 0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_tag(data: bytes, pos: int, end: int) -> tuple[bytes, int]:
    if pos >= end:
        raise DerError("missing tag")
    start = pos
    first = data[pos]
    pos += 1
    if (first & 31) == 31:
        first_octet = True
        count = 0
        while True:
            if pos >= end:
                raise DerError("truncated high-tag-number form")
            b = data[pos]
            pos += 1
            count += 1
            if first_octet and (b & 127) == 0:
                raise DerError("non-minimal high-tag-number form")
            first_octet = False
            if not b & 128:
                break
            if count > 5:
                raise DerError("tag too large")
        if count == 1 and (data[start + 1] & 127) < 31:
            raise DerError("high-tag-number form used for low tag")
    return data[start:pos], pos


def read_length(data: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos >= end:
        raise DerError("missing length")
    first = data[pos]
    pos += 1
    if first < 128:
        return first, pos
    count = first & 127
    if count == 0 or count > 4:
        raise DerError("indefinite or excessive DER length form")
    if pos + count > end:
        raise DerError("truncated length")
    raw = data[pos:pos + count]
    if raw[0] == 0:
        raise DerError("non-minimal length has leading zero")
    length = int.from_bytes(raw, "big")
    if length < 128 or (count > 1 and length < (1 << (8 * (count - 1)))):
        raise DerError("non-minimal long-form length")
    return length, pos + count


def check_primitive(tag: bytes, content: bytes) -> None:
    if tag == b"\x02":
        if not content:
            raise DerError("empty INTEGER")
        if len(content) > 1 and (
            (content[0] == 0 and not content[1] & 128)
            or (content[0] == 255 and content[1] & 128)
        ):
            raise DerError("non-canonical INTEGER sign octet")
    elif tag == b"\x03":
        if not content or content[0] > 7:
            raise DerError("invalid BIT STRING unused-bits count")
        if len(content) == 1 and content[0] != 0:
            raise DerError("empty BIT STRING has unused bits")
        if len(content) > 1 and content[0] and content[-1] & ((1 << content[0]) - 1):
            raise DerError("non-zero BIT STRING padding")
    elif tag == b"\x06":
        if not content:
            raise DerError("empty OBJECT IDENTIFIER")
        at_start = True
        for b in content:
            if at_start and b == 128:
                raise DerError("non-minimal OID subidentifier")
            at_start = not (b & 128)
        if not at_start:
            raise DerError("unterminated OID subidentifier")


def parse_der(data: bytes) -> Node:
    def one(pos: int, end: int, path: str) -> tuple[Node, int]:
        tag, cursor = read_tag(data, pos, end)
        length, start = read_length(data, cursor, end)
        stop = start + length
        if stop > end:
            raise DerError(f"value at {path} exceeds enclosing boundary")
        node = Node(tag, constructed=bool(tag[0] & 32), path=path, original_length=length)
        if node.constructed:
            current = start
            index = 0
            while current < stop:
                child, current = one(current, stop, f"{path}.{index}")
                node.children.append(child)
                index += 1
            if current != stop:
                raise DerError(f"constructed value at {path} has trailing content")
        else:
            node.content = data[start:stop]
            if len(tag) == 1 and tag[0] & 192 == 0:
                check_primitive(tag, node.content)
        return node, stop

    if not data:
        raise DerError("empty input")
    root, end = one(0, len(data), "$")
    if end != len(data):
        raise DerError(f"trailing bytes: {len(data) - end}")
    return root


def length_bytes(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([128 | len(raw)]) + raw


def encode(node: Node, mutation: dict | None = None) -> bytes:
    mutation = mutation or {}
    content = b"".join(encode(child, mutation) for child in node.children) if node.constructed else node.content
    kind = mutation.get("kind") if node.path == mutation.get("target_path") else None
    if kind == "oid-bad-termination" and node.tag == b"\x06" and content:
        content = content[:-1] + bytes([content[-1] | 128])
    elif kind == "bitstring-bad-unused-bits" and node.tag == b"\x03" and content:
        content = bytes([8]) + content[1:]
    elif kind == "integer-redundant-zero" and node.tag == b"\x02" and content:
        content = b"\x00\x00" + content
    if kind == "length-nonminimal":
        if len(content) >= 128:
            raise ValueError("target for nonminimal length must be shorter than 128")
        encoded_length = bytes([129, len(content)])
    else:
        declared = len(content)
        if kind == "length-overrun":
            declared += int(mutation.get("delta", 65536))
        elif kind == "length-underrun":
            declared -= 1
            if declared < 0:
                raise ValueError("cannot underrun empty value")
        encoded_length = length_bytes(declared)
    return node.tag + encoded_length + content


def walk(node: Node):
    yield node
    for child in node.children:
        yield from walk(child)


def first(nodes: list[Node], predicate):
    values = [n for n in nodes if predicate(n)]
    return sorted(values, key=lambda n: (n.path.count("."), n.path))[0] if values else None


def specs(root: Node) -> list[dict]:
    nodes = list(walk(root))
    out = [
        {"id": "truncated-last-byte", "kind": "raw", "action": "truncate-last"},
        {"id": "truncated-half", "kind": "raw", "action": "truncate-half"},
        {"id": "trailing-octet", "kind": "raw", "action": "append-zero"},
        {"id": "root-length-overrun", "kind": "length-overrun", "target_path": "$", "delta": 1},
        {"id": "root-length-underrun", "kind": "length-underrun", "target_path": "$"},
    ]
    short = first(nodes, lambda n: n.path != "$" and 0 < n.original_length < 128)
    if short:
        out.append({"id": "nonminimal-nested-length", "kind": "length-nonminimal", "target_path": short.path})
    nested = sorted((n for n in nodes if n.path != "$" and n.original_length > 0),
                    key=lambda n: (n.path.count("."), n.path), reverse=True)
    if nested:
        out.append({"id": "nested-length-overrun", "kind": "length-overrun",
                    "target_path": nested[0].path, "delta": 65536})
    oid = first(nodes, lambda n: n.tag == b"\x06" and bool(n.content))
    if oid:
        out.append({"id": "oid-unterminated-subidentifier", "kind": "oid-bad-termination", "target_path": oid.path})
    bits = first(nodes, lambda n: n.tag == b"\x03" and bool(n.content))
    if bits:
        out.append({"id": "bitstring-invalid-unused-bits", "kind": "bitstring-bad-unused-bits", "target_path": bits.path})
    integer = first(nodes, lambda n: n.tag == b"\x02" and bool(n.content))
    if integer:
        out.append({"id": "integer-redundant-sign-octets", "kind": "integer-redundant-zero", "target_path": integer.path})
    return out


def source_imprint(path: Path) -> str:
    obj = json.loads(path.read_text(encoding="utf-8"))
    preimage = "|".join((obj["prev_segment_chain_hash"], obj["merkle_root"],
                         str(obj["first_seq"]), str(obj["last_seq"]), obj["sealed_at"]))
    return sha256(preimage.encode("utf-8"))


def generate(fixtures: Path, output: Path) -> dict:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    inputs, cases, errors = [], [], []
    sources = sorted(fixtures.glob("segment-*.tsr"))
    if not sources:
        raise FileNotFoundError(f"no segment-*.tsr fixtures under {fixtures}")
    for src in sources:
        raw = src.read_bytes()
        paired = src.with_suffix(".manifest.json")
        if not paired.exists():
            errors.append(f"missing paired manifest for {src.name}")
            continue
        try:
            root = parse_der(raw)
        except DerError as exc:
            errors.append(f"baseline DER rejected: {src.name}: {exc}")
            continue
        source_hash = sha256(raw)
        imprint = source_imprint(paired)
        inputs.append({"source_file": src.name, "source_sha256": source_hash,
                       "source_size_bytes": len(raw), "paired_manifest_file": paired.name,
                       "paired_manifest_sha256": sha256(paired.read_bytes()),
                       "expected_message_imprint_sha256": imprint})
        for spec in specs(root):
            action = spec.get("action")
            if action == "truncate-last":
                mutant = raw[:-1]
            elif action == "truncate-half":
                mutant = raw[:max(1, len(raw) // 2)]
            elif action == "append-zero":
                mutant = raw + b"\x00"
            else:
                mutant = encode(root, spec)
            try:
                parse_der(mutant)
            except DerError as exc:
                validation, detail = "REJECTED_BY_HARNESS_DER_CHECK", str(exc)
            else:
                validation, detail = "UNEXPECTEDLY_VALID_DER", "generic parser accepted bytes"
                errors.append(f"mutation remains valid DER: {src.name}/{spec['id']}")
            target = Path(src.stem) / f"{spec['id']}.tsr"
            (output / target).parent.mkdir(parents=True, exist_ok=True)
            (output / target).write_bytes(mutant)
            cases.append({"id": f"{src.stem}:{spec['id']}", "source_file": src.name,
                          "source_sha256": source_hash, "mutation_id": spec["id"],
                          "mutation_kind": spec["kind"], "target_path": target.as_posix(),
                          "target_sha256": sha256(mutant), "target_size_bytes": len(mutant),
                          "target_bytes_base64": base64.b64encode(mutant).decode("ascii"),
                          "expected_message_imprint_sha256": imprint, "expected_disposition": "REJECT",
                          "expected_layer": "DER parser or higher-level RFC3161/CMS/PKIX verifier",
                          "harness_der_validation": validation, "harness_der_detail": detail})
    manifest = {"schema": SCHEMA, "generator": GENERATOR,
                "scope": "Deterministic malformed-DER negative inputs derived from existing RFC3161 TSRs.",
                "limitations": ["Harness DER rejection is not proof of production-verifier rejection.",
                                "The Guard Rust integration test must reject every case.",
                                "No independent ECDSA high-S/low-S vectors are included in this DER corpus."],
                "inputs": inputs, "cases": cases,
                "summary": {"baseline_inputs": len(inputs), "generated_cases": len(cases),
                            "harness_der_rejections": sum(c["harness_der_validation"] == "REJECTED_BY_HARNESS_DER_CHECK" for c in cases),
                            "generation_errors": errors}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        raise RuntimeError("; ".join(errors))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = generate(args.fixtures_dir, args.output_dir)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
