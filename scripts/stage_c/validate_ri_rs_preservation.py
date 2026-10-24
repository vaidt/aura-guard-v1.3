import json, hashlib, os, pathlib, sys

root = pathlib.Path("aura-specification/artifacts/stage-c/c6-wire-corpus")
report_path = root / "results/ri-rs-results.json"
index_path = root / "index.json"
evidence_dir = pathlib.Path("artifacts/c6-ri-rs-consumer")
diagnostics_path = evidence_dir / "preservation-diagnostics.json"
expected_commit = os.environ.get("AURA_RI_RS_COMMIT")
errors, report, index = [], None, None
report_raw, index_raw = b"", b""
report_sha, index_sha = None, None
preservation_status = "FAIL"

def validate(report, index, index_sha, expected_commit):
    found = []
    if not isinstance(report, dict):
        found.append("report_not_json_object")
    if not isinstance(index, dict):
        found.append("index_not_json_object")
    if not isinstance(report, dict) or not isinstance(index, dict):
        return found
    if report.get("schema") != "AURA-BC021-WIRE-CONSUMER-RESULTS/0.1":
        found.append("unexpected_report_schema")
    if index.get("schema") != "AURA-BC021-MATERIALIZED-WIRE-CORPUS/0.1":
        found.append("unexpected_index_schema")
    if report.get("index_sha256") != index_sha:
        found.append("report_index_sha256_mismatch")
    rows = report.get("cases")
    if not isinstance(rows, list):
        found.append("report_cases_not_list"); rows = []
    count = report.get("case_count")
    if not isinstance(count, int) or isinstance(count, bool):
        found.append("report_case_count_not_integer")
    elif count != len(rows):
        found.append("report_case_count_mismatch")
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows): found.append("report_case_entry_not_object")
    if any(not isinstance(cid, str) or not cid for cid in ids): found.append("report_invalid_case_id")
    if len(ids) != len(set(ids)): found.append("report_duplicate_case_id")
    if any(row.get("matched") is not True for row in rows if isinstance(row, dict)): found.append("report_unmatched_case")
    if report.get("status") != "PASS": found.append("consumer_report_not_pass")
    if report.get("source_commit") != expected_commit: found.append("report_source_commit_mismatch")
    index_rows = index.get("cases")
    if not isinstance(index_rows, list): found.append("index_cases_not_list"); index_rows = []
    index_ids = [row.get("id") for row in index_rows if isinstance(row, dict)]
    if len(index_ids) != len(index_rows): found.append("index_case_entry_not_object")
    if any(not isinstance(cid, str) or not cid for cid in index_ids): found.append("index_invalid_case_id")
    if len(index_ids) != len(set(index_ids)): found.append("index_duplicate_case_id")
    if set(index_ids) != set(ids): found.append("report_index_case_set_mismatch")
    index_count = index.get("case_count")
    if not isinstance(index_count, int) or isinstance(index_count, bool): found.append("index_case_count_not_integer")
    elif index_count != len(index_rows) or index_count != len(rows): found.append("report_index_case_count_mismatch")
    return found

def parse_json_bytes(raw, label):
    try:
        return json.loads(raw.decode("utf-8")), None
    except Exception as exc:
        return None, f"{label}_json_parse_error:{type(exc).__name__}:{exc}"

def negative_fixture_self_test():
    base_index = {"schema":"AURA-BC021-MATERIALIZED-WIRE-CORPUS/0.1","case_count":1,"cases":[{"id":"C6-W-000"}]}
    base_report = {"schema":"AURA-BC021-WIRE-CONSUMER-RESULTS/0.1","status":"PASS","source_commit":"fixture-sha","index_sha256":"fixture-index-sha","case_count":1,"cases":[{"id":"C6-W-000","matched":True}]}
    if validate(base_report, base_index, "fixture-index-sha", "fixture-sha"):
        raise RuntimeError("valid fixture rejected")
    mutations = [
        ("wrong-index-digest", {**base_report,"index_sha256":"wrong"}, base_index),
        ("count-mismatch", {**base_report,"case_count":2}, base_index),
        ("duplicate-id", {**base_report,"case_count":2,"cases":[{"id":"X","matched":True},{"id":"X","matched":True}]}, {**base_index,"case_count":2,"cases":[{"id":"X"},{"id":"X"}]}),
        ("missing-id", {**base_report,"cases":[{"matched":True}]}, base_index),
        ("false-matched", {**base_report,"cases":[{"id":"C6-W-000","matched":False}]}, base_index),
        ("id-set-mismatch", base_report, {**base_index,"cases":[{"id":"OTHER"}]}),
    ]
    results = []
    for name, test_report, test_index in mutations:
        found = validate(test_report, test_index, "fixture-index-sha", "fixture-sha")
        if not found: raise RuntimeError(f"negative fixture unexpectedly passed: {name}")
        results.append({"name":name,"rejected":True,"errors":found})
    for name, raw in [("malformed-json", b'{"ok":'),("concatenated-json", b'{"ok":true}{"extra":true}'),("trailing-data", b'{"ok":true} trailing')]:
        _, parse_error = parse_json_bytes(raw, "fixture")
        if not parse_error: raise RuntimeError(f"negative fixture unexpectedly passed: {name}")
        results.append({"name":name,"rejected":True})
    print(f"PRESERVATION_NEGATIVE_FIXTURES_PASS={len(results)}")
    print("PRESERVATION_NEGATIVE_FIXTURES="+json.dumps(results,sort_keys=True))

negative_fixture_self_test()

def record_file(path):
    if not path.is_file():
        errors.append(f"missing_file:{path}")
        return b"", None
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    print(f"PRESERVE_PATH={path}")
    print(f"PRESERVE_BYTE_COUNT={len(raw)}")
    print(f"PRESERVE_SHA256={digest}")
    return raw, digest

try:
    report_raw, report_sha = record_file(report_path)
    index_raw, index_sha = record_file(index_path)
    report, report_error = parse_json_bytes(report_raw, "report") if report_raw else (None,None)
    index, index_error = parse_json_bytes(index_raw, "index") if index_raw else (None,None)
    if report_error: errors.append(report_error)
    if index_error: errors.append(index_error)
    errors.extend(validate(report,index,index_sha,expected_commit))
    preservation_status = "PASS" if not errors else "FAIL"
except Exception as exc:
    errors.append(f"preservation_exception:{type(exc).__name__}:{exc}")
    preservation_status = "FAIL"

diagnostics = {
    "schema":"AURA-C6-RI-RS-PRESERVATION-DIAGNOSTICS/0.2",
    "tested_source_commit":expected_commit,
    "report_path":str(report_path),
    "index_path":str(index_path),
    "report_byte_count":len(report_raw),
    "report_sha256":report_sha,
    "index_byte_count":len(index_raw),
    "index_sha256":index_sha,
    "report_status":report.get("status") if isinstance(report,dict) else None,
    "case_count_declared":report.get("case_count") if isinstance(report,dict) else None,
    "case_count_actual":len(report.get("cases",[])) if isinstance(report,dict) and isinstance(report.get("cases"),list) else None,
    "preservation_status":preservation_status,
    "errors":errors,
}
evidence = {
    "schema":"AURA-C6-IMPLEMENTATION-EVIDENCE/0.4",
    "component":"RI-RS-AURA-GUARD-STRICT-BC021-CONSUMER",
    "repository":"vaidt/aura-guard-v1.3",
    "tested_source_commit":expected_commit,
    "consumer_blob_sha256":os.environ.get("AURA_RI_RS_SOURCE_BLOB"),
    "lib_blob_sha256":os.environ.get("AURA_RI_RS_LIB_BLOB"),
    "cargo_blob_sha256":os.environ.get("AURA_RI_RS_CARGO_BLOB"),
    "test_blob_sha256":os.environ.get("AURA_RI_RS_TEST_BLOB"),
    "shared_index_sha256":index_sha,
    "consumer_report_sha256":report_sha,
    "consumer_report_bytes":len(report_raw),
    "case_count":report.get("case_count") if isinstance(report,dict) else 0,
    "consumer_report_status":report.get("status") if isinstance(report,dict) else "NOT_AVAILABLE",
    "preservation_status":preservation_status,
    "preservation_errors":errors,
    "c6_gate_status":"BLOCKED_PENDING_EVIDENCE_REVIEW",
    "authority":"NONE","governance_effect":"NONE","authorization_effect":"NONE","release_effect":"NONE"
}
for path,payload in ((diagnostics_path,diagnostics),(evidence_dir/"implementation-evidence.json",evidence)):
    raw=(json.dumps(payload,indent=2,sort_keys=True)+"\n").encode("utf-8")
    path.write_bytes(raw)
    json.loads(path.read_bytes().decode("utf-8"))
print(f"PRESERVATION_STATUS={preservation_status}")
print("PRESERVATION_ERRORS="+json.dumps(errors,sort_keys=True))
if errors: sys.exit(1)

