# C6 RI-RS Evidence Serialization — Defect Analysis and Safe Fix Proposal

**Status:** Draft engineering note. No protocol or governance effect.  
**Observed run:** [40048516275](https://github.com/vaidt/aura-guard-v1.3/actions/runs/40048516275)  
**Tested RI-RS head in the run:** `ad86f02eb4bb2f3479b3b2e3f6b78f26257c44ff)  
**Artifact ID:** `12542057433`  
**Artifact ZIP SHA-256:** `dbca4cfcc0179052c120617dc386b5123c734dfcbad8716d683d99f253e00273`  
**Extracted RI-RS report SHA-256:** `d89dc3c80727460d763cbda7686fd5ec3c6b91cb24110f3c6e3bee718a4c25ec`

## 1. Observed evidence

The workflow log says the evidence-preservation step failed with:

```text
Extra data: line 18 column 2 (char 809)
```

The downloaded artifact contains `aura-specification/artifacts/stage-c/c6-wire-corpus/results/ri-rs-results.json`. Independent parsing of that exact downloaded file with Python's strict `json.loads` succeeds. The file contains:

- schema: `AURA-BC021-WIRE-CONSUMER-RESULTS/0.1`;
- status: `PASS`;
- `case_count = 27`, with exactly 27 case entries;
- zero mismatches;
- one JSON document followed only by a newline.

The same artifact contains `implementation-evidence.json`, whose `consumer_report_status` is `PASS` and whose C6 status remains `BLOCKED_PENDING_EVIDENCE_REVIEW`.

## 2. Current conclusion

The log failure and uploaded artifact are inconsistent. The evidence presently supports this narrower diagnosis:

> The consumer test step completed and wrote a structurally valid report to the uploaded artifact path, but the evidence-preservation step failed while parsing a report in its runtime workspace.

This does **not** yet establish whether the workflow read the same bytes that were uploaded, whether a stale/partial file existed during the step, or whether the observed failure corresponds to an earlier attempt than the downloaded artifact. Do not dismiss the failure and do not rerun the gate as if it had passed.

## 3. Required next diagnostic

Before changing code, update the experimental RI-RS workflow so the evidence-preservation step:

1. prints the exact report path and byte count before parsing;
2. computes and logs SHA-256 for the complete report bytes;
3. parses the full report with `json.loads` and rejects any trailing data;
4. validates the schema, required fields, source-commit pin, corpus index digest and case count;
5. checks the number of actual cases equals `case_count`, with no duplicate case IDs and no absent cases;
6. writes a preservation evidence record which references the exact report digest and its validated values;
7. always retains the original report, parser diagnostics and evidence record as separate artifact files;
8. leaves the workflow failed if the parser or any validation fails.

The raw consumer report must not be rewritten, normalized, pretty-printed or silently recovered during evidence preservation. Preserve the exact original bytes for audit.

## 4. Safe validation sequence

- Re-read the latest branch head and source blobs.
- Change only the evidence-preservation step on the experimental branch.
- Exercise the validator against: the captured original report, malformed JSON, two concatenated JSON documents, trailing non-whitespace bytes, missing fields, mismatched source pin, altered index hash, wrong case count, duplicate IDs and missing cases.
- Confirm valid report is accepted while every negative case fails closed.
- Run the full workflow on the exact new head and preserve the run URL plus artifact digest.
- Obtain independent review before treating the result as usable evidence.

## 5. Non-effects

No merge, runtime enablement, gate promotion, conformance conclusion, authority finding, ratification, authorization or release decision follows from this note. C6 remains blocked pending complete evidence review.
