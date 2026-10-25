"""Independent contract check of an output.csv, written from AGENTS.md section 6 and sharing no code with ghostaudit.verify.

    python3 code/evaluation/contract_check.py [output.csv]

Reads only the standard library and dataset/. Exit status 0 when every check passes.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "dataset"
OPS = {  # operation: (phase, state), copied from AGENTS.md section 6.4
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"), "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"), "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"), "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"), "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"), "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"), "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"), "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}
KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def rows(name: str) -> list[dict]:
    with (DATA / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "output.csv"
    raw = path.read_bytes()
    failures: list[str] = []
    def check(name: str, ok: bool, detail: str = "") -> None:
        print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
        if not ok:
            failures.append(name)
    check("no byte order mark, LF line endings", not raw.startswith(b"\xef\xbb\xbf") and b"\r" not in raw)
    out = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    header = path.read_text(encoding="utf-8").splitlines()[0]
    check("exact header", header == "case_id,deletion_status,steps_json", header)
    requests = rows("deletion_requests.csv")
    by_case = {r["case_id"]: r for r in requests}
    ids = [r["case_id"] for r in out]
    check("518 data rows", len(out) == 518, str(len(out)))
    check("one row per requested case, none extra or duplicated", sorted(ids) == sorted(by_case) and len(set(ids)) == len(ids))
    natural = sorted(ids, key=lambda c: (c.rsplit("_", 1)[0], int(c.rsplit("_", 1)[1])))
    check("rows sorted by case id in natural numeric order", ids == natural)
    times = {r["file_id"]: ts(r["captured_at"]) for r in rows("evidence_files.csv")}
    times.update({r["activity_id"]: ts(r["event_time"]) for r in rows("system_activity.csv")})
    times.update({r["audit_id"]: ts(r["event_time"]) for r in rows("user_audit_log.csv")})
    bad: list[str] = []
    statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    steps_total = 0
    for row in out:
        case, status = row["case_id"], row["deletion_status"]
        audit_at = ts(by_case[case]["audit_at"]) if case in by_case else None
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            bad.append(f"{case}: steps_json is not JSON")
            continue
        if status not in statuses:
            bad.append(f"{case}: status {status}")
        if not isinstance(steps, list):
            bad.append(f"{case}: steps_json is not an array")
            continue
        steps_total += len(steps)
        if status == "NOT_APPLICABLE" and steps:
            bad.append(f"{case}: NOT_APPLICABLE with steps")
        last = (-1, -1)
        for number, step in enumerate(steps, start=1):
            if set(step) != KEYS:
                bad.append(f"{case} step {number}: keys")
                continue
            if step["step_no"] != number:
                bad.append(f"{case} step {number}: numbering")
            if step["operation"] not in OPS or OPS[step["operation"]] != (step["phase"], step["state"]):
                bad.append(f"{case} step {number}: operation, phase or state")
                continue
            order = (RANK[step["phase"]], list(OPS).index(step["operation"]))
            if order < last:
                bad.append(f"{case} step {number}: order")
            last = order
            ev = step["evidence_id"]
            future_free = ev == "" or (ev in times and audit_at is not None and times[ev] <= audit_at)
            if not future_free:
                bad.append(f"{case} step {number}: evidence {ev} unknown or after audit_at")
            if status == "INCOMPLETE" and step["phase"] != "FINDING" and ev != "":
                bad.append(f"{case} step {number}: future work must have empty evidence_id")
            if (status == "COMPLETE" or step["phase"] == "FINDING") and ev == "":
                bad.append(f"{case} step {number}: proof step without evidence")
            if status == "COMPLETE" and step["phase"] != "VERIFICATION":
                bad.append(f"{case} step {number}: COMPLETE row with a non-verification step")
        if status == "INCOMPLETE" and not any(s.get("phase") == "FINDING" for s in steps):
            bad.append(f"{case}: INCOMPLETE without a finding")
    check("every row: status, JSON array, step schema, numbering, phase order, states, evidence rules", not bad, "; ".join(bad[:4]))
    na = [r["case_id"] for r in out if r["deletion_status"] == "NOT_APPLICABLE"]
    check("NOT_APPLICABLE rows have steps_json == []", all(r["steps_json"] == "[]" for r in out if r["deletion_status"] == "NOT_APPLICABLE"), f"{len(na)} rows")
    print(f"steps in total: {steps_total}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
