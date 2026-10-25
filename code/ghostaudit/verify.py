"""Contract verifier: every output row must satisfy the submission contract before it is written.

These are the checks the specification states, applied to the final rows. A row that fails is
reported; the run command refuses to write a file with problems.
"""
from __future__ import annotations

import json
from datetime import datetime

from .planner import OP_STATE, OPERATION_ORDER, PHASE_ORDER

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
STEP_KEYS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
PHASE_OF = {op: phase for phase, ops in {
    "FINDING": OPERATION_ORDER[0:4], "REMEDIATION": OPERATION_ORDER[4:9], "VERIFICATION": OPERATION_ORDER[9:]}.items()
    for op in ops}


def verify_row(case_id: str, status: str, steps: list[dict], audit_at: datetime,
               evidence_times: dict[str, datetime]) -> list[str]:
    """Problems with one row (empty list when it is valid).

    `evidence_times` maps every citable id (file_id, activity_id, audit_id) to when it was captured
    or happened; a citation after audit_at is not allowed.
    """
    problems: list[str] = []
    tag = f"{case_id}"
    if status not in STATUSES:
        return [f"{tag}: unknown status {status!r}"]
    if status == "NOT_APPLICABLE":
        return [f"{tag}: NOT_APPLICABLE row must have an empty step list"] if steps else []
    if not steps:
        problems.append(f"{tag}: {status} row has no steps")
    previous = None
    for index, step in enumerate(steps, start=1):
        where = f"{tag} step {index}"
        if set(step) != set(STEP_KEYS):
            problems.append(f"{where}: keys {sorted(step)} differ from the contract")
            continue
        if step["step_no"] != index:
            problems.append(f"{where}: step_no is {step['step_no']}")
        if step["operation"] not in OP_STATE:
            problems.append(f"{where}: unknown operation {step['operation']}")
            continue
        if PHASE_OF[step["operation"]] != step["phase"]:
            problems.append(f"{where}: operation {step['operation']} does not belong to phase {step['phase']}")
        if OP_STATE[step["operation"]] != step["state"]:
            problems.append(f"{where}: state {step['state']} does not fit {step['operation']}")
        key = (PHASE_ORDER[step["phase"]], OPERATION_ORDER.index(step["operation"]), step["system_id"], step["resource_id"])
        if previous is not None and key < previous:
            problems.append(f"{where}: out of order")
        previous = key
        evidence = step["evidence_id"]
        must_cite = (status == "COMPLETE") or step["phase"] == "FINDING"
        if status == "INCOMPLETE" and step["phase"] != "FINDING" and evidence != "":
            problems.append(f"{where}: {step['phase']} step in an INCOMPLETE row must have an empty evidence_id")
        if status == "COMPLETE" and step["phase"] != "VERIFICATION":
            problems.append(f"{where}: a COMPLETE row may only contain verification steps")
        if must_cite:
            if not evidence:
                problems.append(f"{where}: {step['operation']} on {step['resource_id']} cites no evidence")
            elif evidence not in evidence_times:
                problems.append(f"{where}: unknown evidence id {evidence}")
            elif evidence_times[evidence] > audit_at:
                problems.append(f"{where}: evidence {evidence} is dated after audit_at")
    if status == "INCOMPLETE" and not any(s.get("phase") == "FINDING" for s in steps):
        problems.append(f"{tag}: INCOMPLETE row has no finding")
    return problems


def serialize_steps(steps: list[dict]) -> str:
    """Deterministic JSON: fixed key order, no spaces, non-ASCII kept."""
    ordered = [{k: step[k] for k in STEP_KEYS} for step in steps]
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))
