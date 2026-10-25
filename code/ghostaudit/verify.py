"""Contract verifier: every output row must satisfy the submission contract before it is written.

These are the checks the specification states, applied to the final rows. A row that fails is
reported; the run command refuses to write a file with problems.
"""
from __future__ import annotations

import json
from datetime import datetime

from .planner import OP_STATE, OPERATION_ORDER, PHASE_ORDER, RULES

STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
STEP_KEYS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
PHASE_OF = {op: phase for phase, ops in {
    "FINDING": OPERATION_ORDER[0:4], "REMEDIATION": OPERATION_ORDER[4:9], "VERIFICATION": OPERATION_ORDER[9:]}.items()
    for op in ops}


# finding -> (remediations that may follow it, verifications that must close it), read from the planner rules
FOLLOW_UP: dict[str, tuple[set[str], set[str]]] = {}
for _finding, _remediation, _verification in RULES.values():
    if _finding:
        FOLLOW_UP.setdefault(_finding, (set(), set()))
        FOLLOW_UP[_finding][0].add(_remediation)
        FOLLOW_UP[_finding][1].add(_verification)


def verify_row(case_id: str, status: str, steps: list[dict], audit_at: datetime,
               evidence_times: dict[str, datetime], allow_unidentified: bool = False,
               evidence_names: dict[str, set[str]] | None = None,
               evidence_systems: dict[str, set[str]] | None = None) -> list[str]:
    """Problems with one row (empty list when it is valid).

    `evidence_times` maps every citable id (file_id, activity_id, audit_id) to when it was captured
    or happened; a citation after audit_at is not allowed. When `evidence_names` (file id to the resource ids
    it names) and `evidence_systems` (file id to the systems it covers) are given, a cited file must also
    name the resource, or, for an absence check, cover the system.
    """
    problems: list[str] = []
    tag = f"{case_id}"
    if status not in STATUSES:
        return [f"{tag}: unknown status {status!r}"]
    if status == "NOT_APPLICABLE":
        return [f"{tag}: NOT_APPLICABLE row must have an empty step list"] if steps else []
    if not steps and not allow_unidentified:
        problems.append(f"{tag}: {status} row has no steps")
    if not steps and allow_unidentified and status != "COMPLETE":
        problems.append(f"{tag}: an unidentified case must be COMPLETE")
    previous = None
    seen: set[tuple] = set()
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
        if key in seen:
            problems.append(f"{where}: duplicate of an earlier step")
        seen.add(key)
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
            elif evidence_names is not None and evidence in evidence_names:
                covers = step["operation"] == "VERIFY_RECORD_ABSENT" and step["system_id"] in (evidence_systems or {}).get(evidence, ())
                if step["resource_id"] not in evidence_names[evidence] and not covers:
                    problems.append(f"{where}: evidence {evidence} neither names {step['resource_id']} nor covers {step['system_id']}")
    if status == "INCOMPLETE":
        by_resource: dict[str, set[str]] = {}
        for step in steps:
            if step.get("operation") in OP_STATE:
                by_resource.setdefault(step["resource_id"], set()).add(step["operation"])
        for resource, found in sorted(by_resource.items()):
            for finding in sorted(found & set(FOLLOW_UP)):
                remediations, verifications = FOLLOW_UP[finding]
                if not found & remediations:
                    problems.append(f"{tag}: {resource} has {finding} but no matching remediation")
                if not found & verifications:
                    problems.append(f"{tag}: {resource} has {finding} but no closing verification")
    if status == "INCOMPLETE" and steps and not any(s.get("phase") == "FINDING" for s in steps):
        problems.append(f"{tag}: INCOMPLETE row has no finding")
    return problems


def serialize_steps(steps: list[dict]) -> str:
    """Deterministic JSON: fixed key order, no spaces, non-ASCII kept."""
    ordered = [{k: step[k] for k in STEP_KEYS} for step in steps]
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))
