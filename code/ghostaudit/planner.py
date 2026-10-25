"""Derive the status and the ordered steps from a ledger.

Per resource type the required final state and the way to get there are fixed by policy:

  DELETE    PRESENT      finding REMAINING_RECORD, remediation DELETE_RECORD, verify ABSENT
  ANONYMIZE IDENTIFIABLE finding EXPOSED_PII,      remediation ANONYMIZE_RECORD, verify ANONYMIZED
  REDACT    IDENTIFIABLE finding EXPOSED_PII,      remediation REDACT_RECORD,    verify REDACTED
  backup    ACTIVE       finding RESTORE_RISK,     remediation BLOCK_RESTORE,    verify RESTORE_BLOCKED
  data flow ACTIVE       finding ACTIVE_DATA_FLOW, remediation DISABLE_DATA_FLOW, verify FLOW_DISABLED
  RETAIN    (audit record, legal hold) verify RECORD_PRESENT

A resource already in its final state yields only the verification step.
"""
from __future__ import annotations

from .common import case_sort_key
from .ledger import CaseLedger, LedgerEntry

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = [
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
]
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
# (action, current state) -> (finding, remediation, verification)
RULES: dict[tuple[str, str], tuple[str | None, str | None, str]] = {
    ("DELETE", "PRESENT"): ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    ("DELETE", "ABSENT"): (None, None, "VERIFY_RECORD_ABSENT"),
    ("ANONYMIZE", "IDENTIFIABLE"): ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    ("ANONYMIZE", "ANONYMIZED"): (None, None, "VERIFY_RECORD_ANONYMIZED"),
    ("REDACT", "IDENTIFIABLE"): ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    ("REDACT", "REDACTED"): (None, None, "VERIFY_RECORD_REDACTED"),
    ("RETAIN", "PRESENT"): (None, None, "VERIFY_RECORD_PRESENT"),
    ("RETAIN", "ACTIVE"): ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
    ("RETAIN", "BLOCKED"): (None, None, "VERIFY_RESTORE_BLOCKED"),
    ("FLOW", "ACTIVE"): ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    ("FLOW", "DISABLED"): (None, None, "VERIFY_DATA_FLOW_DISABLED"),
}


def _entry_ops(entry: LedgerEntry) -> tuple[str | None, str | None, str] | None:
    state = entry.state
    if entry.action in ("DELETE", "ANONYMIZE", "REDACT") and state == "PRESENT" and entry.action != "DELETE":
        state = "IDENTIFIABLE"  # a record that exists where policy requires redaction or anonymization
    return RULES.get((entry.action or "", state))


def plan_steps(ledger: CaseLedger) -> tuple[str, list[dict]]:
    """Return (deletion_status, ordered steps) for an authorised deletion case."""
    pending: list[dict] = []
    findings = False
    complete_evidence: dict[str, str] = {}
    for entry in ledger.entries:
        ops = _entry_ops(entry)
        if ops is None:
            continue
        finding, remediation, verification = ops
        if finding:
            findings = True
            pending.append(_step("FINDING", entry, finding, entry.evidence_id))
            pending.append(_step("REMEDIATION", entry, remediation, ""))
        complete_evidence[entry.resource_id] = entry.evidence_id
        pending.append(_step("VERIFICATION", entry, verification, ""))
    status = "INCOMPLETE" if findings else "COMPLETE"
    if status == "COMPLETE":
        for step in pending:
            step["evidence_id"] = complete_evidence.get(step["resource_id"], "")
    pending.sort(key=lambda s: (PHASE_ORDER[s["phase"]], OPERATION_ORDER.index(s["operation"]),
                                s["system_id"], case_sort_key(s["resource_id"])))
    for number, step in enumerate(pending, start=1):
        step["step_no"] = number
    return status, pending


def _step(phase: str, entry: LedgerEntry, operation: str, evidence_id: str) -> dict:
    return {"step_no": 0, "phase": phase, "system_id": entry.system_id, "resource_id": entry.resource_id,
            "operation": operation, "state": OP_STATE[operation], "evidence_id": evidence_id}
