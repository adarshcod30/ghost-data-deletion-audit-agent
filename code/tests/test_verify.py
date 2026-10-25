from copy import deepcopy
from datetime import datetime, timezone

import pytest

from ghostaudit.verify import serialize_steps, verify_row

AUDIT = datetime(2026, 9, 10, tzinfo=timezone.utc)
EVIDENCE = {"evidence_1": datetime(2026, 9, 1, tzinfo=timezone.utc), "evidence_9": datetime(2026, 9, 20, tzinfo=timezone.utc)}


def step(no, phase, op, state, resource="account_1", system="account_service", evidence=""):
    return {"step_no": no, "phase": phase, "system_id": system, "resource_id": resource,
            "operation": op, "state": state, "evidence_id": evidence}


INCOMPLETE = [step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", evidence="evidence_1"),
              step(2, "REMEDIATION", "DELETE_RECORD", "ABSENT"),
              step(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT")]
COMPLETE = [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", evidence="evidence_1")]


def check(status, steps, **kw):
    return verify_row("case_1", status, steps, AUDIT, EVIDENCE, **kw)


def test_valid_rows_pass():
    assert check("INCOMPLETE", INCOMPLETE) == []
    assert check("COMPLETE", COMPLETE) == []
    assert check("NOT_APPLICABLE", []) == []


@pytest.mark.parametrize("mutate,expected", [
    (lambda s: s[0].update(evidence_id="evidence_9"), "dated after audit_at"),
    (lambda s: s[0].update(evidence_id="evidence_404"), "unknown evidence id"),
    (lambda s: s[0].update(evidence_id=""), "cites no evidence"),
    (lambda s: s[1].update(evidence_id="evidence_1"), "must have an empty evidence_id"),
    (lambda s: s[2].update(state="PRESENT"), "does not fit"),
    (lambda s: s[2].update(phase="REMEDIATION"), "does not belong to phase"),
    (lambda s: s[2].update(step_no=7), "step_no"),
    (lambda s: s.__setitem__(slice(None), [s[2], s[0], s[1]]), "out of order"),
    (lambda s: s[0].update(extra="x"), "differ from the contract"),
])
def test_each_violation_is_detected(mutate, expected):
    steps = deepcopy(INCOMPLETE)
    mutate(steps)
    assert any(expected in p for p in check("INCOMPLETE", steps)), check("INCOMPLETE", steps)


def test_status_specific_rules():
    assert check("NOT_APPLICABLE", COMPLETE)
    assert any("only contain verification" in p for p in check("COMPLETE", INCOMPLETE))
    assert any("no finding" in p for p in check("INCOMPLETE", COMPLETE))
    assert check("COMPLETE", []) and check("COMPLETE", [], allow_unidentified=True) == []
    assert check("INCOMPLETE", [], allow_unidentified=True)  # an unidentified case must be COMPLETE
    assert check("MAYBE", [])


def test_serialization_is_compact_ordered_and_deterministic():
    scrambled = [{k: s[k] for k in reversed(list(s))} for s in INCOMPLETE]
    text = serialize_steps(scrambled)
    assert text == serialize_steps(INCOMPLETE)
    assert text.startswith('[{"step_no":1,"phase":"FINDING","system_id":"account_service"')
    assert ", " not in text and ": " not in text
