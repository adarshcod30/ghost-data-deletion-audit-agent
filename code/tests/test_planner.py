import pytest

from ghostaudit.identity import Subject
from ghostaudit.ledger import CaseLedger, LedgerEntry
from ghostaudit.planner import OP_STATE, OPERATION_ORDER, PHASE_ORDER, RULES, plan_steps
from datetime import datetime, timezone

SUBJECT = Subject("c", "a@b.c", datetime(2026, 1, 1, tzinfo=timezone.utc), "resolved", "user_1", "current", (), (), "", ())


def entry(resource_id, action, state, system="account_service", evidence="evidence_1"):
    prefix = resource_id.rsplit("_", 1)[0]
    return LedgerEntry(resource_id, system, prefix, action, state, evidence, None)


def ledger(*entries):
    return CaseLedger("c", SUBJECT, tuple(entries))


@pytest.mark.parametrize("key", sorted(RULES))
def test_every_rule_produces_its_documented_operations(key):
    action, state = key
    finding, remediation, verification = RULES[key]
    status, steps = plan_steps(ledger(entry("thing_100", action, state)))
    ops = [s["operation"] for s in steps]
    assert ops == [o for o in (finding, remediation, verification) if o]
    assert status == ("INCOMPLETE" if finding else "COMPLETE")
    assert all(s["state"] == OP_STATE[s["operation"]] for s in steps)


def test_phases_and_operations_are_ordered_and_numbered():
    _, steps = plan_steps(ledger(
        entry("account_9", "DELETE", "PRESENT"), entry("data_flow_3", "FLOW", "ACTIVE", "integration_service"),
        entry("analytics_5", "ANONYMIZE", "IDENTIFIABLE", "analytics_platform"),
        entry("audit_record_1", "RETAIN", "PRESENT", "security_service"),
        entry("backup_2", "RETAIN", "ACTIVE", "backup_service")))
    assert [s["step_no"] for s in steps] == list(range(1, len(steps) + 1))
    keys = [(PHASE_ORDER[s["phase"]], OPERATION_ORDER.index(s["operation"])) for s in steps]
    assert keys == sorted(keys)
    remediation = [s["operation"] for s in steps if s["phase"] == "REMEDIATION"]
    assert remediation == ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "ANONYMIZE_RECORD"]


def test_resource_ids_sort_as_strings_within_a_group():
    # "ascending order" is read literally as string order; the 32 reference answers cannot tell it
    # from numeric order, so this test records the decision.
    _, steps = plan_steps(ledger(entry("audit_record_987", "RETAIN", "PRESENT", "security_service"),
                                 entry("audit_record_1596", "RETAIN", "PRESENT", "security_service")))
    assert [s["resource_id"] for s in steps] == ["audit_record_1596", "audit_record_987"]


def test_complete_cases_cite_evidence_and_incomplete_cases_only_cite_findings():
    status, steps = plan_steps(ledger(entry("account_9", "DELETE", "ABSENT", evidence="evidence_7")))
    assert status == "COMPLETE" and [s["evidence_id"] for s in steps] == ["evidence_7"]
    status, steps = plan_steps(ledger(entry("account_9", "DELETE", "PRESENT", evidence="evidence_7")))
    assert status == "INCOMPLETE"
    assert {s["phase"]: s["evidence_id"] for s in steps} == {"FINDING": "evidence_7", "REMEDIATION": "", "VERIFICATION": ""}


def test_one_open_finding_makes_the_whole_case_incomplete():
    status, steps = plan_steps(ledger(entry("account_9", "DELETE", "ABSENT"),
                                      entry("search_4", "DELETE", "PRESENT", "search_service")))
    assert status == "INCOMPLETE"
    assert all(s["evidence_id"] == "" for s in steps if s["phase"] != "FINDING")


def test_an_empty_ledger_is_complete_with_no_steps():
    assert plan_steps(ledger()) == ("COMPLETE", [])
