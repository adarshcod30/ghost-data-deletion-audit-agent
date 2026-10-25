from datetime import datetime, timezone

import pytest

from ghostaudit.evidence import EvidenceRecord
from ghostaudit.state import interpret, is_null, truthy

T = datetime(2026, 9, 1, tzinfo=timezone.utc)


def rec(resource_id, fields, kind="log_line", text=""):
    return EvidenceRecord("evidence_1", T, T, kind, "line:1", resource_id, (resource_id,), None,
                          (), (), (), (), fields, text)


@pytest.mark.parametrize("resource,fields,state", [
    ("account_1", {"event": "profile_lookup_completed", "rows": "0", "http_status": "404"}, "ABSENT"),
    ("account_1", {"event": "profile_lookup_completed", "rows": "1", "http_status": "200"}, "PRESENT"),
    ("account_1", {"status_code": 404, "profile": None}, "ABSENT"),
    ("account_1", {"result": "NOT_FOUND"}, "ABSENT"),
    ("account_1", {"account_status": "DELETION_PENDING"}, "PRESENT"),
    ("search_1", {"event": "index_query_completed", "result": "hit"}, "PRESENT"),
    ("search_1", {"event": "index_query_completed", "total_hits": "0"}, "ABSENT"),
    ("data_flow_1", {"event": "connector_heartbeat", "enabled": "true"}, "ACTIVE"),
    ("data_flow_1", {"event": "connector_config_loaded", "enabled": "false"}, "DISABLED"),
    ("data_flow_1", {"enabled": 0}, "DISABLED"),
    ("backup_1", {"event": "restore_policy_read_completed", "restore_allowed": "true"}, "ACTIVE"),
    ("backup_1", {"event": "restore_policy_read_completed", "restore_allowed": "0"}, "BLOCKED"),
    ("backup_1", {"event": "restore_candidate_evaluated", "eligible": "true", "deletion_block": "false"}, "ACTIVE"),
    ("backup_1", {"event": "restore_candidate_evaluated", "eligible": "true", "deletion_block": "true"}, "BLOCKED"),
    ("analytics_1", {"event": "analytics_profile_read_completed", "email": None, "phone": None, "email_hash": None, "customer_reference": None}, "ANONYMIZED"),
    ("analytics_1", {"event": "analytics_profile_read_completed", "email": "a@b.c"}, "IDENTIFIABLE"),
    ("analytics_1", {"event": "analytics_identity_scan", "matched_value": "a@b.c", "detector": "direct_identifier"}, "IDENTIFIABLE"),
    ("support_1", {"event": "message_pii_scan", "matched_value": "a@b.c"}, "IDENTIFIABLE"),
    ("support_1", {"event": "support_ticket_read_completed", "requester_email": None, "requester_name": None, "message_text": "x"}, "REDACTED"),
    ("tombstone_1", {"name": None, "email": None, "phone": None, "email_hash": None}, "REDACTED"),
    ("tombstone_1", {"name": "Ann", "email": None}, "IDENTIFIABLE"),
    ("export_1", {"event": "export_download_check_completed", "available": "true"}, "PRESENT"),
    ("export_1", {"event": "export_download_check_completed", "available": "false"}, "ABSENT"),
    ("audit_record_1", {"event": "audit_record_read_completed", "rows": "1"}, "PRESENT"),
])
def test_state_vocabulary(resource, fields, state):
    got = interpret(rec(resource, fields), resource)
    assert got is not None and got.state == state, (resource, fields, got)


def test_started_events_have_no_outcome():
    assert interpret(rec("account_1", {"event": "profile_lookup_started", "lookup_key": "a@b.c"}), "account_1") is None


def test_only_the_primary_resource_of_a_record_speaks_for_itself():
    """A search document that carries a source account id says nothing about that account."""
    record = rec("search_1", {"source_resource_id": "account_6", "email": "a@b.c"}, kind="sql_row")
    assert interpret(record, "account_6") is None
    assert interpret(record, "search_1").state == "PRESENT"


def test_support_contacts_and_attachments_are_deleted_while_messages_are_redacted():
    contact = interpret(rec("support_2", {"event": "contact_query_completed", "rows": "1"}), "support_2")
    message = interpret(rec("support_3", {"event": "message_pii_scan", "matched_value": "a@b.c"}), "support_3")
    assert (contact.state, contact.subtype) == ("PRESENT", "attachment")
    assert (message.state, message.subtype) == ("IDENTIFIABLE", "message")


def test_helpers():
    assert is_null("null") and is_null(None) and not is_null("x")
    assert truthy("True") is True and truthy("0") is False and truthy("maybe") is None
