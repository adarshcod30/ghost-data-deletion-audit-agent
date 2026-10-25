"""Turn an evidence record into an observation of one resource's state.

An observation says what one piece of evidence shows about one resource at one time. States:

  PRESENT       the record exists (account, search entry, export, audit record, ...)
  ABSENT        a lookup or snapshot shows the record is gone
  IDENTIFIABLE  the record exists and still exposes direct identifiers (analytics, support, tombstone)
  ANONYMIZED    an analytics/telemetry record with no direct identifier left
  REDACTED      a support or tombstone record with the identifying fields removed
  ACTIVE        a data flow that is enabled, or a backup whose restore is allowed
  DISABLED      a data flow that is switched off
  BLOCKED       a backup whose restore is blocked

Field names differ by dialect (log key=value, JSON exports, SQL columns, handover text), so
interpretation is keyed by resource type and reads the vocabulary measured from the evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .common import parse_ts
from .evidence import EvidenceRecord, resource_prefix

NULLS = {None, "", "null", "None", "none", "NULL"}
DIRECT_IDENTIFIER_FIELDS = ("email", "phone", "email_hash", "owner_email", "requester_email",
                            "customer_email", "full_name", "name", "requester_name", "requester_phone",
                            "owner_phone", "display_name")
REFERENCE_FIELDS = ("customer_reference", "user_id", "subject_reference")


@dataclass(frozen=True, slots=True)
class Observation:
    resource_id: str
    state: str
    time: datetime
    file_id: str
    file_captured_at: datetime
    kind: str            # record kind the observation came from
    locator: str
    subtype: str = ""    # e.g. attachment for support attachments


def is_null(value) -> bool:
    return value in NULLS or (isinstance(value, str) and value.strip() in NULLS)


def truthy(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().casefold()
    if text in ("true", "1", "yes", "enabled", "active"):
        return True
    if text in ("false", "0", "no", "disabled", "blocked", "stopped"):
        return False
    return None


def has_direct_identifier(fields: dict) -> bool:
    return any(not is_null(fields.get(k)) for k in DIRECT_IDENTIFIER_FIELDS)


def observation_time(rec: EvidenceRecord) -> datetime:
    snapshot = rec.fields.get("_snapshot_at")
    if rec.record_time is not None:
        return rec.record_time
    if isinstance(snapshot, str):
        try:
            return parse_ts(snapshot)
        except ValueError:
            pass
    return rec.captured_at


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def interpret(rec: EvidenceRecord, resource_id: str) -> Observation | None:
    """State of `resource_id` as shown by this record, or None when the record has no outcome.

    Only a record whose primary resource is `resource_id` may speak for it: a search document
    that merely carries a source account id says nothing about that account.
    """
    if rec.resource_id != resource_id:
        return None
    f = rec.fields
    prefix = resource_prefix(resource_id)
    event = str(f.get("event", ""))
    if event.endswith("_started") or event in ("connection_acquired", "dependency_retry", "thumbnail_failed"):
        return None  # a lookup that has not reported its result
    result = str(f.get("result", "")).upper()
    rows, http = _int(f.get("rows")), _int(f.get("http_status") or f.get("status_code"))
    state, subtype = None, ""

    if prefix == "account":
        status = f.get("account_status")
        if rec.kind in ("sql_row", "json_record") and not is_null(status):
            state = "PRESENT"   # the record's own live fields outrank a stray result or rows claim inside it
        elif result == "NOT_FOUND" or rows == 0 or http == 404:
            state = "ABSENT"
        elif result == "FOUND" or rows == 1 or http == 200 or not is_null(status):
            state = "PRESENT"
        elif rec.kind in ("sql_row", "json_record") and not is_null(f.get("email")):
            state = "PRESENT"
    elif prefix in ("analytics", "telemetry"):
        if event == "contact_lookup_completed" or "email_opt_in" in f:
            state, subtype = "PRESENT", "marketing"  # an opt-in contact held in the analytics platform
        elif result in ("IDENTIFIABLE", "ANONYMIZED"):
            state = result
        elif event == "analytics_identity_scan" or not is_null(f.get("matched_value")):
            state = "IDENTIFIABLE"
        elif "email" in f or "customer_reference" in f or event.startswith("analytics_profile_read"):
            direct = any(not is_null(f.get(k)) for k in ("email", "phone", "email_hash", "customer_reference", "user_id"))
            state = "IDENTIFIABLE" if direct else "ANONYMIZED"
        elif rec.kind in ("json_record", "sql_row"):  # a structured row is read by its columns, whichever keys it carries
            direct = any(not is_null(f.get(k)) for k in ("email", "phone", "email_hash", "customer_reference", "user_id"))
            state = "IDENTIFIABLE" if direct else "ANONYMIZED"
    elif prefix == "support":
        is_attachment_row = (not is_null(f.get("file_name")) or str(f.get("storage_class", "")).casefold() == "ticket_attachment"
                             or str(f.get("collection_name", "")).casefold() == "ticket_attachments")
        if is_attachment_row or "attachment" in event or str(f.get("record_type", "")).upper() == "SUPPORT_ATTACHMENT" or rec.kind in ("document", "document_line"):
            subtype = "attachment"
            state = "PRESENT"
        elif event in ("contact_query_completed", "deletion_marker_check"):
            subtype = "attachment"  # a contact or attachment record: policy deletes it rather than redacts
            state = "PRESENT" if (rows == 1 or truthy(f.get("marker_found")) is False) else None
        else:
            subtype = "message"
            if result in ("IDENTIFIABLE", "REDACTED"):
                state = result
            elif event == "message_pii_scan" or not is_null(f.get("matched_value")):
                state = "IDENTIFIABLE"
            elif any(k in f for k in ("requester_email", "message_text", "message_excerpt")) or event in ("support_ticket_read_completed", "message_read"):
                direct = any(not is_null(f.get(k)) for k in ("requester_email", "requester_name", "requester_phone"))
                state = "IDENTIFIABLE" if direct else "REDACTED"
    elif prefix == "tombstone":
        direct = any(not is_null(f.get(k)) for k in ("name", "email", "phone", "email_hash"))
        if result == "NOT_FOUND" or rows == 0 or http == 404:
            state = "ABSENT"    # a lookup that finds nothing is not a redacted tombstone
        else:
            state = result if result in ("IDENTIFIABLE", "REDACTED") else ("IDENTIFIABLE" if direct else "REDACTED")
    elif prefix == "backup":
        allowed = truthy(f.get("restore_allowed"))
        eligible, blocked = truthy(f.get("eligible")), truthy(f.get("deletion_block"))
        decision = str(f.get("decision", "")).casefold()
        if result in ("ACTIVE", "BLOCKED"):
            state = result
        elif decision in ("deny", "denied", "blocked", "block"):
            state = "BLOCKED"   # the restore was refused by the deletion policy
        elif decision in ("allow", "allowed", "approve", "approved", "grant", "granted"):
            state = "ACTIVE"
        elif allowed is not None:
            state = "ACTIVE" if allowed else "BLOCKED"
        elif eligible is not None:
            state = "ACTIVE" if (eligible and not blocked) else "BLOCKED"
    elif prefix == "data_flow":
        enabled = truthy(f.get("enabled"))
        if result in ("ACTIVE", "DISABLED"):
            state = result
        elif enabled is not None:
            state = "ACTIVE" if enabled else "DISABLED"
    elif prefix == "search":
        hits = _int(f.get("total_hits"))
        if result == "NOT_FOUND" or hits == 0 or rows == 0:
            state = "ABSENT"
        elif result in ("HIT", "FOUND") or hits or rec.kind in ("sql_row", "json_record"):
            state = "PRESENT"
    elif prefix == "export":
        avail = truthy(f.get("download_available"))
        avail = truthy(f.get("available")) if avail is None else avail
        if result == "NOT_FOUND" or avail is False:
            state = "ABSENT"
        elif result == "FOUND" or avail or rec.kind in ("sql_row", "json_record", "text_line"):
            state = "PRESENT"
    else:  # audit_record, legal_hold, marketing, cache, object, email_delivery and the rest
        if result == "NOT_FOUND" or rows == 0:
            state = "ABSENT"
        elif (result in ("FOUND", "PRESENT") or rec.kind in ("sql_row", "json_record", "text_line", "document", "document_line")
              or rows_found(f) or event.endswith(("_completed", "_loaded"))):
            state = "PRESENT"
    if state is None:
        return None
    return Observation(resource_id, state, observation_time(rec), rec.file_id, rec.captured_at,
                       rec.kind, rec.locator, subtype)


def rows_found(fields: dict) -> bool:
    rows = _int(fields.get("rows"))
    return rows is not None and rows > 0
