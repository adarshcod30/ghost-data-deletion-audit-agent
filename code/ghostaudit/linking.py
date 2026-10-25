"""Find the resources that belong to a subject.

A resource belongs to a subject when an evidence record carrying one of the subject's strong
identifiers (current or historical email, email hash, phone, user id) also names the resource.
Which resources belong to a case does not depend on time: only a resource's state does, and
that is handled in state.py and ledger.py. Names never link anything.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from .evidence import EvidenceIndex, EvidenceRecord
from .identity import Subject

RETAINED_PREFIXES = ("audit_record", "legal_hold")


def admissible(rec: EvidenceRecord, audit_at: datetime) -> bool:
    """May this record establish anything about a case audited at `audit_at`?

    Evidence created later must not change the answer, so a record counts only if it is dated at or
    before audit_at: its own timestamp when it has one, otherwise the capture time of its file.
    A retained record (security audit log, legal hold) inside a snapshot carries no timestamp and is
    append-only, so its existence in any snapshot is accepted.
    """
    if rec.record_time is not None:
        return rec.record_time <= audit_at
    if rec.resource_id and rec.resource_id.rsplit("_", 1)[0] in RETAINED_PREFIXES:
        return True
    return rec.captured_at <= audit_at


LINKING_KINDS = ("json_record", "sql_row", "log_trace", "log_line", "text_line", "document", "document_line")


def link_resources(subject: Subject, index: EvidenceIndex, audit_at: datetime | None = None) -> dict[str, list[EvidenceRecord]]:
    """resource_id -> records that tie it to the subject.

    When `audit_at` is given, only records admissible at that time link anything. Whether a resource
    linked only by evidence that predates the request still counts is decided in the ledger.
    """
    text_files = {r.file_id for r in index.records if r.kind == "text_line"}
    linked: dict[str, list[EvidenceRecord]] = defaultdict(list)
    seen: set[tuple[int, str]] = set()
    for value in sorted(subject.strong_values()):
        for rec in index.for_identifier(value):
            if rec.kind not in LINKING_KINDS:
                continue
            if audit_at is not None and not admissible(rec, audit_at):
                continue
            if rec.kind == "document" and rec.file_id in text_files:
                continue  # a whole shift handover lists many people; its lines link, not the document
            if rec.kind == "document" and (len(rec.mentions) != 1 or len(rec.emails) > 1):
                continue  # a document that names several people or records links by line, never as a whole
            if rec.kind in ("log_line", "text_line", "document_line"):
                resources = (rec.resource_id,) if rec.resource_id else ()
            elif rec.kind in ("json_record", "sql_row"):
                resources = rec.mentions
            else:  # log_trace and document: every resource named in the same trace or document
                resources = rec.mentions
            for rid in resources:
                key = (id(rec), rid)
                if key not in seen:
                    seen.add(key)
                    linked[rid].append(rec)
    return dict(linked)
