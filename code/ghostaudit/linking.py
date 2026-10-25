"""Find the resources that belong to a subject.

A resource belongs to a subject when an evidence record carrying one of the subject's strong
identifiers (current or historical email, email hash, phone, user id) also names the resource.
Which resources belong to a case does not depend on time: only a resource's state does, and
that is handled in state.py and ledger.py. Names never link anything.
"""
from __future__ import annotations

from collections import defaultdict

from .evidence import EvidenceIndex, EvidenceRecord
from .identity import Subject

LINKING_KINDS = ("json_record", "sql_row", "log_trace", "log_line", "text_line", "document", "document_line")


def link_resources(subject: Subject, index: EvidenceIndex) -> dict[str, list[EvidenceRecord]]:
    """resource_id -> records that tie it to the subject.

    Time is not applied here. The ledger decides whether a resource linked only by evidence that
    predates the request still counts.
    """
    text_files = {r.file_id for r in index.records if r.kind == "text_line"}
    linked: dict[str, list[EvidenceRecord]] = defaultdict(list)
    seen: set[tuple[int, str]] = set()
    for value in sorted(subject.strong_values()):
        for rec in index.for_identifier(value):
            if rec.kind not in LINKING_KINDS:
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
