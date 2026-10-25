"""Strict loader for dataset/.

The loader validates headers, id uniqueness, enumerations, timestamps, referential
integrity and the existence of every evidence file. It collects every problem it finds
and raises one DatasetError, so a half-broken dataset can never be used silently.
"""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Callable, Iterable, TypeVar

from .common import DATASET_DIR, parse_ts
from .models import (
    Activity,
    AuditEvent,
    Dataset,
    DeletionRequest,
    EvidenceFile,
    Identity,
    Rule,
)

REPORTED_STATUSES = frozenset({"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"})
AUDIT_FIELDS = frozenset({"email", "email_hash", "phone"})
RULE_ACTIONS = frozenset({"DELETE", "REDACT", "ANONYMIZE", "RETAIN"})

HEADERS: dict[str, tuple[str, ...]] = {
    "deletion_requests.csv": (
        "case_id", "email", "requested_at", "reported_status", "reported_at",
        "audit_at", "request_text",
    ),
    "sample_deletion_requests.csv": (
        "case_id", "email", "requested_at", "reported_status", "reported_at",
        "audit_at", "request_text",
    ),
    "sample_output.csv": ("case_id", "deletion_status", "steps_json"),
    "user_identities.csv": ("user_id", "name", "email", "phone", "email_hash", "updated_at"),
    "user_audit_log.csv": (
        "audit_id", "user_id", "event_time", "field_name", "old_value", "new_value",
    ),
    "system_activity.csv": (
        "activity_id", "event_time", "event_type", "source_system", "target_system",
        "resource_id", "reported_result", "details",
    ),
    "deletion_rules.csv": ("rule_id", "data_category", "condition", "required_action"),
    "evidence_files.csv": ("file_id", "file_path", "origin", "captured_at"),
}

T = TypeVar("T")


class DatasetError(Exception):
    """Raised with every validation problem found, one per line."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        shown = problems[:25]
        more = f"\n... and {len(problems) - 25} more" if len(problems) > 25 else ""
        super().__init__("dataset validation failed:\n" + "\n".join(shown) + more)


def _read_rows(path: Path, name: str, problems: list[str]) -> list[dict[str, str]]:
    if not path.is_file():
        problems.append(f"{name}: file not found at {path}")
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        header = tuple(reader.fieldnames or ())
        if header != HEADERS[name]:
            problems.append(f"{name}: header {header} != expected {HEADERS[name]}")
            return []
        return list(reader)


def _build(
    rows: Iterable[dict[str, str]],
    name: str,
    id_field: str,
    factory: Callable[[dict[str, str]], T],
    problems: list[str],
) -> tuple[T, ...]:
    """Convert rows to records, reporting bad rows and duplicate ids."""
    out: list[T] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=2):  # line 1 is the header
        key = row.get(id_field, "")
        if not key:
            problems.append(f"{name}:{index}: empty {id_field}")
            continue
        if key in seen:
            problems.append(f"{name}:{index}: duplicate {id_field} {key!r}")
            continue
        seen.add(key)
        try:
            out.append(factory(row))
        except (ValueError, KeyError) as exc:
            problems.append(f"{name}:{index}: {key}: {exc}")
    return tuple(out)


def _request(row: dict[str, str]) -> DeletionRequest:
    if row["reported_status"] not in REPORTED_STATUSES:
        raise ValueError(f"bad reported_status {row['reported_status']!r}")
    return DeletionRequest(
        case_id=row["case_id"],
        email=row["email"],
        requested_at=parse_ts(row["requested_at"]),
        reported_status=row["reported_status"],
        reported_at=parse_ts(row["reported_at"]),
        audit_at=parse_ts(row["audit_at"]),
        request_text=row["request_text"],
    )


def _identity(row: dict[str, str]) -> Identity:
    return Identity(
        user_id=row["user_id"], name=row["name"], email=row["email"], phone=row["phone"],
        email_hash=row["email_hash"], updated_at=parse_ts(row["updated_at"]),
    )


def _audit(row: dict[str, str]) -> AuditEvent:
    if row["field_name"] not in AUDIT_FIELDS:
        raise ValueError(f"bad field_name {row['field_name']!r}")
    return AuditEvent(
        audit_id=row["audit_id"], user_id=row["user_id"],
        event_time=parse_ts(row["event_time"]), field_name=row["field_name"],
        old_value=row["old_value"], new_value=row["new_value"],
    )


def _activity(row: dict[str, str]) -> Activity:
    return Activity(
        activity_id=row["activity_id"], event_time=parse_ts(row["event_time"]),
        event_type=row["event_type"], source_system=row["source_system"],
        target_system=row["target_system"], resource_id=row["resource_id"],
        reported_result=row["reported_result"], details=row["details"],
    )


def _rule(row: dict[str, str]) -> Rule:
    if row["required_action"] not in RULE_ACTIONS:
        raise ValueError(f"bad required_action {row['required_action']!r}")
    return Rule(
        rule_id=row["rule_id"], data_category=row["data_category"],
        condition=row["condition"], required_action=row["required_action"],
    )


def load_dataset(dataset_dir: Path | None = None) -> Dataset:
    """Load and validate every participant-facing table.

    sample_output.csv is parsed because the evaluator needs it, but nothing on the
    prediction path may read Dataset.sample_output.
    """
    root = (dataset_dir or DATASET_DIR).resolve()
    problems: list[str] = []

    def rows(name: str) -> list[dict[str, str]]:
        return _read_rows(root / name, name, problems)

    requests = _build(rows("deletion_requests.csv"), "deletion_requests.csv", "case_id", _request, problems)
    samples = _build(rows("sample_deletion_requests.csv"), "sample_deletion_requests.csv", "case_id", _request, problems)
    identities = _build(rows("user_identities.csv"), "user_identities.csv", "user_id", _identity, problems)
    audit = _build(rows("user_audit_log.csv"), "user_audit_log.csv", "audit_id", _audit, problems)
    activity = _build(rows("system_activity.csv"), "system_activity.csv", "activity_id", _activity, problems)
    rules = _build(rows("deletion_rules.csv"), "deletion_rules.csv", "rule_id", _rule, problems)

    evidence_rows = rows("evidence_files.csv")

    def _evidence(row: dict[str, str]) -> EvidenceFile:
        return EvidenceFile(
            file_id=row["file_id"], file_path=row["file_path"], origin=row["origin"],
            captured_at=parse_ts(row["captured_at"]), abs_path=root / row["file_path"],
        )

    evidence = _build(evidence_rows, "evidence_files.csv", "file_id", _evidence, problems)

    # Referential integrity.
    user_ids = {i.user_id for i in identities}
    for event in audit:
        if event.user_id not in user_ids:
            problems.append(f"user_audit_log.csv: {event.audit_id}: unknown user {event.user_id}")
    for item in evidence:
        if not Path(os.path.normpath(item.abs_path)).is_relative_to(root):   # lexical: blocks ../, allows a symlinked evidence folder
            problems.append(f"evidence_files.csv: {item.file_id}: path leaves the dataset folder")
            continue
        if not item.abs_path.is_file():
            problems.append(f"evidence_files.csv: {item.file_id}: missing file {item.file_path}")
    overlap = {r.case_id for r in requests} & {r.case_id for r in samples}
    if overlap:
        problems.append(f"case ids present in both requests and samples: {sorted(overlap)[:5]}")

    sample_output: dict[str, tuple[str, list[dict]]] = {}
    for index, row in enumerate(rows("sample_output.csv"), start=2):
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError as exc:
            problems.append(f"sample_output.csv:{index}: {row['case_id']}: bad steps_json ({exc})")
            continue
        sample_output[row["case_id"]] = (row["deletion_status"], steps)

    if problems:
        raise DatasetError(problems)
    return Dataset(
        root=root, requests=requests, sample_requests=samples, identities=identities,
        audit_log=audit, activity=activity, rules=rules, evidence_files=evidence,
        sample_output=sample_output,
    )
