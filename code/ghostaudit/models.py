"""Typed records for every participant-facing table in dataset/."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True, slots=True)
class Identity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class AuditEvent:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True, slots=True)
class Activity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True, slots=True)
class EvidenceFile:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime
    abs_path: Path


@dataclass(frozen=True, slots=True)
class Dataset:
    root: Path
    requests: tuple[DeletionRequest, ...]
    sample_requests: tuple[DeletionRequest, ...]
    identities: tuple[Identity, ...]
    audit_log: tuple[AuditEvent, ...]
    activity: tuple[Activity, ...]
    rules: tuple[Rule, ...]
    evidence_files: tuple[EvidenceFile, ...]
    # case_id -> (deletion_status, parsed steps). Used only by the evaluator.
    sample_output: dict[str, tuple[str, list[dict]]] = field(default_factory=dict)
