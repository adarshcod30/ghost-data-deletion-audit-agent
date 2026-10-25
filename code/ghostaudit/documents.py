"""Read PDF and screenshot evidence with a vision model into structured, validated facts.

The text pipeline (pdftotext, tesseract) loses structure: it drops underscores, garbles emails and cannot
tell a headline record from a row that belongs to someone else. A vision model reads the same page as
a reader would. Its answer is accepted only if it passes a strict schema check; an answer that does not
is retried once with the error, then rejected. Every call is cached and counted in the usage ledger.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .llm import BedrockClient, LLMUnavailable, extract_json_object
from .models import EvidenceFile

PROMPT = (Path(__file__).resolve().parents[1] / "prompts" / "document_reader.md").read_text(encoding="utf-8")
DOC_TYPES = {"console_screenshot", "statement", "register", "journal", "attachment", "other"}
KINDS = {"account", "search", "support", "analytics", "export", "backup", "data_flow", "audit_record",
         "marketing", "object", "tombstone", "legal_hold", "order", "other"}
ROLES = {"primary", "listed"}
PLATFORM_ID = re.compile(r"^[a-z]+(?:_[a-z]+)*_\d+$")
PRINTED_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,80}$")  # any identifier printed on the page, e.g. ORD-20264118
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True, slots=True)
class DocumentFacts:
    file_id: str
    document_type: str
    subject: dict
    records: tuple[dict, ...]
    model_id: str
    attempts: int


def validate(obj: object) -> list[str]:
    """Problems with a model answer (empty list when it satisfies the schema)."""
    if not isinstance(obj, dict):
        return ["answer is not a JSON object"]
    problems: list[str] = []
    if set(obj) != {"document_type", "subject", "records"}:
        problems.append(f"top-level keys are {sorted(obj)}")
        return problems
    if obj["document_type"] not in DOC_TYPES:
        problems.append(f"document_type {obj['document_type']!r}")
    subject = obj["subject"]
    if not isinstance(subject, dict) or set(subject) != {"emails", "phones", "user_ids", "names"}:
        problems.append("subject must have emails, phones, user_ids, names")
    else:
        for key, values in subject.items():
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                problems.append(f"subject.{key} must be a list of strings")
        problems += [f"subject email {e!r}" for e in subject.get("emails", []) if isinstance(e, str) and not EMAIL.match(e)]
    if not isinstance(obj["records"], list):
        return problems + ["records must be a list"]
    for i, rec in enumerate(obj["records"]):
        where = f"records[{i}]"
        if not isinstance(rec, dict) or set(rec) != {"resource_id", "resource_kind", "role", "state_text", "emails", "user_ids", "quote"}:
            problems.append(f"{where} has the wrong keys")
            continue
        rid = rec["resource_id"]
        if rid is not None and not (isinstance(rid, str) and PRINTED_ID.match(rid)):
            problems.append(f"{where}.resource_id {rid!r}")
        if rec["resource_kind"] not in KINDS:
            problems.append(f"{where}.resource_kind {rec['resource_kind']!r}")
        if rec["role"] not in ROLES:
            problems.append(f"{where}.role {rec['role']!r}")
        if not isinstance(rec["state_text"], str) or not isinstance(rec["quote"], str):
            problems.append(f"{where} state_text and quote must be strings")
        for key in ("emails", "user_ids"):
            if not isinstance(rec[key], list) or not all(isinstance(v, str) for v in rec[key]):
                problems.append(f"{where}.{key} must be a list of strings")
        problems += [f"{where} email {e!r}" for e in rec["emails"] if isinstance(e, str) and not EMAIL.match(e)] if isinstance(rec["emails"], list) else []
    return problems


def _message(file: EvidenceFile) -> list:
    if file.abs_path.suffix.lower() == ".png":
        content = [{"image": {"format": "png", "source": {"bytes": file.abs_path.read_bytes()}}},
                   {"text": "Read this screenshot and answer with the JSON object only."}]
    else:
        text = subprocess.run(["pdftotext", "-layout", str(file.abs_path), "-"], capture_output=True, text=True, timeout=120).stdout
        content = [{"text": f"<document>\n{text}\n</document>\nRead this document and answer with the JSON object only."}]
    return [{"role": "user", "content": content}]


def read_document(client: BedrockClient, model_id: str, file: EvidenceFile) -> DocumentFacts | None:
    """Structured facts for one document, or None when the model cannot produce a valid answer."""
    messages = _message(file)
    problems: list[str] = []
    for attempt in (1, 2):
        try:
            result = client.converse(model_id, system=PROMPT, messages=messages, max_tokens=2500,
                                     purpose="document_reader")
        except LLMUnavailable:
            return None
        parsed = extract_json_object(result.text)
        problems = validate(parsed)
        if not problems:
            return DocumentFacts(file.file_id, parsed["document_type"], parsed["subject"],
                                 tuple(parsed["records"]), model_id, attempt)
        messages = messages + [{"role": "assistant", "content": [{"text": result.text[:1500] or "{}"}]},
                               {"role": "user", "content": [{"text": "That answer was invalid: " + "; ".join(problems[:5])
                                                             + ". Reply again with one valid JSON object only."}]}]
    return None
