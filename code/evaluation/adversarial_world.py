"""Synthetic datasets for adversarial tests: tiny, fictional (example.test addresses, 555 numbers), built in a temp dir.

World writes the same CSV and evidence formats as the challenge dataset, so the real loader, indexer and pipeline run
unchanged. Nothing here reads dataset/ except deletion_rules.csv, the supplied policy.
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghostaudit.common import DATASET_DIR  # noqa: E402
from ghostaudit.data import load_dataset  # noqa: E402
from ghostaudit.pipeline import Pipeline  # noqa: E402
from ghostaudit.verify import verify_row  # noqa: E402

REQUESTED, REPORTED, AUDIT = "2026-06-10T08:00:00Z", "2026-06-12T02:00:00Z", "2026-06-14T12:00:00Z"
EARLY, MID, LATE = "2026-06-01T10:00:00Z", "2026-06-13T10:00:00Z", "2026-06-20T10:00:00Z"
SYSTEMS = {"account": "account_service", "search": "search_service", "analytics": "analytics_platform",
           "support": "support_platform", "backup": "backup_service", "data_flow": "integration_service",
           "audit_record": "security_service", "legal_hold": "legal_service", "tombstone": "identity_service",
           "export": "export_service"}


def sha(email: str) -> str:
    return hashlib.sha256(email.strip().casefold().encode()).hexdigest()


class World:
    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="adversarial_"))
        self.users: list[dict] = []
        self.audit: list[list[str]] = []
        self.files: list[tuple[str, str, str, str]] = []   # file_id, path, origin, captured_at
        self.n = 0
        self.add_user("user_1", "Alice Example", "alice@example.test", "+1 202 555 0101")
        self.add_user("user_2", "Alice Example", "alice@examp1e.test", "+1 202 555 0102")
        # a neutral export of unrelated people teaches the indexer which system owns each id prefix, as the real bundles do
        neutral = [(SYSTEMS[p], f"{p}_collection", [{"resource_id": f"{p}_9900", "customer_reference": "user_99", "email": "other.person@example.test", "updated_at": "2026-01-01T00:00:00Z"}])
                   for p in sorted(SYSTEMS)]
        body = {"exported_at": "2026-01-01T00:00:00Z", "source": "test", "snapshots": [
            {"captured_at": "2026-01-01T00:00:00Z", "data_store": s, "collection": c, "records": r} for s, c, r in neutral]}
        path = self.root / "evidence/records/evidence_00.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body), encoding="utf-8")
        self.files.append(("evidence_00", "evidence/records/evidence_00.json", "test_export", "2026-01-01T00:00:00Z"))

    def add_user(self, user_id, name, email, phone, updated="2026-05-01T00:00:00Z") -> None:
        self.users.append({"user_id": user_id, "name": name, "email": email, "phone": phone, "email_hash": sha(email), "updated_at": updated})

    def change_email(self, user_id, old, new, when="2026-05-20T00:00:00Z") -> None:
        for u in self.users:
            if u["user_id"] == user_id:
                u["email"], u["email_hash"] = new, sha(new)
        self.audit.append([f"audit_{len(self.audit) + 1}", user_id, when, "email", old, new])
        self.audit.append([f"audit_{len(self.audit) + 1}", user_id, when, "email_hash", sha(old), sha(new)])

    def change_phone(self, user_id, old, new, when="2026-05-20T00:00:00Z") -> None:
        for u in self.users:
            if u["user_id"] == user_id:
                u["phone"] = new
        self.audit.append([f"audit_{len(self.audit) + 1}", user_id, when, "phone", old, new])

    def _file(self, captured: str, suffix: str, content: str, origin: str = "test_export") -> str:
        self.n += 1
        file_id = f"evidence_{self.n:02d}"
        rel = f"evidence/records/{file_id}.{suffix}"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.files.append((file_id, rel, origin, captured))
        return file_id

    def json_file(self, captured: str, snapshots: list[tuple[str, str, list[dict]]], snap_at: str | None = None) -> str:
        """snapshots: (data_store, collection, records)."""
        body = {"exported_at": captured, "source": "test", "snapshots": [
            {"captured_at": snap_at or captured, "data_store": s, "collection": c, "records": r} for s, c, r in snapshots]}
        return self._file(captured, "json", json.dumps(body, indent=1))

    def log_file(self, captured: str, lines: list[str]) -> str:
        return self._file(captured, "log", "\n".join(lines) + "\n", "central_observability_export")

    def raw_file(self, captured: str, suffix: str, content: str) -> str:
        return self._file(captured, suffix, content)

    @staticmethod
    def lookup(resource: str, email: str, when: str, found: bool, service: str = "account_service", trace: str = "t1") -> list[str]:
        tail = "rows=1 http_status=200" if found else "rows=0 http_status=404"
        return [f"{when} level=DEBUG service={service} trace_id={trace} event=profile_lookup_started resource_id={resource} lookup_key={email}",
                f"{when} level=INFO service={service} trace_id={trace} event=profile_lookup_completed resource_id={resource} {tail}"]

    def build(self, email: str = "alice@example.test", status: str = "COMPLETE") -> Pipeline:
        # the activity log teaches the indexer which system owns each id prefix, as in the real dataset
        activity = [[f"activity_{i}", "2026-01-02T00:00:00Z", "DELETE_RECORD", "deletion_worker", system, f"{prefix}_9{i:03d}", "SUCCESS", "decoy"]
                    for i, (prefix, system) in enumerate(sorted(SYSTEMS.items()), start=1)]
        def write(name, header, rows):
            with (self.root / name).open("w", newline="", encoding="utf-8") as h:
                w = csv.writer(h)
                w.writerow(header)
                w.writerows(rows)
        req_header = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
        text = "Please permanently delete my account and all personal data."
        write("deletion_requests.csv", req_header, [["case_1", email, REQUESTED, status, REPORTED, AUDIT, text]])
        write("sample_deletion_requests.csv", req_header, [])
        write("sample_output.csv", ["case_id", "deletion_status", "steps_json"], [])
        write("user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
              [[u[k] for k in ("user_id", "name", "email", "phone", "email_hash", "updated_at")] for u in self.users])
        write("user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], self.audit)
        write("system_activity.csv", ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"], activity)
        write("evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], [list(f) for f in self.files])
        shutil.copy(DATASET_DIR / "deletion_rules.csv", self.root / "deletion_rules.csv")
        self.dataset = load_dataset(self.root)
        return Pipeline(self.dataset)

    def answer(self, email: str = "alice@example.test", status: str = "COMPLETE"):
        pipeline = self.build(email, status)
        request = self.dataset.requests[0]
        answer = pipeline.answer(request)
        times = {f.file_id: f.captured_at for f in self.dataset.evidence_files}
        times.update({a.activity_id: a.event_time for a in self.dataset.activity})
        unidentified = answer.status == "COMPLETE" and not answer.steps and answer.note.startswith("no resource")
        problems = verify_row(request.case_id, answer.status, answer.steps, request.audit_at, times, allow_unidentified=unidentified)
        return answer, problems

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


PHONES = {"user_1": "+1 202 555 0101", "user_2": "+1 202 555 0102"}


def acct(rid, user="user_1", email="alice@example.test", when=None, status="ACTIVE", **extra) -> dict:
    rec = {"resource_id": rid, "customer_reference": user, "full_name": "Alice Example", "email": email,
           "phone": PHONES.get(user, "+1 202 555 0777"), "account_status": status}
    if when:
        rec["updated_at"] = when
    rec.update(extra)
    return rec
