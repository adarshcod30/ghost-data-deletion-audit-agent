"""Evidence indexer: every file under dataset/evidence/ becomes normalised records.

A record is one unit of evidence (a log line, a log trace, a JSON record, a SQL row, a line
of a document) with the identifiers found in it. Matching later uses emails, email hashes,
phones, user ids and resource ids. Names are deliberately not indexed as identifiers.

Dialects handled
  sql   executed in an in-memory SQLite with an authorizer that only allows creating tables and
        inserting rows; every row of every table becomes a record, topology and snapshot time
        come from the header comments
  json  every dict carrying a resource id is a record; the nearest enclosing system key or
        data_store value gives its system
  log   six line styles (key=value, bracketed, JSON, syslog, pipe separated, cloud runtime with a
        nested message); lines sharing a trace id are also grouped into one log_trace record
        because an email and its resource id often sit on different lines of one trace
  txt   the pipe separated handover lines, plus every line as a generic unit
  pdf   pdftotext -layout; one record per document plus one per line
  png   tesseract OCR (cached); same shape as pdf. OCR text is lower confidence, flagged ocr=True

Resource id prefixes are not hardcoded: they are learned from system_activity.csv. The mapping
from a resource id prefix to its system is learned from evidence that states both, and any
prefix that maps to two systems is reported as a conflict.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .common import REPO_ROOT, case_sort_key, normalize_email, normalize_phone, parse_ts
from .models import Activity, Dataset, EvidenceFile

OCR_CACHE_DIR = REPO_ROOT / ".cache" / "ocr"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
PHONE_RE = re.compile(r"(?<![\w+])\+\d[\d ()\-]{6,18}\d")
USER_RE = re.compile(r"(?<![A-Za-z0-9_])user_\d+(?![A-Za-z0-9_])")
KV_RE = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|[^\s]+)')
TS_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:]+(?:\.\d+)?Z)\s+(.*)$")
TRACE_RE = re.compile(r"\b((?:tr|rb)-[A-Za-z0-9-]+)\b")
BRACKET_RE = re.compile(r"^\[(\w+)\]\s+\[([\w-]+)\]\s+\[([\w-]+)\]\s+(\w+):\s*(.*)$")
SYSLOG_RE = re.compile(r"^<\d+>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$")
HANDOVER_RE = re.compile(r"^-\s+(\S+)\s+\|\s+(\w+)\s+\|\s+(\S+)\s+\|\s+(\w+)\s+\|\s+(\w+)\s+\|\s+(.*)$")
TIME_KEYS = ("observed_at", "recorded_at", "updated_at", "created_at", "event_time", "timestamp",
             "captured_at", "exported_at", "last_write")


class EvidenceIndexError(Exception):
    """The index does not cover every evidence file, or a file could not be parsed."""


@dataclass(frozen=True, slots=True, eq=False)
class EvidenceRecord:
    file_id: str
    captured_at: datetime            # when the file was captured (from the manifest)
    record_time: datetime | None     # time stated inside the record, if any
    kind: str                        # sql_row | json_record | log_line | log_trace | text_line | document | document_line
    locator: str                     # where in the file: line number, table:rowid, json path
    resource_id: str | None          # primary resource id, if the unit names exactly one
    mentions: tuple[str, ...]        # every resource id found in the unit
    system: str | None               # system stated by the unit itself (not inferred)
    emails: tuple[str, ...]
    hashes: tuple[str, ...]
    phones: tuple[str, ...]
    user_ids: tuple[str, ...]
    fields: dict = field(default_factory=dict)
    text: str = ""
    ocr: bool = False


@dataclass(frozen=True, slots=True)
class Scope:
    """What a file covers: a system's table or collection as it stood at snapshot_at.

    Absence is proved by scope, not by mention: if a file covers account_service at a time
    and does not contain a record, the record was not there.
    """
    file_id: str
    system: str | None
    collection: str | None
    snapshot_at: datetime
    kind: str                 # sql_table | sql_snapshot_scope | json_snapshot | service_export
    topology: str | None
    row_count: int


class ResourcePatterns:
    """The exact resource id pattern for machine text and the tolerant one for OCR text."""

    def __init__(self, prefixes: Iterable[str]) -> None:
        prefixes = list(prefixes)
        self.exact = compile_resource_re(prefixes)
        self.ocr = compile_ocr_resource_re(prefixes)

    def fullmatch(self, text: str):
        return self.exact.fullmatch(text)


def _collect_ids(text: str, resource_re, ocr: bool = False) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    emails = sorted({normalize_email(m) for m in EMAIL_RE.findall(text)})
    hashes = sorted({m.casefold() for m in HASH_RE.findall(text)})
    phones = sorted({p for p in (normalize_phone(m) for m in PHONE_RE.findall(text)) if 8 <= len(p) <= 16})
    users = sorted({m.casefold() for m in USER_RE.findall(text)})
    mentions: list[str] = []
    pattern = resource_re.ocr if ocr and hasattr(resource_re, "ocr") else getattr(resource_re, "exact", resource_re)
    for m in pattern.finditer(text):
        rid = normalize_ocr_resource(m.group(0)) if ocr else m.group(0)
        if rid not in mentions:
            mentions.append(rid)
    return tuple(emails), tuple(hashes), tuple(phones), tuple(users), tuple(mentions)


def _first_time(fields: dict) -> datetime | None:
    for key in TIME_KEYS:
        value = fields.get(key)
        if isinstance(value, str):
            try:
                return parse_ts(value)
            except ValueError:
                continue
    return None


def prefixes_from_activity(activity: Iterable[Activity]) -> list[str]:
    """Resource id prefixes (account, data_flow, audit_record, ...) learned from the activity log."""
    prefixes = {a.resource_id.rsplit("_", 1)[0] for a in activity if "_" in a.resource_id}
    prefixes.discard("user")
    return sorted(prefixes, key=lambda p: (-len(p), p))


def compile_resource_re(prefixes: Iterable[str]) -> re.Pattern:
    alternation = "|".join(re.escape(p) for p in sorted(set(prefixes), key=lambda p: (-len(p), p)))
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{alternation})_\d+(?![A-Za-z0-9_])")


def compile_ocr_resource_re(prefixes: Iterable[str]) -> re.Pattern:
    """Like compile_resource_re but for OCR text, where an underscore is often read as a space or a
    dash ("export 1260"). At least three digits are required so ordinary prose does not match."""
    parts = []
    for p in sorted(set(prefixes), key=lambda p: (-len(p), p)):
        parts.append(re.escape(p).replace("_", "[ _]"))
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{'|'.join(parts)})[ _\-]+\d{{3,}}(?![A-Za-z0-9_])", re.I)


def normalize_ocr_resource(raw: str) -> str:
    return re.sub(r"[ \-]+", "_", raw.strip().lower()).replace("__", "_")


def resource_prefix(resource_id: str) -> str:
    return resource_id.rsplit("_", 1)[0]


# --------------------------------------------------------------------------- parsing helpers
def parse_kv(text: str) -> dict:
    fields: dict = {}
    for key, raw in KV_RE.findall(text):
        value = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\") if raw.startswith('"') else raw.rstrip(",;")
        fields.setdefault(key, value)
    # cloud runtime export nests the real key=value pairs inside message="..."
    message = fields.get("message")
    if isinstance(message, str) and "=" in message:
        for key, value in parse_kv(message).items():
            fields.setdefault(key, value)
    return fields


def parse_log_line(line: str) -> tuple[datetime | None, dict]:
    """Return (line time, fields) for any of the log dialects."""
    match = TS_PREFIX_RE.match(line.strip())
    if not match:
        return None, parse_kv(line)
    stamp, rest = match.groups()
    time = parse_ts(stamp)
    fields: dict = {}
    if rest.startswith("{"):
        try:
            data = json.loads(rest)
            if isinstance(data, dict):
                return time, {k: v for k, v in data.items()}
        except json.JSONDecodeError:
            pass
    bracket = BRACKET_RE.match(rest)
    syslog = SYSLOG_RE.match(rest)
    if bracket:
        level, service, trace, event, tail = bracket.groups()
        fields.update(level=level, service=service, trace_id=trace, event=event)
        fields.update({k: v for k, v in parse_kv(tail).items() if k not in fields})
    elif syslog:
        host, service, trace, tail = syslog.groups()
        fields.update(host=host, service=service, trace_id=trace)
        fields.update({k: v for k, v in parse_kv(tail).items() if k not in fields})
    elif " | " in rest and not KV_RE.match(rest):
        parts = [p.strip() for p in rest.split(" | ")]
        if len(parts) >= 5:  # LEVEL | service | trace | event | key=value ...
            fields.update(level=parts[0], service=parts[1], trace_id=parts[2], event=parts[3])
            fields.update({k: v for k, v in parse_kv(" | ".join(parts[4:])).items() if k not in fields})
        else:
            fields.update(parse_kv(rest))
    else:
        bare = re.match(r"^([A-Z]+)\s+(.*)$", rest)
        if bare and "=" in bare.group(2):
            fields["level"] = bare.group(1)
            rest = bare.group(2)
        fields.update({k: v for k, v in parse_kv(rest).items() if k not in fields})
    if "trace_id" not in fields:
        trace = fields.get("requestId") or fields.get("trace")
        if not trace:
            found = TRACE_RE.search(line)
            trace = found.group(1) if found else None
        if trace:
            fields["trace_id"] = trace
    return time, fields


def sql_header(text: str) -> dict:
    header: dict = {}
    for line in text.splitlines():
        if not line.startswith("--"):
            break
        match = re.match(r"--\s*(Captured at|Database topology|Dialect):\s*(.+)$", line)
        if match:
            header[match.group(1).casefold().replace(" ", "_")] = match.group(2).strip()
    return header


def _sql_authorizer(action, arg1, arg2, db, source):
    """Evidence SQL may create tables and indexes and insert rows. The only pragma allowed is
    foreign_keys (several snapshots start with it). ATTACH, other pragmas and anything else are denied."""
    if action == sqlite3.SQLITE_PRAGMA:
        return sqlite3.SQLITE_OK if str(arg1).casefold() == "foreign_keys" else sqlite3.SQLITE_DENY
    allowed = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_SELECT,
               sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_FUNCTION,
               sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_REINDEX, sqlite3.SQLITE_UPDATE,
               sqlite3.SQLITE_SAVEPOINT,
               getattr(sqlite3, "SQLITE_RECURSIVE", -1)}
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


def _ocr_text(path: Path) -> str:
    key = hashlib.sha256(path.read_bytes()).hexdigest()
    cached = OCR_CACHE_DIR / f"{key}.txt"
    if cached.is_file():
        return cached.read_text(encoding="utf-8")
    done = subprocess.run(["tesseract", str(path), "-"], capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise EvidenceIndexError(f"tesseract failed on {path.name}: {done.stderr[:120]}")
    OCR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cached.write_text(done.stdout, encoding="utf-8")
    return done.stdout


def _pdf_text(path: Path) -> str:
    done = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise EvidenceIndexError(f"pdftotext failed on {path.name}: {done.stderr[:120]}")
    return done.stdout


# --------------------------------------------------------------------------- the index
@dataclass
class EvidenceIndex:
    records: list[EvidenceRecord]
    files: dict[str, int]                       # file_id -> record count
    prefix_system: dict[str, str]
    prefix_conflicts: dict[str, set[str]]
    errors: dict[str, str]
    scopes: list = field(default_factory=list)
    file_times: dict = field(default_factory=dict)   # file_id -> manifest capture time (the citable time)
    _by_resource: dict[str, list[int]] = field(default_factory=dict, repr=False)
    _by_identifier: dict[str, list[int]] = field(default_factory=dict, repr=False)

    def _link(self) -> None:
        by_res: dict[str, list[int]] = defaultdict(list)
        by_ident: dict[str, list[int]] = defaultdict(list)
        for i, rec in enumerate(self.records):
            for rid in rec.mentions:
                by_res[rid].append(i)
            for value in (*rec.emails, *rec.hashes, *rec.phones, *rec.user_ids):
                by_ident[value].append(i)
        self._by_resource, self._by_identifier = dict(by_res), dict(by_ident)

    def for_resource(self, resource_id: str) -> list[EvidenceRecord]:
        return [self.records[i] for i in self._by_resource.get(resource_id, ())]

    def for_identifier(self, value: str) -> list[EvidenceRecord]:
        key = value.casefold() if "@" in value or value.startswith("user_") else value
        return [self.records[i] for i in self._by_identifier.get(key, ())]

    def system_of(self, resource_id: str) -> str | None:
        return self.prefix_system.get(resource_prefix(resource_id))

    def scopes_covering(self, file_id: str, system: str) -> list[Scope]:
        """Scopes of one file that cover a system (used to prove a record is absent)."""
        return [sc for sc in self.scopes if sc.file_id == file_id and sc.system == system]


def _mk(file: EvidenceFile, kind: str, locator: str, text: str, fields: dict, resource_re: re.Pattern,
        systems: set[str], context_system: str | None = None, ocr: bool = False,
        forced_time: datetime | None = None) -> EvidenceRecord:
    emails, hashes, phones, users, mentions = _collect_ids(text, resource_re, ocr)
    primary = fields.get("resource_id") if isinstance(fields.get("resource_id"), str) else None
    if primary and primary not in mentions and resource_re.fullmatch(primary):
        mentions = (primary, *mentions)
    if primary is None and len(mentions) == 1:
        primary = mentions[0]
    explicit = None
    for key in ("system", "origin_system", "target_system", "data_store"):
        if isinstance(fields.get(key), str) and fields[key] in systems:
            explicit = fields[key]
            break
    return EvidenceRecord(
        file_id=file.file_id, captured_at=file.captured_at,
        record_time=forced_time or _first_time(fields), kind=kind, locator=locator,
        resource_id=primary, mentions=mentions, system=explicit or context_system,
        emails=emails, hashes=hashes, phones=phones, user_ids=users,
        fields=fields, text=text[:2000], ocr=ocr)


def _index_sql(file: EvidenceFile, resource_re, systems, scopes: list) -> list[EvidenceRecord]:
    text = file.abs_path.read_text(encoding="utf-8")
    header = sql_header(text)
    snapshot_at = parse_ts(header["captured_at"]) if "captured_at" in header else file.captured_at
    conn = sqlite3.connect(":memory:")
    conn.set_authorizer(_sql_authorizer)
    out: list[EvidenceRecord] = []
    try:
        conn.executescript(text)
        conn.set_authorizer(None)
        conn.row_factory = sqlite3.Row
        tables = [r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for table in tables:
            count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            if table == "snapshot_scope":
                for row in conn.execute('SELECT * FROM "snapshot_scope"'):
                    values = list(row)
                    when = next((parse_ts(v) for v in values if isinstance(v, str) and v[:2] == "20" and "T" in v), snapshot_at)
                    who = next((v for v in values if isinstance(v, str) and v in systems), None)
                    scopes.append(Scope(file.file_id, who, None, when, "sql_snapshot_scope",
                                        header.get("database_topology"), count))
            else:
                scopes.append(Scope(file.file_id, None, table, snapshot_at, "sql_table",
                                    header.get("database_topology"), count))
            for row in conn.execute(f'SELECT rowid AS _rowid_, * FROM "{table}" ORDER BY rowid'):
                data = {k: row[k] for k in row.keys() if k != "_rowid_"}
                fields = dict(data)
                blob = fields.get("record_json")
                if isinstance(blob, str):
                    try:
                        for k, v in json.loads(blob).items():
                            fields.setdefault(k, v)
                    except json.JSONDecodeError:
                        pass
                fields.update(_table=table, _topology=header.get("database_topology"),
                              _snapshot_at=header.get("captured_at"))
                out.append(_mk(file, "sql_row", f"{table}:{row['_rowid_']}",
                               json.dumps(data, sort_keys=True, ensure_ascii=False), fields,
                               resource_re, systems))
    finally:
        conn.close()
    return out


def _walk_json(node, path: list[str], context: str | None, systems: set[str], sink: list) -> None:
    if isinstance(node, dict):
        ctx = context
        for key in ("system", "data_store", "origin_system"):
            if isinstance(node.get(key), str) and node[key] in systems:
                ctx = node[key]
        scalar = {k: v for k, v in node.items() if not isinstance(v, (dict, list))}
        has_resource = isinstance(node.get("resource_id"), str)
        if has_resource:
            sink.append(("/".join(path) or "$", node, ctx))
        for key, value in node.items():
            sub = key if key in systems else ctx
            _walk_json(value, path + [str(key)], sub, systems, sink)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_json(item, path + [str(i)], context, systems, sink)


def _index_json(file: EvidenceFile, resource_re, systems, scopes: list) -> list[EvidenceRecord]:
    data = json.loads(file.abs_path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        for snap in data.get("snapshots") or []:
            if isinstance(snap, dict) and isinstance(snap.get("records"), list):
                scopes.append(Scope(file.file_id, snap.get("data_store"), snap.get("collection"),
                                    parse_ts(snap.get("captured_at") or file.captured_at.isoformat()),
                                    "json_snapshot", None, len(snap["records"])))
        exports = data.get("service_exports")
        if isinstance(exports, dict):
            when = parse_ts(data.get("exported_at") or file.captured_at.isoformat())
            for system, body in sorted(exports.items()):
                n = sum(len(v) for v in body.values() if isinstance(v, list)) if isinstance(body, dict) else 0
                scopes.append(Scope(file.file_id, system, ",".join(sorted(body)) if isinstance(body, dict) else None,
                                    when, "service_export", None, n))
    found: list = []
    _walk_json(data, [], None, systems, found)
    out = []
    for path, node, ctx in found:
        flat = {k: v for k, v in node.items() if not isinstance(v, (dict, list))}
        for key, value in node.items():  # lift one level of nested scalars (profile.email, ...)
            if isinstance(value, dict):
                for k2, v2 in value.items():
                    if not isinstance(v2, (dict, list)):
                        flat.setdefault(k2, v2)
        flat["_json"] = node
        out.append(_mk(file, "json_record", path, json.dumps(node, sort_keys=True, ensure_ascii=False),
                       flat, resource_re, systems, context_system=ctx))
    return out


def _index_log(file: EvidenceFile, resource_re, systems) -> list[EvidenceRecord]:
    out: list[EvidenceRecord] = []
    traces: dict[str, list[tuple[int, datetime | None, dict, str]]] = defaultdict(list)
    for number, line in enumerate(file.abs_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        time, fields = parse_log_line(line)
        out.append(_mk(file, "log_line", f"line:{number}", line, fields, resource_re, systems, forced_time=time))
        trace = fields.get("trace_id")
        if isinstance(trace, str):
            traces[trace].append((number, time, fields, line))
    for trace, lines in sorted(traces.items()):
        if len(lines) < 2:
            continue
        merged: dict = {}
        for _, _, fields, _ in lines:
            for key, value in fields.items():
                merged[key] = value  # later lines carry the outcome (rows, result, status)
        merged["_events"] = [f.get("event") for _, _, f, _ in lines]
        merged["_lines"] = [n for n, _, _, _ in lines]
        merged.pop("resource_id", None)
        blob = "\n".join(line for *_, line in lines)
        rec = _mk(file, "log_trace", f"trace:{trace}", blob, merged, resource_re, systems,
                  forced_time=lines[-1][1])
        out.append(rec)
    return out


def _index_text(file: EvidenceFile, resource_re, systems, text: str, kind_line: str, ocr: bool) -> list[EvidenceRecord]:
    out = [_mk(file, "document", "document", text, {}, resource_re, systems, ocr=ocr)]
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields: dict = {}
        match = HANDOVER_RE.match(line)
        if match:
            ts, system, resource, category, state, subject = match.groups()
            fields = {"observed_at": ts, "system": system, "resource_id": resource,
                      "record_type": category, "result": state, "subject_reference": subject}
        out.append(_mk(file, kind_line, f"line:{number}", line, fields, resource_re, systems, ocr=ocr))
    return out


def _index_file(file: EvidenceFile, resource_re, systems, scopes: list) -> list[EvidenceRecord]:
    suffix = file.abs_path.suffix.lower()
    if suffix == ".sql":
        return _index_sql(file, resource_re, systems, scopes)
    if suffix == ".json":
        return _index_json(file, resource_re, systems, scopes)
    if suffix == ".log":
        return _index_log(file, resource_re, systems)
    if suffix == ".txt":
        return _index_text(file, resource_re, systems, file.abs_path.read_text(encoding="utf-8"), "text_line", False)
    if suffix == ".pdf":
        return _index_text(file, resource_re, systems, _pdf_text(file.abs_path), "document_line", False)
    if suffix == ".png":
        return _index_text(file, resource_re, systems, _ocr_text(file.abs_path), "document_line", True)
    raise EvidenceIndexError(f"{file.file_id}: unsupported evidence type {suffix}")


def build_index(dataset: Dataset, allow_empty: Iterable[str] = ()) -> EvidenceIndex:
    """Index every evidence file. Raises EvidenceIndexError rather than return a partial index."""
    systems = {a.source_system for a in dataset.activity} | {a.target_system for a in dataset.activity}
    resource_re = ResourcePatterns(prefixes_from_activity(dataset.activity))
    files = sorted(dataset.evidence_files, key=lambda f: case_sort_key(f.file_id))
    records: list[EvidenceRecord] = []
    scopes: list[Scope] = []
    counts: dict[str, int] = {}
    errors: dict[str, str] = {}
    for file in files:
        try:
            made = _index_file(file, resource_re, systems, scopes)
        except Exception as exc:  # collected and reported together below
            errors[file.file_id] = f"{type(exc).__name__}: {str(exc)[:120]}"
            continue
        counts[file.file_id] = len(made)
        records.extend(made)

    empty = [fid for fid, n in counts.items() if n == 0 and fid not in set(allow_empty)]
    missing = [f.file_id for f in files if f.file_id not in counts and f.file_id not in errors]
    if errors or empty or missing:
        parts = [f"{fid}: {why}" for fid, why in sorted(errors.items())]
        parts += [f"{fid}: parsed but produced no records" for fid in empty]
        parts += [f"{fid}: not indexed" for fid in missing]
        raise EvidenceIndexError("evidence coverage check failed:\n" + "\n".join(parts[:25]))

    stated: dict[str, set[str]] = defaultdict(set)
    for rec in records:
        if rec.resource_id and rec.system:
            stated[resource_prefix(rec.resource_id)].add(rec.system)
    conflicts = {p: s for p, s in stated.items() if len(s) > 1}
    prefix_system = {p: next(iter(s)) for p, s in stated.items() if len(s) == 1}
    scopes = _resolve_table_systems(scopes, records, prefix_system)
    known = {normalize_email(i.email) for i in dataset.identities}
    known |= {normalize_email(a.old_value) for a in dataset.audit_log if a.field_name == "email"}
    known |= {normalize_email(a.new_value) for a in dataset.audit_log if a.field_name == "email"}
    records = _repair_ocr_emails(records, known)
    index = EvidenceIndex(records, counts, prefix_system, conflicts, errors, scopes,
                          {f.file_id: f.captured_at for f in files})
    index._link()
    return index


def edit_distance(a: str, b: str, cap: int = 3) -> int:
    """Levenshtein distance, giving up above `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def _repair_ocr_emails(records: list[EvidenceRecord], known: set[str]) -> list[EvidenceRecord]:
    """OCR garbles characters ("outiook" for "outlook"). An email found in OCR text that nobody owns
    is mapped to the one real email within edit distance 2, and only if that choice is unique. An email
    that IS someone's real address is never rewritten, so a genuine near-duplicate (joana.berg versus
    jonas.berg) can never be merged."""
    from dataclasses import replace
    cache: dict[str, str | None] = {}

    def resolve(email: str) -> str | None:
        if email in known:
            return None
        if email not in cache:
            near = [k for k in known if edit_distance(email, k, 2) <= 2]
            cache[email] = near[0] if len(near) == 1 else None
        return cache[email]

    out: list[EvidenceRecord] = []
    for rec in records:
        if rec.ocr and rec.emails:
            extra = {fixed for e in rec.emails if (fixed := resolve(e))}
            if extra:
                rec = replace(rec, emails=tuple(sorted(set(rec.emails) | extra)))
        out.append(rec)
    return out


def _resolve_table_systems(scopes: list[Scope], records: list[EvidenceRecord], prefix_system: dict[str, str]) -> list[Scope]:
    """Give each SQL table the system its rows belong to (stated system, else resource prefix)."""
    votes: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for rec in records:
        if rec.kind != "sql_row":
            continue
        table = rec.fields.get("_table")
        system = rec.system or (prefix_system.get(resource_prefix(rec.resource_id)) if rec.resource_id else None)
        if system:
            votes[(rec.file_id, table)][system] += 1
    # An empty table has no rows to vote with, so fall back to what the same table name means
    # in other files (for example customer_profiles is account_service wherever it has rows).
    by_name: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for (_, table), tally in votes.items():
        for system, n in tally.items():
            by_name[table][system] += n

    def best(tally: dict[str, int] | None) -> str | None:
        return sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if tally else None

    out: list[Scope] = []
    for sc in scopes:
        if sc.kind == "sql_table" and sc.system is None:
            system = best(votes.get((sc.file_id, sc.collection))) or best(by_name.get(sc.collection))
            if system:
                sc = Scope(sc.file_id, system, sc.collection, sc.snapshot_at, sc.kind, sc.topology, sc.row_count)
        out.append(sc)
    return out
