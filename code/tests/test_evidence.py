import shutil
import sqlite3

import pytest

from ghostaudit.common import DATASET_DIR
from ghostaudit.data import load_dataset
from ghostaudit.evidence import (EvidenceIndexError, _sql_authorizer, build_index,
                                 compile_resource_re, parse_log_line, prefixes_from_activity)


@pytest.fixture(scope="module")
def index(dataset):
    return build_index(dataset)


# ------------------------------------------------------------------ coverage
def test_every_evidence_file_is_indexed(index, dataset):
    assert set(index.files) == {f.file_id for f in dataset.evidence_files}
    assert all(count > 0 for count in index.files.values())


def test_no_prefix_maps_to_two_systems_and_samples_agree(index, dataset):
    assert index.prefix_conflicts == {}
    for _, steps in dataset.sample_output.values():
        for step in steps:
            learned = index.system_of(step["resource_id"])
            assert learned in (None, step["system_id"]), step


def test_every_sql_table_has_a_system(index):
    assert [s for s in index.scopes if s.kind == "sql_table" and s.system is None] == []


def test_index_is_deterministic(dataset):
    def signature(idx):
        return [(r.file_id, r.kind, r.locator, r.mentions, r.emails) for r in idx.records]
    assert signature(build_index(dataset)) == signature(build_index(dataset))


# ------------------------------------------------------------------ the Phase 2 gate
def test_sample_cited_evidence_is_found_or_proved_absent(index, dataset):
    """Every evidence-backed sample step must be reproducible from the index.

    Present records are found by a mention inside the cited file. An absence step is proved by
    scope: the cited file covers the step's system at a time at or before audit_at and the
    record is not in it. Either way the cited file must predate the case's audit_at.
    """
    audit_at = {r.case_id: r.audit_at for r in dataset.sample_requests}
    captured = {f.file_id: f.captured_at for f in dataset.evidence_files}
    checked = 0
    for case_id, (_, steps) in dataset.sample_output.items():
        for step in steps:
            file_id = step["evidence_id"]
            if not file_id:
                continue
            checked += 1
            assert captured[file_id] <= audit_at[case_id], (case_id, step)
            mentioned = any(file_id == r.file_id and step["resource_id"] in r.mentions for r in index.records)
            if step["operation"] == "VERIFY_RECORD_ABSENT" and not mentioned:
                covering = [s for s in index.scopes_covering(file_id, step["system_id"])
                            if s.snapshot_at <= audit_at[case_id]]
                assert covering, ("absence not provable", case_id, step)
            else:
                assert mentioned, ("not found in cited file", case_id, step)
    assert checked == 75


# ------------------------------------------------------------------ identifiers
def test_identifier_lookup_is_case_insensitive(index):
    # The shift handover lists some emails in upper case.
    assert index.for_identifier("choi.jihoon94@gmail.com")
    assert index.for_identifier("CHOI.JIHOON94@GMAIL.COM") == index.for_identifier("choi.jihoon94@gmail.com")


def test_names_are_not_indexed_as_identifiers(index):
    assert not index.for_identifier("Leila Haddad")


def test_user_ids_and_hashes_are_found(index, dataset):
    assert any(r.user_ids for r in index.records)
    one = dataset.identities[0]
    assert index._by_identifier is not None and isinstance(index.for_identifier(one.email_hash), list)


# ------------------------------------------------------------------ log dialects
@pytest.mark.parametrize("line,expect", [
    ("2026-09-15T08:51:57Z level=INFO service=search_service instance=search-2 trace_id=tr-1 resource_id=search_1874 event=index_query_completed result=hit",
     {"service": "search_service", "trace_id": "tr-1", "resource_id": "search_1874", "event": "index_query_completed"}),
    ('2026-07-28T05:51:18Z [DEBUG] [account_service] [tr-6074163] profile_lookup_started: lookup_key="l.n@gmail.com" attempt="1"',
     {"service": "account_service", "trace_id": "tr-6074163", "event": "profile_lookup_started", "lookup_key": "l.n@gmail.com"}),
    ('2026-04-19T06:51:13Z {"severity":"DEBUG","service":"search_service","trace_id":"tr-77","event":"index_query_started","match_key":"a@b.co"}',
     {"service": "search_service", "trace_id": "tr-77", "match_key": "a@b.co"}),
    ('2026-08-22T10:51:17Z <15>1 node-1 account_service tr-4973247 - - level=DEBUG resource_id="account_1785" event="profile_lookup_completed" rows="1"',
     {"service": "account_service", "trace_id": "tr-4973247", "resource_id": "account_1785", "rows": "1"}),
    ('2026-07-03T07:51:32Z | DEBUG | security_service | tr-5156005 | audit_record_read_completed | resource_id="audit_record_4413" correlation_key="user_211"',
     {"service": "security_service", "trace_id": "tr-5156005", "resource_id": "audit_record_4413", "correlation_key": "user_211"}),
    ('2026-06-08T06:52:09Z requestId=tr-1108860 level=INFO function=search_service message="instance=\\"search-3\\" resource_id=\\"search_021\\" event=\\"index_query_completed\\""',
     {"trace_id": "tr-1108860", "resource_id": "search_021", "event": "index_query_completed"}),
    ('2026-03-15T07:00:00Z INFO service=downstream_delivery_service event=record_lookup seq=2 system="account_service" resource_id="account_1538" result="FOUND" subject_reference="n.m@yahoo.com"',
     {"level": "INFO", "system": "account_service", "result": "FOUND", "subject_reference": "n.m@yahoo.com"}),
])
def test_every_log_dialect_parses(line, expect):
    time, fields = parse_log_line(line)
    assert time is not None
    for key, value in expect.items():
        assert fields.get(key) == value, (key, fields)


def test_resource_regex_learns_prefixes_and_ignores_lookalikes(dataset):
    pattern = compile_resource_re(prefixes_from_activity(dataset.activity))
    found = pattern.findall("see account_146 and data_flow_2528, not customer_data_read_replica_20260921, user_39 or xaccount_9")
    assert found == ["account_146", "data_flow_2528"]


# ------------------------------------------------------------------ SQL safety
def test_sql_authorizer_allows_tables_rows_and_foreign_keys_only():
    def run(script):
        conn = sqlite3.connect(":memory:")
        conn.set_authorizer(_sql_authorizer)
        conn.executescript(script)
    run("PRAGMA foreign_keys=ON; CREATE TABLE t(a TEXT); CREATE INDEX i ON t(a); INSERT INTO t VALUES ('x');")
    for hostile in ("ATTACH DATABASE ':memory:' AS other;", "PRAGMA journal_mode=OFF;",
                    "CREATE TABLE t(a); DROP TABLE t;", "CREATE VIEW v AS SELECT 1;"):
        with pytest.raises(sqlite3.DatabaseError):
            run(hostile)


# ------------------------------------------------------------------ the guard refuses partial indexes
@pytest.fixture()
def dataset_copy(tmp_path):
    target = tmp_path / "dataset"
    shutil.copytree(DATASET_DIR, target)
    return target


def test_guard_refuses_an_unparseable_file(dataset_copy):
    victim = next(dataset_copy.glob("evidence/records/*.json"))
    victim.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(EvidenceIndexError, match="coverage check failed"):
        build_index(load_dataset(dataset_copy))


def test_guard_refuses_a_file_that_yields_nothing(dataset_copy):
    victim = next(dataset_copy.glob("evidence/logs/support_replica.log"))
    victim.write_text("", encoding="utf-8")
    with pytest.raises(EvidenceIndexError, match="produced no records"):
        build_index(load_dataset(dataset_copy))
