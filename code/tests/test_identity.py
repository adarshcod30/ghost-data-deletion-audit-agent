import ast
import random
import re
from collections import Counter
from pathlib import Path

import pytest

from ghostaudit.common import email_hash, parse_ts
from ghostaudit.identity import IdentityResolver, STRONG
from ghostaudit.models import AuditEvent, Identity


# ----------------------------------------------------------------- real dataset
@pytest.fixture(scope="module")
def resolver(dataset):
    return IdentityResolver(dataset.identities, dataset.audit_log)


def test_phase1_gate_all_requests_resolve(dataset, resolver):
    subjects = [resolver.resolve(r) for r in dataset.requests]
    assert all(s.resolved for s in subjects)
    kinds = Counter(s.match_kind for s in subjects)
    assert kinds == {"current": 418, "historical": 100}
    assert not any(s.anomalies for s in subjects)


def test_samples_all_resolve(dataset, resolver):
    assert all(resolver.resolve(r).resolved for r in dataset.sample_requests)


def test_hash_scheme_holds_for_every_user(resolver):
    assert resolver.hash_anomalies() == []


def test_uppercase_request_email_resolves_like_lowercase(dataset, resolver):
    upper = [r for r in dataset.requests if r.email != r.email.lower()]
    assert len(upper) == 20
    for request in upper:
        lower = resolver.resolve_email(request.case_id, request.email.lower(), request.audit_at)
        got = resolver.resolve(request)
        assert got.resolved and got.user_id == lower.user_id


def test_independent_check_against_catalog_link_rows(dataset, resolver):
    """LINK_RESOURCE_IDENTITY rows name an email and a user_id without using our resolver."""
    pattern = re.compile(r"to (\S+@\S+) and (user_\d+)")
    pairs = []
    for row in dataset.activity:
        if row.event_type == "LINK_RESOURCE_IDENTITY":
            match = pattern.search(row.details)
            if match:
                pairs.append((match.group(1), match.group(2)))
    assert len(pairs) >= 10
    far_future = parse_ts("2100-01-01T00:00:00Z")
    for email, user_id in pairs:
        subject = resolver.resolve_email("check", email, far_future)
        assert subject.resolved and subject.user_id == user_id, (email, user_id, subject.reason)


def test_every_alias_is_traceable_to_a_source_row(dataset, resolver):
    audit_ids = {e.audit_id for e in dataset.audit_log}
    user_ids = {i.user_id for i in dataset.identities}
    for request in dataset.requests:
        for alias in resolver.resolve(request).aliases:
            assert alias.source_id in (audit_ids | user_ids), alias
            if alias.source_kind == "audit_log":
                assert alias.source_id in audit_ids


def test_name_alias_is_weak_and_never_a_strong_value(dataset, resolver):
    subject = resolver.resolve(dataset.requests[0])
    names = subject.values("name")
    assert names and names.isdisjoint(subject.strong_values())
    assert all(a.strength == STRONG for a in subject.aliases if a.kind != "name")


def test_historical_requests_expose_old_and_current_email(dataset, resolver):
    historical = [resolver.resolve(r) for r in dataset.requests]
    historical = [s for s in historical if s.match_kind == "historical"]
    assert len(historical) == 100
    for subject in historical:
        assert subject.values("email", status="current")
        assert subject.values("email", status="historical")


def test_no_hardcoded_ids_in_prediction_code():
    """Phase 1 rule: no logic keyed on a case, user or account id (docstrings excluded)."""
    package = Path(__file__).resolve().parents[1] / "ghostaudit"
    pattern = re.compile(r"(case|user|account|search|support|analytics)_\d+")
    offenders = []
    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                      if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef))
                      and node.body and isinstance(node.body[0], ast.Expr)
                      and isinstance(node.body[0].value, ast.Constant)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docstrings and pattern.search(node.value)):
                offenders.append((path.name, node.value))
    assert offenders == []


# ------------------------------------------------------------------- synthetic
T0 = parse_ts("2026-01-01T00:00:00Z")
T1 = parse_ts("2026-03-01T00:00:00Z")
T2 = parse_ts("2026-06-01T00:00:00Z")
T3 = parse_ts("2026-09-01T00:00:00Z")


def ident(user, name, email, phone="+1 202 555 0100", updated=T3):
    return Identity(user, name, email, phone, email_hash(email), updated)


def change(audit_id, user, when, field, old, new):
    return AuditEvent(audit_id, user, when, field, old, new)


def email_change(audit_id, user, when, old, new):
    return [
        change(audit_id, user, when, "email", old, new),
        change(audit_id + "h", user, when, "email_hash", email_hash(old), email_hash(new)),
    ]


@pytest.fixture()
def synthetic():
    identities = [ident("u1", "Ada Lovelace", "ada.new@example.com"),
                  ident("u2", "Bob Stone", "bob@example.com")]
    audit = email_change("a1", "u1", T1, "ada.old@example.com", "ada.mid@example.com")
    audit += email_change("a2", "u1", T2, "ada.mid@example.com", "ada.new@example.com")
    return identities, audit


def test_as_of_excludes_changes_after_audit_at(synthetic):
    identities, audit = synthetic
    r = IdentityResolver(identities, audit)
    early = r.resolve_email("c", "ada.old@example.com", T1 - (T1 - T0) / 2)
    assert early.resolved and early.match_kind == "current"
    assert early.values("email") == {"ada.old@example.com"}
    assert email_hash("ada.new@example.com") not in early.values("email_hash")
    # The newest email did not exist yet, so it cannot identify anyone at that time.
    miss = r.resolve_email("c", "ada.new@example.com", T0)
    assert not miss.resolved and "after audit_at" in miss.reason


def test_multi_hop_chain_has_every_alias_at_the_end(synthetic):
    identities, audit = synthetic
    r = IdentityResolver(identities, audit)
    subject = r.resolve_email("c", "ADA.OLD@example.com ", T3)
    assert subject.user_id == "u1" and subject.match_kind == "historical"
    assert subject.values("email", status="historical") == {"ada.old@example.com", "ada.mid@example.com"}
    assert subject.values("email", status="current") == {"ada.new@example.com"}
    assert len(subject.values("email_hash")) == 3


def test_change_exactly_at_audit_time_is_applied(synthetic):
    identities, audit = synthetic
    r = IdentityResolver(identities, audit)
    subject = r.resolve_email("c", "ada.mid@example.com", T1)
    assert subject.match_kind == "current"


def test_audit_file_order_does_not_change_the_answer(synthetic):
    identities, audit = synthetic
    baseline = IdentityResolver(identities, audit).resolve_email("c", "ada.old@example.com", T3)
    for seed in range(5):
        shuffled = audit[:]
        random.Random(seed).shuffle(shuffled)
        got = IdentityResolver(identities, shuffled).resolve_email("c", "ada.old@example.com", T3)
        assert got.aliases == baseline.aliases and got.anomalies == baseline.anomalies


def test_unknown_email_is_unresolved(synthetic):
    identities, audit = synthetic
    subject = IdentityResolver(identities, audit).resolve_email("c", "nobody@example.com", T3)
    assert subject.resolution == "unresolved" and subject.user_id is None


def test_shared_email_is_ambiguous_unless_exactly_one_current_holder():
    identities = [ident("u1", "A", "shared@example.com"), ident("u2", "B", "shared@example.com")]
    both = IdentityResolver(identities, []).resolve_email("c", "shared@example.com", T3)
    assert both.resolution == "ambiguous" and set(both.candidates) == {"u1", "u2"}

    identities = [ident("u1", "A", "new1@example.com"), ident("u2", "B", "shared@example.com")]
    audit = email_change("a1", "u1", T1, "shared@example.com", "new1@example.com")
    one = IdentityResolver(identities, audit).resolve_email("c", "shared@example.com", T3)
    assert one.resolved and one.user_id == "u2" and one.match_kind == "current"
    assert any("past alias of u1" in note for note in one.anomalies)


def test_chain_gap_and_snapshot_mismatch_are_reported():
    identities = [ident("u1", "A", "c@example.com")]
    audit = email_change("a1", "u1", T1, "a@example.com", "b@example.com")
    audit += email_change("a2", "u1", T2, "x@example.com", "c@example.com")  # gap: b != x
    r = IdentityResolver(identities, audit)
    notes = " ".join(r.timeline_anomalies["u1"])
    assert "chain gap before a2" in notes

    identities = [ident("u1", "A", "different@example.com")]
    r = IdentityResolver(identities, email_change("a1", "u1", T1, "a@example.com", "b@example.com"))
    assert any("differs from snapshot" in n for n in r.timeline_anomalies["u1"])


def test_phone_history_is_aliased_with_normalised_values():
    identities = [ident("u1", "A", "a@example.com", phone="+44 7700 900380")]
    audit = [change("p1", "u1", T1, "phone", "+44 7700 900880", "+44 7700 900380")]
    subject = IdentityResolver(identities, audit).resolve_email("c", "a@example.com", T3)
    assert subject.values("phone", status="historical") == {"+447700900880"}
    assert subject.values("phone", status="current") == {"+447700900380"}
