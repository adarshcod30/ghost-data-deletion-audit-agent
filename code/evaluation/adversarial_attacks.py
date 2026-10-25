"""Attack catalogue for the adversarial review. Each attack states the expected behaviour, runs it, and records what happened.

    .venv/bin/python code/evaluation/adversarial_review.py

Verdicts:
  blocked      the system produced the expected answer
  detected     the system did not produce the answer, but refused loudly (run stops, row verifier or indexer error)
  exploitable  the system silently produced a wrong answer, or accepted an invalid one
Severity (for exploitable ones): HIGH when the wrong answer is a false COMPLETE, MEDIUM for a wrong INCOMPLETE plan, LOW otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adversarial_world import AUDIT, EARLY, LATE, MID, World, acct, sha  # noqa: E402
from ghostaudit.data import DatasetError  # noqa: E402
from ghostaudit.evidence import EvidenceIndexError, _repair_ocr_emails, EvidenceRecord  # noqa: E402
from ghostaudit.verify import verify_row  # noqa: E402
from datetime import datetime, timezone

ALICE = "alice@example.test"
BOB = "alice@examp1e.test"


def ops(answer) -> list[tuple[str, str]]:
    return [(s["operation"], s["resource_id"]) for s in answer.steps]


def short(answer, problems=()) -> str:
    body = ", ".join(f"{o} {r}" for o, r in ops(answer)) or "no steps"
    return f"{answer.status}: {body}" + (f" | verifier: {problems[0]}" if problems else "")


def result(id_, area, attack, expected, actual, verdict, severity="", impact=""):
    return {"id": id_, "area": area, "attack": attack, "expected": expected, "actual": actual,
            "verdict": verdict, "severity": severity if verdict == "exploitable" else "", "impact": impact if verdict == "exploitable" else ""}


def judge(id_, area, attack, expected, world, ok, email=ALICE, severity="HIGH", impact=""):
    """Run the pipeline on `world`; blocked when ok(answer) holds, detected when the row verifier or the loader refused."""
    try:
        answer, problems = world.answer(email)
    except (EvidenceIndexError, DatasetError) as exc:
        world.close()
        return result(id_, area, attack, expected, f"run refused: {str(exc)[:110]}", "detected")
    finally:
        pass
    world.close()
    text = short(answer, problems)
    if ok(answer):
        return result(id_, area, attack, expected, text, "blocked")
    if problems:
        return result(id_, area, attack, expected, text, "detected")
    ledger = answer.ledger
    if ledger is not None:
        from ghostaudit.planner import _entry_ops
        flags = [f"{rid} left out ({why})" for rid, why in ledger.dropped] + [f"{e.resource_id} has no allowed operation" for e in ledger.entries if _entry_ops(e) is None]
        if flags:   # the run prints and records these; the status is not changed, so this is detection, not prevention
            return result(id_, area, attack, expected, text + " | FLAGGED in run output: " + "; ".join(flags), "detected")
    return result(id_, area, attack, expected, text, "exploitable", severity, impact)


def has(answer, op, rid=None):
    return any(o == op and (rid is None or r == rid) for o, r in ops(answer))


def incomplete_with(op, rid=None):
    return lambda a: a.status == "INCOMPLETE" and has(a, op, rid)


# ------------------------------------------------------------------------------------------------ identity
def i1():
    w = World()
    w.change_email("user_1", "alice.old@example.test", ALICE)
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", email="alice.old@example.test", when=MID)])])
    return judge("I1", "Identity", "Request uses the ORIGINAL email; the live record still carries the original email, the profile now has a new one",
                 "INCOMPLETE, REPORT_REMAINING_RECORD account_100", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"),
                 email="alice.old@example.test", impact="A person who changed email is reported deleted while the old-email record remains.")


def i2():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_200", "user_2", BOB, MID)])])
    w.log_file(MID, World.lookup("account_201", ALICE, MID, False))
    return judge("I2", "Identity", "Near-identical email and identical name: user_2 (alice@examp1e.test) has a live account; user_1 is already gone",
                 "COMPLETE for user_1 with no step about account_200", w,
                 lambda a: a.status == "COMPLETE" and not has(a, "REPORT_REMAINING_RECORD") and all(r != "account_200" for _, r in ops(a)),
                 severity="MEDIUM", impact="Another person's record is reported as this person's leftover data.")


def i2b():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_200", "user_2", BOB, MID)])])
    return judge("I2b", "Identity", "Request for the look-alike address (user_2) must see only user_2's record",
                 "INCOMPLETE, account_200 only", w, lambda a: a.status == "INCOMPLETE" and all(r == "account_200" for _, r in ops(a)), email=BOB, severity="MEDIUM")


def i3():
    w = World()
    w.change_phone("user_1", "+1 202 555 0999", "+1 202 555 0101")
    rec = {"resource_id": "account_100", "full_name": "A. Example", "phone": "+1 202 555 0999", "account_status": "ACTIVE", "updated_at": MID}
    w.json_file(MID, [("account_service", "customer_profiles", [rec])])
    return judge("I3", "Identity", "Old record carries only the HISTORICAL phone number",
                 "INCOMPLETE, REPORT_REMAINING_RECORD account_100", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"),
                 impact="Residue under an old phone number is missed and the case is closed COMPLETE.")


def i3b():
    w = World()
    w.change_email("user_1", "alice.old@example.test", ALICE)
    rec = {"resource_id": "analytics_100", "user_id": "user_9", "email_hash": sha("alice.old@example.test"), "updated_at": MID}
    w.json_file(MID, [("analytics_platform", "customer_analytics_reports", [rec])])
    return judge("I3b", "Identity", "Analytics record carries only the HISTORICAL email hash",
                 "INCOMPLETE, REPORT_EXPOSED_PII analytics_100", w, incomplete_with("REPORT_EXPOSED_PII", "analytics_100"),
                 impact="Attributable analytics data under an old email hash is missed.")


def i4():
    """Two cases, one account-deletion row each in the same window: a row must never be given to the wrong case."""
    from ghostaudit.workflow import _forced_assignments
    got = _forced_assignments({"case_a": {"row_1", "row_2"}, "case_b": {"row_1", "row_2"}})
    ok = got == {}
    return result("I4", "Identity", "Two cases share a window and a superficial attribute (result, time); two candidate activity rows",
                  "no link made (ambiguous)", f"links: {got or 'none'}", "blocked" if ok else "exploitable", "HIGH",
                  "A deletion row of a stranger is attributed to this case.")


def i5():
    w = World()
    rec_a = {"resource_id": "tombstone_100", "customer_reference": "user_1", "email": ALICE, "updated_at": MID}
    rec_b = acct("account_300", "user_2", BOB, MID)
    w.json_file(MID, [("identity_service", "account_tombstones", [rec_a]), ("account_service", "customer_profiles", [rec_b])])
    return judge("I5", "Identity", "Tombstone for user_1 plus a live account for user_2 under a different stable id",
                 "INCOMPLETE: tombstone_100 exposed, nothing about account_300", w,
                 lambda a: a.status == "INCOMPLETE" and has(a, "REPORT_EXPOSED_PII", "tombstone_100") and not any(r == "account_300" for _, r in ops(a)))


# ------------------------------------------------------------------------------------------------ evidence
def e1():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)])])
    w.raw_file(MID, "json", '{"unrelated": "marketing brochure", "note": "no resource records here"}')
    return judge("E1", "Evidence", "Manifest lists a misleading file that parses but holds no records",
                 "run refuses (coverage check) or ignores it without changing the answer", w,
                 lambda a: a.status == "INCOMPLETE" and has(a, "REPORT_REMAINING_RECORD", "account_100"))


def e1b():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)])])
    w.raw_file(MID, "json", '{"snapshots": [ {"records": [ ')   # truncated: cannot be parsed
    return judge("E1b", "Evidence", "Manifest lists a file that cannot be parsed", "run refuses; no output is written from a partial index", w,
                 lambda a: False)


def e2():
    now = datetime(2026, 6, 13, tzinfo=timezone.utc)
    def rec(email):
        return EvidenceRecord("evidence_1", now, "ocr_line", "l1", None, None, None, "", (email,), (), (), (), (), True) if False else None
    # Use the public function with a minimal stand-in record carrying the fields it reads.
    from types import SimpleNamespace
    from dataclasses import dataclass, replace
    import dataclasses
    fields = {f.name for f in dataclasses.fields(EvidenceRecord)}
    base = {name: None for name in fields}
    base.update({"ocr": True, "emails": ("alice@exampie.test",)})
    try:
        record = EvidenceRecord(**{k: v for k, v in base.items()})
    except TypeError as exc:
        return result("E2", "Evidence", "OCR email equidistant from two real, near-identical addresses", "not repaired to either", f"fixture error {exc}", "blocked")
    known = {ALICE, BOB}   # "alice@exampie.test" is one edit from BOTH real addresses
    out = _repair_ocr_emails([record], known)[0].emails
    ok = out == ("alice@exampie.test",)
    return result("E2", "Evidence", "OCR email is within edit distance 2 of TWO real, near-identical addresses",
                  "left unrepaired (ambiguous), so it links to neither person", f"emails after repair: {out}", "blocked" if ok else "exploitable", "HIGH",
                  "An ambiguous OCR identifier is silently attached to one of two people.")


def e2b():
    from types import SimpleNamespace
    import dataclasses
    base = {f.name: None for f in dataclasses.fields(EvidenceRecord)}
    base.update({"ocr": True, "emails": ("alice@exampie.test",)})
    record = EvidenceRecord(**base)
    out = _repair_ocr_emails([record], {ALICE})[0].emails   # unique near match
    ok = ALICE in out
    return result("E2b", "Evidence", "OCR email within distance 2 of exactly one real address", "repaired to that address (uniqueness rule)",
                  f"emails after repair: {out}", "blocked" if ok else "exploitable", "LOW")


def e3():
    w = World()
    rec = acct("account_100", when=MID, result="NOT_FOUND", note="deleted by worker")
    w.json_file(MID, [("account_service", "customer_profiles", [rec])])
    return judge("E3", "Evidence", "JSON record is ACTIVE with email and phone present but carries a stray result=NOT_FOUND claim",
                 "INCOMPLETE (the resource fields show the account exists)", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"),
                 impact="A contradictory claim inside a live record turns it into ABSENT and the case is closed COMPLETE.")


def e3b():
    w = World()
    rec = acct("account_100", when=MID, rows=0)
    w.json_file(MID, [("account_service", "customer_profiles", [rec])])
    return judge("E3b", "Evidence", "JSON record with live fields plus a stray rows=0", "INCOMPLETE", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"))


def e4():
    w = World()
    w.log_file(EARLY, World.lookup("account_100", ALICE, EARLY, True))
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)])])
    # activity (decoy rows) claims SUCCESS deletes; the snapshot is the evidence
    return judge("E4", "Evidence", "Activity log says the deletion succeeded; a later snapshot still holds the record",
                 "INCOMPLETE (snapshot beats the claim)", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"))


def e5():
    w = World()
    w.log_file(MID, World.lookup("account_100", ALICE, MID, False))
    w.json_file(LATE, [("account_service", "customer_profiles", [acct("account_100", when=LATE)])])
    return judge("E5", "Evidence", "A file captured AFTER audit_at shows the account present again", "COMPLETE, citing only the earlier file", w,
                 lambda a: a.status == "COMPLETE" and all(s["evidence_id"] in ("evidence_01",) for s in a.steps))


def e5b():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)])])
    w.log_file(LATE, World.lookup("account_100", ALICE, LATE, False))
    return judge("E5b", "Evidence", "A file captured AFTER audit_at shows the account deleted", "INCOMPLETE (later deletion cannot rescue the case)", w,
                 incomplete_with("REPORT_REMAINING_RECORD", "account_100"))


def e6():
    w = World()
    w.log_file(MID, World.lookup("account_100", ALICE, MID, False))
    w.log_file("2026-06-13T11:00:00Z", World.lookup("account_100", ALICE, "2026-06-13T10:30:00Z", True, trace="t2"))
    return judge("E6", "Evidence", "Stale-looking ABSENT lookup at 10:00 is superseded by a PRESENT lookup at 10:30 (before audit_at)", "INCOMPLETE", w,
                 incomplete_with("REPORT_REMAINING_RECORD", "account_100"), impact="Superseded evidence closes the case.")


def e6b():
    w = World()
    t = "2026-06-13T10:00:00Z"
    w.log_file(MID, World.lookup("account_100", ALICE, t, False, trace="a"))       # evidence_01, ABSENT
    w.log_file(MID, World.lookup("account_100", ALICE, t, True, trace="b"))        # evidence_02, PRESENT, same instant
    return judge("E6b", "Evidence", "Two observations at the SAME instant disagree (ABSENT in evidence_01, PRESENT in evidence_02)",
                 "INCOMPLETE (the unsafe reading wins a tie)", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"),
                 impact="On a timestamp tie the higher file number wins regardless of state, so the order of two exports decides COMPLETE.")


def e6c():
    w = World()
    t = "2026-06-13T10:00:00Z"
    w.log_file(MID, World.lookup("account_100", ALICE, t, True, trace="b"))        # evidence_01, PRESENT
    w.log_file(MID, World.lookup("account_100", ALICE, t, False, trace="a"))       # evidence_02, ABSENT
    return judge("E6c", "Evidence", "Same tie, file order reversed (PRESENT in evidence_01, ABSENT in evidence_02)",
                 "INCOMPLETE (the unsafe reading wins a tie)", w, incomplete_with("REPORT_REMAINING_RECORD", "account_100"),
                 impact="Same as E6b: the answer flips with file numbering.")


def e7():
    w = World()
    w.log_file(MID, ["2026-06-13T10:00:00Z level=INFO service=search_service resource_id=search_100 matched_value=" + ALICE + " event=weird_unknown_event"])
    return judge("E7", "Evidence", "A log line links the subject's email to search_100 but its event has no known outcome",
                 "not COMPLETE: the resource is linked and its state is unknown", w, lambda a: a.status != "COMPLETE" or any(r == "search_100" for _, r in ops(a)),
                 impact="A resource that evidence ties to the person is silently dropped when its state cannot be read; the case is closed COMPLETE.")


# ------------------------------------------------------------------------------------------------ policy
def p1():
    w = World()
    rec = {"resource_id": "support_100", "customer_reference": "user_1", "requester_name": "Alice Example", "requester_email": ALICE,
           "message_excerpt": "Order 55 question, agent reply attached", "updated_at": MID}
    w.json_file(MID, [("support_platform", "support_records", [rec])])
    return judge("P1", "Policy", "Support conversation with shared context and the requester's identifiers still visible",
                 "INCOMPLETE: REPORT_EXPOSED_PII, REDACT_RECORD (never DELETE_RECORD)", w,
                 lambda a: has(a, "REDACT_RECORD", "support_100") and not has(a, "DELETE_RECORD", "support_100"))


def p2():
    w = World()
    rec = {"resource_id": "support_101", "customer_reference": "user_1", "customer_email": ALICE, "file_name": "id_scan.pdf",
           "storage_class": "ticket_attachment", "updated_at": MID}
    w.json_file(MID, [("support_platform", "ticket_attachments", [rec])])
    return judge("P2", "Policy", "Standalone customer attachment", "INCOMPLETE: DELETE_RECORD support_101", w,
                 lambda a: has(a, "DELETE_RECORD", "support_101") and not has(a, "REDACT_RECORD", "support_101"))


def p3():
    w = World()
    rec = {"resource_id": "analytics_100", "user_id": "user_1", "email": None, "phone": None, "email_hash": None, "updated_at": MID}
    w.json_file(MID, [("analytics_platform", "customer_analytics_reports", [rec])])
    return judge("P3", "Policy", "Analytics record whose stable user_id still points at the subject", "INCOMPLETE: ANONYMIZE_RECORD analytics_100", w,
                 lambda a: has(a, "ANONYMIZE_RECORD", "analytics_100"),
                 impact="A record that still carries the subject's user id is treated as anonymized.")


def p3b():
    w = World()
    rec = {"resource_id": "analytics_100", "user_id": None, "email": None, "phone": None, "email_hash": None, "updated_at": MID,
           "note": "ex " + ALICE}
    w.json_file(MID, [("analytics_platform", "customer_analytics_reports", [rec])])
    return judge("P3b", "Policy", "Analytics record, identifier fields null but a free-text note holds the email", "linked and reported (the email is visible)", w,
                 lambda a: a.status == "INCOMPLETE" and has(a, "ANONYMIZE_RECORD", "analytics_100"),
                 impact="An identifier hidden in a free-text field escapes the anonymization check.")


def p4():
    w = World()
    rec = {"resource_id": "audit_record_100", "subject_reference": "user_1", "event_code": "LOGIN", "retention_until": "2027-01-01T00:00:00Z", "updated_at": MID}
    w.json_file(MID, [("security_service", "security_audit_records", [rec])])
    return judge("P4", "Policy", "Security audit record inside its retention period", "COMPLETE: VERIFY_RECORD_PRESENT only, never DELETE", w,
                 lambda a: a.status == "COMPLETE" and ops(a) == [("VERIFY_RECORD_PRESENT", "audit_record_100")])


def p4b():
    w = World()
    rec = {"resource_id": "audit_record_100", "subject_reference": "user_1", "event_code": "LOGIN", "retention_until": "2027-01-01T00:00:00Z", "updated_at": EARLY}
    w.json_file(EARLY, [("security_service", "security_audit_records", [rec])])
    w.log_file(MID, ["2026-06-13T10:00:00Z level=INFO service=security_service resource_id=audit_record_100 subject_reference=user_1 event=audit_lookup_completed rows=0"])
    return judge("P4b", "Policy", "A record that MUST be retained was deleted before audit_at (lookup now returns nothing)",
                 "not COMPLETE: a required retained record is gone", w, lambda a: a.status != "COMPLETE",
                 impact="Destroyed audit evidence is invisible: the retained record's absence produces no step and the case is closed COMPLETE.")


def p5():
    w = World()
    rec = {"resource_id": "legal_hold_100", "subject_reference": "user_1", "hold_status": "ACTIVE", "updated_at": MID}
    w.json_file(MID, [("legal_service", "legal_holds", [rec])])
    return judge("P5", "Policy", "Active legal hold", "COMPLETE: VERIFY_RECORD_PRESENT legal_hold_100, no delete", w,
                 lambda a: a.status == "COMPLETE" and ops(a) == [("VERIFY_RECORD_PRESENT", "legal_hold_100")])


def p6():
    w = World()
    rec = {"resource_id": "backup_100", "customer_reference": "user_1", "customer_email": ALICE, "archive_key": "k", "restore_allowed": 1, "updated_at": MID}
    w.json_file(MID, [("backup_service", "backup_restore_entries", [rec])])
    return judge("P6", "Policy", "Permitted backup that can still be restored", "INCOMPLETE: REPORT_RESTORE_RISK, BLOCK_RESTORE, VERIFY_RESTORE_BLOCKED, no DELETE", w,
                 lambda a: has(a, "BLOCK_RESTORE", "backup_100") and not has(a, "DELETE_RECORD", "backup_100"))


def p6b():
    w = World()
    rec = {"resource_id": "backup_100", "customer_reference": "user_1", "customer_email": ALICE, "archive_key": "k", "updated_at": MID}
    w.json_file(MID, [("backup_service", "backup_restore_entries", [rec])])
    return judge("P6b", "Policy", "Backup entry for the subject whose restore flag is missing", "not COMPLETE without a restore verdict", w,
                 lambda a: a.status != "COMPLETE" or any(r == "backup_100" for _, r in ops(a)),
                 impact="A backup that may be restorable is dropped because its restore state is unreadable; COMPLETE.")


def p7():
    w = World()
    rec = {"resource_id": "tombstone_100", "customer_reference": "user_1", "email": ALICE, "phone": "+1 202 555 0101", "updated_at": MID}
    w.json_file(MID, [("identity_service", "account_tombstones", [rec])])
    return judge("P7", "Policy", "Tombstone keeps user_1 but still exposes email and phone", "INCOMPLETE: REDACT_RECORD tombstone_100 (never DELETE)", w,
                 lambda a: has(a, "REDACT_RECORD", "tombstone_100") and not has(a, "DELETE_RECORD", "tombstone_100"))


def p7b():
    w = World()
    rec = {"resource_id": "tombstone_100", "customer_reference": "user_1", "email": None, "phone": None, "email_hash": None, "name": None, "updated_at": MID}
    w.json_file(MID, [("identity_service", "account_tombstones", [rec])])
    return judge("P7b", "Policy", "Compliant tombstone", "COMPLETE: VERIFY_RECORD_REDACTED tombstone_100", w,
                 lambda a: a.status == "COMPLETE" and ops(a) == [("VERIFY_RECORD_REDACTED", "tombstone_100")])


def p7c():
    w = World()
    rec = {"resource_id": "tombstone_100", "customer_reference": "user_1", "email": None, "phone": None, "email_hash": None, "name": None, "updated_at": EARLY}
    w.json_file(EARLY, [("identity_service", "account_tombstones", [rec])])
    w.log_file(MID, ["2026-06-13T10:00:00Z level=INFO service=identity_service resource_id=tombstone_100 customer_reference=user_1 event=tombstone_lookup_completed rows=0"])
    return judge("P7c", "Policy", "The tombstone that must be preserved has itself been deleted", "not COMPLETE: the stable reference is gone", w,
                 lambda a: a.status != "COMPLETE", impact="Deleting the tombstone breaks references from retained records, and the case is closed COMPLETE.")


# ------------------------------------------------------------------------------------------------ state flow
def s1():
    w = World()
    w.log_file(MID, World.lookup("account_100", ALICE, MID, False))
    w.json_file("2026-06-14T09:00:00Z", [("account_service", "customer_profiles", [acct("account_100", when="2026-06-14T08:00:00Z")])])
    w.json_file(MID, [("integration_service", "data_flows", [{"resource_id": "data_flow_100", "customer_reference": "user_1", "customer_email": ALICE, "enabled": 1, "updated_at": MID}])])
    return judge("S1", "State flow", "Account deleted at 10:00, a still-active sync recreates it at 08:00 next day (before audit_at)",
                 "INCOMPLETE: account_100 reported, data_flow_100 reported", w,
                 lambda a: has(a, "REPORT_REMAINING_RECORD", "account_100") and has(a, "REPORT_ACTIVE_DATA_FLOW", "data_flow_100"))


def s2():
    w = World()
    w.json_file(MID, [("integration_service", "data_flows", [{"resource_id": "data_flow_100", "customer_reference": "user_1", "customer_email": ALICE, "enabled": 0, "updated_at": MID}])])
    return judge("S2", "State flow", "Flow is disabled", "COMPLETE with VERIFY_DATA_FLOW_DISABLED citing the evidence", w,
                 lambda a: a.status == "COMPLETE" and ops(a) == [("VERIFY_DATA_FLOW_DISABLED", "data_flow_100")] and a.steps[0]["evidence_id"] == "evidence_01")


def s3():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)]),
                      ("integration_service", "data_flows", [{"resource_id": "data_flow_100", "customer_reference": "user_1", "customer_email": ALICE, "enabled": 1, "updated_at": MID}])])
    def ok(a):
        order = [o for o, _ in ops(a)]
        return "DISABLE_DATA_FLOW" in order and order.index("DISABLE_DATA_FLOW") < order.index("DELETE_RECORD")
    return judge("S3", "State flow", "Account present and its recreating flow active", "DISABLE_DATA_FLOW is planned before DELETE_RECORD", w, ok)


def s4():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)]),
                      ("search_service", "customer_search_documents", [{"resource_id": "search_100", "customer_reference": "user_1", "email": ALICE, "updated_at": MID}]),
                      ("export_service", "customer_exports", [{"resource_id": "export_100", "customer_reference": "user_1", "owner_email": ALICE, "updated_at": MID}]),
                      ("analytics_platform", "customer_analytics_reports", [{"resource_id": "analytics_100", "user_id": "user_1", "email": ALICE, "updated_at": MID}])])
    need = {"account_100", "search_100", "export_100", "analytics_100"}
    return judge("S4", "State flow", "Four independent copies in four systems", "a finding, a remediation and a verification for EACH copy", w,
                 lambda a: all(sum(1 for _, r in ops(a) if r == rid) == 3 for rid in need))


def s5():
    """Verifier-level: a COMPLETE-looking row that verifies the primary copy and says nothing about the secondary one."""
    return None


# ------------------------------------------------------------------------------------------------ output (verifier level)
T = {"evidence_01": datetime(2026, 6, 1, tzinfo=timezone.utc), "evidence_02": datetime(2026, 6, 2, tzinfo=timezone.utc),
     "evidence_99": datetime(2026, 7, 1, tzinfo=timezone.utc)}
AUD = datetime(2026, 6, 14, tzinfo=timezone.utc)


def st(n, phase, op, state, rid="account_100", ev="evidence_01", system="account_service"):
    return {"step_no": n, "phase": phase, "system_id": system, "resource_id": rid, "operation": op, "state": state, "evidence_id": ev}


def verifier_case(id_, area, attack, expected, status, steps, must_flag=True, severity="HIGH", impact="", names=None, systems=None):
    problems = verify_row("case_1", status, steps, AUD, T, evidence_names=names, evidence_systems=systems)
    flagged = bool(problems)
    ok = flagged == must_flag
    return result(id_, area, attack, expected, "verifier: " + (problems[0] if problems else "accepted the row"),
                  "detected" if ok else "exploitable", severity, impact)


def o1():
    steps = [st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ev="evidence_02")]   # evidence_02 exists and predates audit but does not mention account_100
    return verifier_case("O1", "Output", "Wrong evidence id: a real, in-time file that never mentions the resource", "row rejected", "COMPLETE", steps, severity="HIGH",
                         names={"evidence_01": {"account_100"}, "evidence_02": {"account_999"}}, systems={"evidence_02": {"search_service"}},
                         impact="Verification steps can cite unrelated evidence and still pass; a wrong citation costs the step and, for COMPLETE rows, the proof.")


def o2():
    bad = st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "PRESENT")
    return verifier_case("O2", "Output", "Incompatible state for an operation", "row rejected", "COMPLETE", [bad])


def o2b():
    bad = st(1, "VERIFICATION", "ERASE_EVERYTHING", "ABSENT")
    return verifier_case("O2b", "Output", "Unsupported operation", "row rejected", "COMPLETE", [bad])


def o3():
    steps = [st(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT")]
    return verifier_case("O3", "Output", "INCOMPLETE row with a finding but no remediation and no verification", "row rejected", "INCOMPLETE", steps, severity="MEDIUM",
                         impact="A plan that names a problem and never fixes or checks it is emitted.")


def o3b():
    steps = [st(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT"), st(2, "REMEDIATION", "DELETE_RECORD", "ABSENT", ev="")]
    return verifier_case("O3b", "Output", "Finding and remediation present, final verification missing", "row rejected", "INCOMPLETE", steps, severity="MEDIUM",
                         impact="No post-remediation check is required for the record.")


def o4():
    s = st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT")
    dup = dict(s, step_no=2)
    return verifier_case("O4", "Output", "Duplicate step", "row rejected", "COMPLETE", [s, dup], severity="LOW")


def o5():
    steps = [st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"), st(2, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT")]
    return verifier_case("O5", "Output", "Verification before finding", "row rejected", "INCOMPLETE", steps)


def o5b():
    steps = [st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"), st(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", rid="account_101")]
    return verifier_case("O5b", "Output", "Numbering gap", "row rejected", "COMPLETE", steps)


def o6():
    steps = [st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ev="evidence_99")]
    return verifier_case("O6", "Output", "COMPLETE citing evidence captured after audit_at", "row rejected", "COMPLETE", steps)


def o7():
    """A falsely COMPLETE row that is valid in every structural way: it verifies only the primary copy."""
    steps = [st(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ev="evidence_01")]
    return verifier_case("O7", "Output", "COMPLETE row verifies the primary record only; a secondary copy exists elsewhere in the ledger",
                         "cannot be rejected by structure alone: the planner is the control (see S4)", "COMPLETE", steps, must_flag=False,
                         impact="")


def o8():
    steps = [st(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT"), st(2, "REMEDIATION", "DELETE_RECORD", "ABSENT", ev=""),
             st(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ev="")]
    steps.insert(0, st(0, "FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", rid="data_flow_100", system="integration_service"))
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    return verifier_case("O8", "State flow", "Remediation deletes the record but never disables the active flow that was reported", "row rejected", "INCOMPLETE", steps, severity="HIGH",
                         impact="A plan that deletes without stopping the recreating flow is emitted; the data comes back.")


def e8():
    """Pipeline-level: a user whose identity cannot be resolved must not become COMPLETE."""
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_100", when=MID)])])
    return judge("E8", "Identity", "Request email held by no user", "not COMPLETE", w, lambda a: a.status != "COMPLETE", email="nobody@example.test")


def e9():
    w = World()
    w.json_file(MID, [("account_service", "customer_profiles", [acct("account_999", user="user_77", email="stranger@example.test", when=MID)])])
    return judge("E9", "Evidence", "Subject has no evidence at all (nothing links to them)", "COMPLETE but flagged as unidentified (documented limit)", w,
                 lambda a: a.status == "COMPLETE" and a.note.startswith("no resource"))


ATTACKS = [i1, i2, i2b, i3, i3b, i4, i5, e1, e1b, e2, e2b, e3, e3b, e4, e5, e5b, e6, e6b, e6c, e7, e8, e9,
           p1, p2, p3, p3b, p4, p4b, p5, p6, p6b, p7, p7b, p7c, s1, s2, s3, s4,
           o1, o2, o2b, o3, o3b, o4, o5, o5b, o6, o7, o8]


def run_all() -> list[dict]:
    return [attack() for attack in ATTACKS]
