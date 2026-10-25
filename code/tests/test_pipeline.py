from pathlib import Path

import pytest

from ghostaudit.common import case_sort_key
from ghostaudit.pipeline import Pipeline
from ghostaudit.scoring import score_case, summarize
from ghostaudit.verify import serialize_steps, verify_row


@pytest.fixture(scope="module")
def pipeline(dataset):
    return Pipeline(dataset)


@pytest.fixture(scope="module")
def sample_summary(dataset, pipeline):
    results = []
    for request in dataset.sample_requests:
        gold_status, gold_steps = dataset.sample_output[request.case_id]
        answer = pipeline.answer(request)
        results.append(score_case(answer.status, answer.steps, gold_status, gold_steps))
    return summarize(results)


def test_sample_status_is_perfect(sample_summary):
    assert sample_summary["status_correct"] == sample_summary["cases"] == 32


def test_sample_steps_never_claim_something_wrong(sample_summary):
    """Precision 1.0: every step we emit is in the reference answer, state and citation included."""
    full = sample_summary["full_steps"]
    assert full["pred"] == full["tp"] == 179
    assert sample_summary["field_accuracy"] == {"state": 1.0, "evidence_id": 1.0}


def test_sample_recall_floor(sample_summary):
    """179 of 193 reference steps. The 14 not found are measured and explained in the evaluation report:
    5 anonymous accounts tied by a coin flip, 7 anonymized analytics profiles that share a reported_at,
    2 audit records that appear nowhere in the participant data."""
    full = sample_summary["full_steps"]
    assert full["gold"] == 193 and full["tp"] >= 179
    assert sample_summary["cases_exact"] >= 20


def test_all_518_rows_satisfy_the_contract(dataset, pipeline):
    times = {f.file_id: f.captured_at for f in dataset.evidence_files}
    times.update({a.activity_id: a.event_time for a in dataset.activity})
    times.update({e.audit_id: e.event_time for e in dataset.audit_log})
    problems = []
    for request in dataset.requests:
        answer = pipeline.answer(request)
        unidentified = answer.status == "COMPLETE" and not answer.steps and answer.note.startswith("no resource")
        problems += verify_row(request.case_id, answer.status, answer.steps, request.audit_at, times, unidentified)
    assert problems == []


def test_output_is_deterministic_and_in_numeric_case_order(dataset):
    def render():
        pipe = Pipeline(dataset)
        rows = [(r.case_id, pipe.answer(r).status, serialize_steps(pipe.answer(r).steps))
                for r in sorted(dataset.requests, key=lambda r: case_sort_key(r.case_id))]
        return rows
    first, second = render(), render()
    assert first == second
    assert len(first) == 518 and [c for c, _, _ in first] == sorted((c for c, _, _ in first), key=case_sort_key)


def test_not_applicable_rows_are_empty_and_deletion_rows_are_not(dataset, pipeline):
    for request in dataset.requests:
        answer = pipeline.answer(request)
        if answer.status == "NOT_APPLICABLE":
            assert answer.steps == []


def test_no_prediction_module_reads_the_sample_answers():
    """Sample labels may be read only by the loader that parses them and by the scorer."""
    package = Path(__file__).resolve().parents[1] / "ghostaudit"
    allowed = {"data.py", "models.py", "scoring.py"}
    offenders = [p.name for p in package.glob("*.py") if p.name not in allowed and "sample_output" in p.read_text(encoding="utf-8")]
    assert offenders == []


# ---------------------------------------------------------------------- workflow matcher
def test_workflow_matcher_learns_its_rules_from_identified_cases(pipeline):
    stats = pipeline.workflow.stats
    assert stats["account_result_map"] == {"COMPLETE": "SUCCESS", "NOT_STARTED": "FAILED", "PARTIALLY_COMPLETE": "PARTIAL"}
    lo, hi = stats["account_window_minutes"]
    assert -120 < lo < -60 and 0 < hi < 30
    # the counting identity that makes elimination valid: every case that needs an account has one row
    assert stats["cases_needing_account"] == stats["unclaimed_account_rows"]


def test_workflow_matcher_never_assigns_a_row_twice_or_a_claimed_account(pipeline):
    assigned = list(pipeline.workflow.account.values())
    assert len(assigned) == len(set(assigned))
    claimed = {rid for rids in pipeline._relevant.values() for rid in rids}
    assert not set(assigned) & claimed


def test_workflow_matches_in_the_samples_are_all_correct(dataset, pipeline):
    checked = 0
    for request in dataset.sample_requests:
        rid = pipeline.workflow.account.get(request.case_id)
        if rid:
            checked += 1
            assert rid in {s["resource_id"] for s in dataset.sample_output[request.case_id][1]}
    assert checked >= 10
