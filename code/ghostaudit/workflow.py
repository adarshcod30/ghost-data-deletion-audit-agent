"""Link anonymous resources to cases through the deletion workflow's own activity rows.

Some resources a case concerns carry no identifier anywhere in the evidence: a deleted account
answers a lookup with 404 and no email, an anonymized analytics profile has every identifying
field null. The only record that ties such a resource to a case is the activity log, where the
deletion worker wrote a row for it shortly before the case's `reported_at`.

Two facts make this usable, both measured from the cases whose accounts ARE identified by email:

  * every case owns exactly one account deletion row, in a window just before `reported_at`
    (the number of cases still needing an account equals the number of unclaimed rows), and
  * the row's result follows the case's reported status (COMPLETE -> SUCCESS, NOT_STARTED ->
    FAILED, PARTIALLY_COMPLETE -> PARTIAL).

The mapping and the window are learned from those identified cases, not typed in. Rows are then
matched to cases by elimination, and a link is made only when it is forced: a row that fits one
case, or a case that fits one row, after already-assigned rows are removed. Ties are left
unassigned rather than guessed. This is a statistical inference from timing, not a proof, and
the README says so.

Anonymized analytics profiles were tried the same way and rejected: their activity rows sit at one
identical offset before `reported_at`, so cases that share a `reported_at` cannot be told apart. On
the samples the attempt recovered none of the missing steps and added one wrong one.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .evidence import EvidenceIndex, resource_prefix
from .models import Activity, DeletionRequest

MINUTE = dt.timedelta(minutes=1)


@dataclass(slots=True)
class WorkflowLinks:
    account: dict[str, str] = field(default_factory=dict)     # case_id -> account resource id
    stats: dict = field(default_factory=dict)


def _percentile_window(offsets: list[float], pad: float) -> tuple[float, float]:
    ordered = sorted(offsets)
    return ordered[0] - pad, ordered[-1] + pad


def _learn_account_rules(requests, relevant, rows_by_resource) -> tuple[dict[str, str], tuple[float, float]]:
    """Result per reported status and offset window, from cases whose account is identified."""
    results: dict[str, Counter] = defaultdict(Counter)
    samples: list[tuple[str, str, float]] = []
    for req in requests:
        for rid in relevant.get(req.case_id, ()):
            if resource_prefix(rid) != "account":
                continue
            rows = [a for a in rows_by_resource.get(rid, ()) if a.target_system == "account_service"]
            if len(rows) == 1:
                offset = (rows[0].event_time - req.reported_at) / MINUTE
                results[req.reported_status][rows[0].reported_result] += 1
                samples.append((req.reported_status, rows[0].reported_result, offset))
    expected = {status: counter.most_common(1)[0][0] for status, counter in results.items()}
    inliers = [off for status, result, off in samples if expected.get(status) == result and -180 <= off <= 60]
    window = _percentile_window(inliers, 5.0) if inliers else (-90.0, 15.0)
    return expected, window


def link_through_workflow(requests: list[DeletionRequest], activity: tuple[Activity, ...], index: EvidenceIndex,
                          relevant: dict[str, list[str]]) -> WorkflowLinks:
    """`relevant` maps every case to the resources already identified for it."""
    links = WorkflowLinks()
    claimed = {rid for rids in relevant.values() for rid in rids}
    rows_by_resource: dict[str, list[Activity]] = defaultdict(list)
    for a in activity:
        if a.source_system == "deletion_worker":
            rows_by_resource[a.resource_id].append(a)

    # ---------------------------------------------------------------- accounts: one row per case
    expected, (lo, hi) = _learn_account_rules(requests, relevant, rows_by_resource)
    needing = [r for r in requests if not any(resource_prefix(x) == "account" for x in relevant.get(r.case_id, ()))]
    rows = [a for a in activity if a.source_system == "deletion_worker" and a.event_type == "DELETE_RECORD"
            and a.target_system == "account_service" and a.resource_id not in claimed]
    by_id = {a.activity_id: a for a in rows}
    candidates = {
        r.case_id: {a.activity_id for a in rows
                    if r.reported_at + lo * MINUTE <= a.event_time <= r.reported_at + hi * MINUTE
                    and a.reported_result == expected.get(r.reported_status)}
        for r in needing
    }
    assigned: dict[str, str] = {}
    changed = True
    while changed:
        changed = False
        taken = set(assigned.values())
        for case_id, options in candidates.items():
            if case_id in assigned:
                continue
            left = options - taken
            if len(left) == 1:
                assigned[case_id] = next(iter(left))
                taken.add(assigned[case_id])
                changed = True
        wanted: dict[str, set[str]] = defaultdict(set)
        for case_id, options in candidates.items():
            if case_id not in assigned:
                for row in options - taken:
                    wanted[row].add(case_id)
        for row, cases in wanted.items():
            if len(cases) == 1 and row not in set(assigned.values()):
                case_id = next(iter(cases))
                if case_id not in assigned:
                    assigned[case_id] = row
                    changed = True
    links.account = {case: by_id[row].resource_id for case, row in assigned.items()}

    links.stats = {
        "account_result_map": expected, "account_window_minutes": (round(lo, 1), round(hi, 1)),
        "cases_needing_account": len(needing), "unclaimed_account_rows": len(rows),
        "accounts_assigned": len(links.account),
    }
    return links
