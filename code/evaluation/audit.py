"""Hand audit of hidden cases: raw evidence beside our output, with a fixed-seed stratified draw.

    .venv/bin/python code/evaluation/audit.py --seed 20261025 --n 12            # draw and print
    .venv/bin/python code/evaluation/audit.py --cases case_40 case_91           # chosen cases

There is no reference answer for the 518 requests, so precision on them can only be estimated by
reading the evidence the way a reviewer would. For every case this prints everything in the
evidence that names the subject (flagged A for admissible at audit_at, L for later, B for before the
request), the ledger we built with the observation behind each entry, and the final steps.

The draw takes one deletion case from each month February to September and fills the rest at random,
from case ids sorted numerically, so the same seed always gives the same cases.
"""
from __future__ import annotations

import argparse
import collections
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghostaudit.common import case_sort_key  # noqa: E402
from ghostaudit.data import load_dataset  # noqa: E402
from ghostaudit.linking import admissible  # noqa: E402
from ghostaudit.pipeline import Pipeline  # noqa: E402


def draw(dataset, pipeline, seed: int, n: int) -> list[str]:
    rng = random.Random(seed)
    deletion = [r for r in sorted(dataset.requests, key=lambda r: case_sort_key(r.case_id))
                if pipeline.answer(r).status != "NOT_APPLICABLE"]
    by_month = collections.defaultdict(list)
    for r in deletion:
        by_month[r.audit_at.strftime("%m")].append(r.case_id)
    chosen = [rng.choice(by_month[m]) for m in sorted(by_month) if "02" <= m <= "09"]
    rest = [r.case_id for r in deletion if r.case_id not in chosen]
    chosen += rng.sample(rest, max(0, n - len(chosen)))
    return sorted(chosen[:n], key=case_sort_key)


def show(case_id: str, dataset, pipeline) -> None:
    request = next(r for r in dataset.requests if r.case_id == case_id)
    answer = pipeline.answer(request)
    subject = pipeline.resolver.resolve(request)
    f = lambda t: t.strftime("%m-%d %H:%M")
    print(f"\n{'=' * 100}\n{case_id} | reported {request.reported_status} | requested {f(request.requested_at)} "
          f"reported {f(request.reported_at)} AUDIT {f(request.audit_at)} | our status {answer.status}")
    print(f"  text: {request.request_text[:110]!r}")
    print(f"  user {subject.user_id} ({subject.match_kind}) emails {sorted(subject.values('email'))[:3]} "
          f"phones {len(subject.values('phone'))}")
    groups: dict[str, list] = collections.defaultdict(list)
    for value in sorted(subject.strong_values()):
        for rec in pipeline.index.for_identifier(value):
            if rec.kind in ("log_trace", "document"):
                continue
            groups[rec.file_id].append(rec)
    print("  EVIDENCE NAMING THE SUBJECT  (A admissible at audit, L later than audit, B before request)")
    for file_id, recs in sorted(groups.items(), key=lambda kv: min(r.captured_at for r in kv[1])):
        when = min((r.record_time or r.captured_at) for r in recs)
        flag = "A" if all(admissible(r, request.audit_at) for r in recs) else ("L" if not any(admissible(r, request.audit_at) for r in recs) else "A/L")
        if when < request.requested_at:
            flag += "B"
        seen, lines = set(), []
        for r in recs:
            key = (r.resource_id, r.kind)
            if key in seen:
                continue
            seen.add(key)
            brief = {k: v for k, v in r.fields.items() if k in ("event", "result", "rows", "http_status", "status_code", "enabled",
                     "restore_allowed", "eligible", "deletion_block", "available", "account_status", "total_hits", "matched_value")}
            lines.append(f"{r.resource_id or '-'}[{r.kind[:6]}] {brief if brief else r.text[:60].replace(chr(10), ' ')}")
        captured = f(min(r.captured_at for r in recs))
        cite = "citable" if min(r.captured_at for r in recs) <= request.audit_at else "NOT citable (file captured after audit)"
        print(f"    {file_id:12s} [{flag:4s}] record {f(when)}, file {captured} {cite} :: " + " | ".join(lines[:4]) + (f" | +{len(lines) - 4} more" if len(lines) > 4 else ""))
    link = pipeline.workflow.account.get(case_id)
    print(f"  workflow account link: {link or '-'}")
    print("  OUR LEDGER")
    for e in (answer.ledger.entries if answer.ledger else ()):
        o = e.observation
        src = f"{o.file_id} {o.kind[:6]} {f(o.time)}" if o else "inferred"
        print(f"    {e.resource_id:18s} {e.state:12s} cite={e.evidence_id or '-':12s} from {src}{'  [workflow]' if e.resource_id == link else ''}")
    print("  OUR STEPS")
    for s in answer.steps:
        print(f"    {s['step_no']:2d} {s['phase'][:4]} {s['operation']:<26} {s['resource_id']:<20} {s['evidence_id'] or '-'}")
    if not answer.steps:
        print(f"    (none) {answer.note}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=20261025)
    parser.add_argument("--n", type=int, default=12)
    parser.add_argument("--cases", nargs="*")
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--take", type=int, default=999)
    args = parser.parse_args()
    dataset = load_dataset()
    pipeline = Pipeline(dataset)
    cases = args.cases or draw(dataset, pipeline, args.seed, args.n)
    print("audit sample:", cases)
    for case_id in cases[args.skip:args.skip + args.take]:
        show(case_id, dataset, pipeline)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
