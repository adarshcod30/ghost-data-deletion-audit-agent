"""Evaluate the pipeline against the public samples.

    .venv/bin/python code/evaluation/main.py            # summary
    .venv/bin/python code/evaluation/main.py --diff     # plus a diff for every case that is not exact
    .venv/bin/python code/evaluation/main.py --case case_21 --diff

Nothing on the prediction path reads sample_output.csv; this script is the only reader.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghostaudit.common import case_sort_key  # noqa: E402
from ghostaudit.data import load_dataset  # noqa: E402
from ghostaudit.pipeline import Pipeline  # noqa: E402
from ghostaudit.scoring import score_case, summarize  # noqa: E402


def fmt(step: dict) -> str:
    return f"{step['phase'][:4]} {step['operation']:<26} {step['system_id']:<20} {step['resource_id']:<20} {step['state']:<11} {step['evidence_id'] or '-'}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--diff", action="store_true")
    parser.add_argument("--case", action="append")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    dataset = load_dataset()
    pipeline = Pipeline(dataset)
    results, shown = [], 0
    for request in sorted(dataset.sample_requests, key=lambda r: case_sort_key(r.case_id)):
        if args.case and request.case_id not in args.case:
            continue
        gold_status, gold_steps = dataset.sample_output[request.case_id]
        answer = pipeline.answer(request)
        result = score_case(answer.status, answer.steps, gold_status, gold_steps)
        results.append(result)
        if args.diff and not result["case_exact"]:
            shown += 1
            print(f"--- {request.case_id}: status {answer.status} (gold {gold_status}); exact={result['case_exact']}")
            pred, gold = {tuple(sorted(s.items())) for s in answer.steps}, {tuple(sorted(s.items())) for s in gold_steps}
            gk = [(s["phase"], s["operation"], s["system_id"], s["resource_id"]) for s in gold_steps]
            for s in gold_steps:
                if tuple(sorted({**s, "step_no": 0}.items())) not in {tuple(sorted({**p, "step_no": 0}.items())) for p in answer.steps}:
                    print("   MISSING ", fmt(s))
            for s in answer.steps:
                if tuple(sorted({**s, "step_no": 0}.items())) not in {tuple(sorted({**g, "step_no": 0}.items())) for g in gold_steps}:
                    print("   EXTRA   ", fmt(s))
    summary = summarize(results)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        s = summary
        print(f"cases {s['cases']}: status {s['status_correct']}/{s['cases']}, exact {s['cases_exact']}/{s['cases']}, "
              f"sequence-exact {s['sequence_exact']}/{s['cases']}, mean LCS {s['mean_lcs_ratio']}")
        for name in ("full_steps", "identity_steps"):
            t = s[name]
            print(f"{name:15s} tp {t['tp']}/{t['gold']} gold, {t['pred']} predicted: precision {t['precision']}, recall {t['recall']}, F1 {t['f1']}")
        print(f"field accuracy on {s['matched_steps']} aligned steps: {s['field_accuracy']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
