"""Compare predicted answers with reference answers (the public samples).

Metrics reported (the exact hidden grader is unknown, so several complementary views are used):
  status accuracy      the case-level deletion_status matches
  step precision/recall/F1
                       steps compared as (phase, system_id, resource_id, operation, state, evidence_id)
                       tuples, order ignored; "identity" variant ignores evidence_id
  field accuracy       for each reference step that has a counterpart with the same
                       (phase, operation, system_id, resource_id), how often each remaining field matches
  sequence accuracy    the ordered list of (phase, system_id, resource_id, operation) is identical;
                       also the mean longest-common-subsequence ratio
"""
from __future__ import annotations

from collections import Counter
from difflib import SequenceMatcher

STEP_FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")
IDENTITY_FIELDS = ("phase", "system_id", "resource_id", "operation", "state")
KEY_FIELDS = ("phase", "operation", "system_id", "resource_id")


def _t(step: dict, fields: tuple[str, ...]) -> tuple:
    return tuple(step.get(f, "") for f in fields)


def _prf(pred: Counter, gold: Counter) -> tuple[int, int, int]:
    tp = sum((pred & gold).values())
    return tp, sum(pred.values()), sum(gold.values())


def score_case(pred_status: str, pred_steps: list[dict], gold_status: str, gold_steps: list[dict]) -> dict:
    out: dict = {"status_ok": pred_status == gold_status}
    for name, fields in (("full", STEP_FIELDS), ("identity", IDENTITY_FIELDS)):
        tp, p, g = _prf(Counter(_t(s, fields) for s in pred_steps), Counter(_t(s, fields) for s in gold_steps))
        out[f"{name}_tp"], out[f"{name}_pred"], out[f"{name}_gold"] = tp, p, g
    pred_by_key = {_t(s, KEY_FIELDS): s for s in pred_steps}
    matched = field_ok = 0
    per_field: Counter = Counter()
    for gold in gold_steps:
        other = pred_by_key.get(_t(gold, KEY_FIELDS))
        if other is None:
            continue
        matched += 1
        for f in ("state", "evidence_id"):
            if other.get(f) == gold.get(f):
                per_field[f] += 1
    out["matched_steps"], out["field_ok"] = matched, per_field
    pseq = [_t(s, KEY_FIELDS) for s in pred_steps]
    gseq = [_t(s, KEY_FIELDS) for s in gold_steps]
    out["sequence_exact"] = pseq == gseq
    out["lcs_ratio"] = SequenceMatcher(None, pseq, gseq, autojunk=False).ratio() if (pseq or gseq) else 1.0
    out["case_exact"] = out["status_ok"] and pred_steps == [{**s} for s in gold_steps] or (
        out["status_ok"] and [_t(s, ("step_no",) + STEP_FIELDS) for s in pred_steps]
        == [_t(s, ("step_no",) + STEP_FIELDS) for s in gold_steps])
    return out


def summarize(results: list[dict]) -> dict:
    n = len(results)
    def ratio(a: int, b: int) -> float:
        return round(a / b, 4) if b else 1.0
    summary = {"cases": n, "status_correct": sum(r["status_ok"] for r in results),
               "cases_exact": sum(r["case_exact"] for r in results),
               "sequence_exact": sum(r["sequence_exact"] for r in results),
               "mean_lcs_ratio": round(sum(r["lcs_ratio"] for r in results) / n, 4) if n else 1.0}
    for name in ("full", "identity"):
        tp = sum(r[f"{name}_tp"] for r in results)
        p = sum(r[f"{name}_pred"] for r in results)
        g = sum(r[f"{name}_gold"] for r in results)
        precision, recall = ratio(tp, p), ratio(tp, g)
        summary[f"{name}_steps"] = {"tp": tp, "pred": p, "gold": g, "precision": precision, "recall": recall,
                                    "f1": round(2 * precision * recall / (precision + recall), 4) if tp else 0.0}
    matched = sum(r["matched_steps"] for r in results)
    summary["field_accuracy"] = {f: ratio(sum(r["field_ok"][f] for r in results), matched) for f in ("state", "evidence_id")}
    summary["matched_steps"] = matched
    return summary
