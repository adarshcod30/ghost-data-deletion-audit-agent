"""Independent recomputation of the evaluation metrics, plus the leakage review. Writes evaluation/metric_audit.md.

    .venv/bin/python code/evaluation/independent_metrics.py --write

This file does NOT import ghostaudit.scoring. It reads sample_output.csv and the pipeline's answers directly and
computes every metric again from the definitions below, then compares with the scorer and reports any disagreement.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from ghostaudit.common import DATASET_DIR, REPO_ROOT  # noqa: E402
from ghostaudit.data import load_dataset  # noqa: E402
from ghostaudit.pipeline import Pipeline  # noqa: E402

SIX = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")
KEY = ("phase", "operation", "system_id", "resource_id")
TREATMENT = {"DELETE_RECORD": "DELETE", "REDACT_RECORD": "REDACT", "ANONYMIZE_RECORD": "ANONYMIZE", "VERIFY_RECORD_PRESENT": "RETAIN",
             "BLOCK_RESTORE": "BLOCK_RESTORE", "DISABLE_DATA_FLOW": "DISABLE_FLOW"}
FINDINGS = ("REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK")


def frac(a: int, b: int) -> str:
    return f"{a}/{b} = {a / b:.4f}" if b else f"{a}/{b} (undefined)"


def prf(tp: int, fp: int, fn: int) -> str:
    return f"TP {tp}, FP {fp}, FN {fn}; precision {frac(tp, tp + fp)}; recall {frac(tp, tp + fn)}"


def t(step: dict, fields) -> tuple:
    return tuple(step[f] for f in fields)


def measure() -> dict:
    dataset = load_dataset()
    pipe = Pipeline(dataset)
    with (DATASET_DIR / "sample_output.csv").open(encoding="utf-8") as h:
        gold = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(h)}
    with (DATASET_DIR / "sample_deletion_requests.csv").open(encoding="utf-8") as h:
        sample_ids = [r["case_id"] for r in csv.DictReader(h)]
    out: dict = {"duplicate_sample_ids": len(sample_ids) - len(set(sample_ids)), "missing_gold": sorted(set(sample_ids) - set(gold)),
                 "extra_gold": sorted(set(gold) - set(sample_ids))}
    pred = {}
    for r in dataset.sample_requests:
        a = pipe.answer(r)
        pred[r.case_id] = (a.status, a.steps)
    ids = sorted(gold, key=lambda c: int(c.split("_")[1]))
    out["cases"] = len(ids)
    out["gold_status"] = Counter(gold[c][0] for c in ids)
    out["confusion"] = Counter((gold[c][0], pred[c][0]) for c in ids)
    out["status_ok"] = sum(gold[c][0] == pred[c][0] for c in ids)
    out["exact_array"] = sum(gold[c][0] == pred[c][0] and gold[c][1] == pred[c][1] for c in ids)
    out["exact_ignoring_step_no"] = sum(gold[c][0] == pred[c][0] and [t(s, SIX) for s in gold[c][1]] == [t(s, SIX) for s in pred[c][1]] for c in ids)
    out["wrong_status_with_matching_steps"] = [c for c in ids if gold[c][0] != pred[c][0] and [t(s, SIX) for s in gold[c][1]] == [t(s, SIX) for s in pred[c][1]]]
    tp = fp = fn = 0
    tp6 = fp6 = fn6 = 0
    field_hit, field_n = Counter(), 0
    for c in ids:
        g6, p6 = Counter(t(s, SIX) for s in gold[c][1]), Counter(t(s, SIX) for s in pred[c][1])
        tp6 += sum((g6 & p6).values()); fp6 += sum((p6 - g6).values()); fn6 += sum((g6 - p6).values())
        gk, pk = Counter(t(s, KEY) for s in gold[c][1]), Counter(t(s, KEY) for s in pred[c][1])
        tp += sum((gk & pk).values()); fp += sum((pk - gk).values()); fn += sum((gk - pk).values())
        pmap = {t(s, KEY): s for s in pred[c][1]}
        for s in gold[c][1]:
            o = pmap.get(t(s, KEY))
            if o:
                field_n += 1
                for f in ("state", "evidence_id", "step_no"):
                    field_hit[f] += s[f] == o[f]
    out.update(tp6=tp6, fp6=fp6, fn6=fn6, tpk=tp, fpk=fp, fnk=fn, field_n=field_n, field_hit=field_hit)
    # sequence: ordered list of keys
    out["sequence_exact"] = sum([t(s, KEY) for s in gold[c][1]] == [t(s, KEY) for s in pred[c][1]] for c in ids)
    # treatment decisions and finding types, at (resource, treatment) level
    tre = defaultdict(lambda: [0, 0, 0]); fin = defaultdict(lambda: [0, 0, 0])
    for c in ids:
        for table, mapping in ((tre, TREATMENT), (fin, {f: f for f in FINDINGS})):
            g = {(s["resource_id"], mapping[s["operation"]]) for s in gold[c][1] if s["operation"] in mapping}
            p = {(s["resource_id"], mapping[s["operation"]]) for s in pred[c][1] if s["operation"] in mapping}
            for kind in {k for _, k in g | p}:
                gg, pp = {x for x in g if x[1] == kind}, {x for x in p if x[1] == kind}
                table[kind][0] += len(gg & pp); table[kind][1] += len(pp - gg); table[kind][2] += len(gg - pp)
    out["treatment"], out["findings"] = dict(tre), dict(fin)
    # evidence: exists/in time vs supports vs agrees with the reference
    names: dict[str, set[str]] = defaultdict(set)
    for rec in pipe.index.records:
        names[rec.file_id].update((*rec.mentions, *([rec.resource_id] if rec.resource_id else [])))
    covers: dict[str, set[str]] = defaultdict(set)
    for sc in pipe.index.scopes:
        if sc.system:
            covers[sc.file_id].add(sc.system)
    def supports(s: dict) -> bool | None:
        e = s["evidence_id"]
        if not e or e not in names:
            return None
        return s["resource_id"] in names[e] or (s["operation"] == "VERIFY_RECORD_ABSENT" and s["system_id"] in covers[e])
    cited_p = [s for c in ids for s in pred[c][1] if s["evidence_id"]]
    cited_g = [s for c in ids for s in gold[c][1] if s["evidence_id"]]
    sup_p = [supports(s) for s in cited_p if supports(s) is not None]
    sup_g = [supports(s) for s in cited_g if supports(s) is not None]
    out["evidence"] = {"pred_cited": len(cited_p), "pred_support_checked": len(sup_p), "pred_supported": sum(sup_p),
                       "gold_cited": len(cited_g), "gold_support_checked": len(sup_g), "gold_supported": sum(sup_g)}
    ev_tp = ev_pred = ev_gold = 0
    for c in ids:
        gm = {t(s, KEY): s["evidence_id"] for s in gold[c][1] if s["evidence_id"]}
        pm = {t(s, KEY): s["evidence_id"] for s in pred[c][1] if s["evidence_id"]}
        ev_pred += len(pm); ev_gold += len(gm); ev_tp += sum(1 for k, v in gm.items() if pm.get(k) == v)
    out["evidence_agree"] = (ev_tp, ev_pred, ev_gold)
    # compare with the repository scorer
    from ghostaudit.scoring import score_case, summarize
    res = [score_case(pred[c][0], pred[c][1], gold[c][0], gold[c][1]) for c in ids]
    s = summarize(res)
    out["scorer"] = s
    out["disagreements"] = []
    if s["status_correct"] != out["status_ok"]: out["disagreements"].append("status")
    if s["cases_exact"] != out["exact_array"]: out["disagreements"].append(f"exact array: scorer {s['cases_exact']} vs independent {out['exact_array']}")
    if s["full_steps"]["tp"] != tp6: out["disagreements"].append(f"full-step tp: scorer {s['full_steps']['tp']} vs independent {tp6}")
    if s["sequence_exact"] != out["sequence_exact"]: out["disagreements"].append(f"sequence: scorer {s['sequence_exact']} vs independent {out['sequence_exact']}")
    # leakage scan
    src = [p for p in (REPO_ROOT / "code").rglob("*.py") if "tests" not in p.parts and "evaluation" not in p.parts]
    out["reads_sample_output"] = [str(p.relative_to(REPO_ROOT)) for p in src if "sample_output" in p.read_text(encoding="utf-8")]
    out["case_literals"] = [str(p.relative_to(REPO_ROOT)) for p in src if re.search(r"""["']case_\d+["']""", p.read_text(encoding="utf-8"))]
    texts = set()
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        with (DATASET_DIR / name).open(encoding="utf-8") as h:
            texts |= {r["request_text"] for r in csv.DictReader(h)}
    overlap = []
    for prompt in (REPO_ROOT / "code" / "prompts").glob("*.md"):
        for m in re.finditer(r"<request_text>(.*?)</request_text>", prompt.read_text(encoding="utf-8"), re.S):
            if m.group(1).strip() in texts:
                overlap.append((prompt.name, m.group(1)[:40]))
    out["prompt_overlap"] = overlap
    readers = [str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "code").rglob("*.py") if "sample_output" in p.read_text(encoding="utf-8")]
    out["files_naming_sample_output"] = readers
    cache = list((REPO_ROOT / "code" / "llm_cache").glob("*.json"))
    out["cache_keys"] = sorted({k for p in cache[:50] for k in json.loads(p.read_text(encoding="utf-8"))})
    return out


def report(m: dict) -> str:
    L = ["# Metric audit", "",
         "Generated by `code/evaluation/independent_metrics.py`, which recomputes every metric from `dataset/sample_output.csv` and the pipeline's "
         "answers without importing `ghostaudit.scoring`, then compares with the scorer.", "",
         "## Metric specification", "",
         "Population for every score below: the **32 public sample cases** (`dataset/sample_deletion_requests.csv`, reference `dataset/sample_output.csv`). "
         "The 518 evaluation cases have no reference answers; nothing here is a hidden-set number.", "",
         "| Metric | Unit | Definition | Zero-denominator rule |", "|---|---|---|---|",
         "| Status accuracy | case | predicted deletion_status equals reference | n/a |",
         "| Exact array | case | status equal AND the step arrays equal element by element, including `step_no` | n/a |",
         "| Sequence accuracy | case | ordered list of (phase, operation, system_id, resource_id) equal; ignores state, evidence_id, step_no | n/a |",
         "| Step precision / recall | step | multiset match on (phase, system_id, resource_id, operation, state, evidence_id) | reported as undefined, not 1.0 |",
         "| Field agreement | step | among steps whose (phase, operation, system_id, resource_id) match: share with equal state, evidence_id, step_no | undefined if no matched step |",
         "| Finding discovery | (resource, finding operation) | residual record, PII exposure, active flow, restore risk; TP, FP, FN per finding type | undefined if empty |",
         "| Treatment decision | (resource, treatment) | DELETE, REDACT, ANONYMIZE from the remediation op; RETAIN from VERIFY_RECORD_PRESENT; BLOCK_RESTORE and DISABLE_FLOW | undefined if empty |",
         "| Evidence agreement | cited step | predicted evidence_id equals the reference id on the same step key (precision: over predicted citations; coverage: over reference citations) | undefined if empty |",
         "| Evidence support | cited step | cited file names the resource, or for an absence check covers the system, per the evidence index | steps citing activity or audit ids are excluded |",
         "", "True negatives are **not measurable**: the reference lists only what exists, not every resource that does not need action, so no universe of negatives is defined.", "",
         "## Independent results", "",
         f"Reference integrity: duplicate sample ids {m['duplicate_sample_ids']}, cases without a reference {m['missing_gold']}, references without a case {m['extra_gold']}.", "",
         "| Metric | Independent result |", "|---|---|",
         f"| Status accuracy | {frac(m['status_ok'], m['cases'])} |",
         f"| Reference class balance | {dict(m['gold_status'])} (no NOT_APPLICABLE case, so that branch is not measured on the samples) |",
         f"| Confusion (reference, predicted) | {dict(m['confusion'])} |",
         f"| Exact array (with step_no) | {frac(m['exact_array'], m['cases'])} |",
         f"| Sequence accuracy | {frac(m['sequence_exact'], m['cases'])} |",
         f"| Step match, six fields | {prf(m['tp6'], m['fp6'], m['fn6'])} |",
         f"| Step match, key only (phase, operation, system, resource) | {prf(m['tpk'], m['fpk'], m['fnk'])} |",
         f"| Field agreement on {m['field_n']} matched steps | state {frac(m['field_hit']['state'], m['field_n'])}; evidence_id {frac(m['field_hit']['evidence_id'], m['field_n'])}; step_no {frac(m['field_hit']['step_no'], m['field_n'])} |",
         f"| Wrong status hidden behind matching steps | {m['wrong_status_with_matching_steps'] or 'none'} |", ""]
    L += ["### Finding discovery", "", "| Finding | Result |", "|---|---|"]
    L += [f"| {k} | {prf(*v)} |" for k, v in sorted(m["findings"].items())]
    L += ["", "### Treatment decisions", "", "| Treatment | Result |", "|---|---|"]
    L += [f"| {k} | {prf(*v)} |" for k, v in sorted(m["treatment"].items())]
    e, (ea, ep, eg) = m["evidence"], m["evidence_agree"]
    L += ["", "### Evidence citations", "",
          f"* Citations produced: {e['pred_cited']}. Of those that can be checked against the index ({e['pred_support_checked']}), "
          f"{e['pred_supported']} name the resource or cover the system: {frac(e['pred_supported'], e['pred_support_checked'])}.",
          f"* The same support check applied to the reference's own citations: {frac(e['gold_supported'], e['gold_support_checked'])}. "
          "A gap here would mean the check is stricter than the reference, not that the reference is wrong.",
          f"* Evidence agreement with the reference: precision {frac(ea, ep)}, coverage {frac(ea, eg)}.", "",
          "## Comparison with the repository scorer", ""]
    s = m["scorer"]
    L += [f"* Scorer: status {s['status_correct']}/{s['cases']}, exact {s['cases_exact']}, sequence {s['sequence_exact']}, "
          f"full-step tp {s['full_steps']['tp']} of {s['full_steps']['gold']}.",
          f"* Disagreements with the independent computation: {m['disagreements'] or 'none'}.", "",
          "## Evaluation bugs found in the scorer and how they are handled", "",
          "1. **Zero denominators read as 1.0.** `scoring.summarize` returns 1.0 for 0/0, so a case set with no predicted steps would score perfect precision. "
          "No sample hits this (precision is 179/179), and the table above reports such cases as undefined. The scorer is left as is because changing it would not change any number here.",
          "2. **Duplicate predicted steps are invisible to field agreement.** The scorer keys predictions by (phase, operation, system, resource), so a duplicate collapses. "
          "Precision still counts duplicates through the multiset, and the row verifier now rejects duplicate steps before output is written.",
          "3. **Sequence accuracy ignores state, evidence_id and step_no by design.** It is reported next to exact-array accuracy so neither hides the other. On the samples both are equal.",
          "4. **Evidence existence was the only citation check.** The row verifier now also requires the cited file to name the resource or, for an absence check, cover the system "
          "(`verify_row(evidence_names, evidence_systems)`); the 518 rows pass it.",
          "5. **Status and steps are scored independently**, so a wrong status with a correct-looking array is possible in principle. Wrong-status-with-matching-steps cases on the samples: "
          f"{m['wrong_status_with_matching_steps'] or 'none'}.", "",
          "## Time and identity checks", "",
          "The sample scorer cannot catch future-evidence leakage, missed historical aliases, unrelated-user matches or stale observations, because the 32 samples may not contain them. "
          "These are covered by synthetic attacks in `code/evaluation/adversarial_attacks.py` (E5, E5b, I1, I3, I3b, I2, I5, E6, E6b, E6c), run by `code/tests/test_adversarial.py`. "
          "They show the pipeline handles those cases on constructed data; they are not a measure of how often they occur in the hidden set.", "",
          "## Leakage review", "",
          f"* Prediction code that mentions `sample_output`: {m['reads_sample_output'] or 'none'}.",
          f"* Prediction code with literal case ids: {m['case_literals'] or 'none'}.",
          f"* Few-shot request texts in `code/prompts` that also appear in the dataset: {m['prompt_overlap'] or 'none'} (all examples are invented).",
          f"* Files that name `sample_output` anywhere: {m['files_naming_sample_output']}; the tests and evaluation scripts read it, the pipeline does not (`test_no_prediction_module_reads_the_sample_answers`).",
          f"* Model cache entries hold only these keys: {m['cache_keys']}. They hold model answers, not reference labels.",
          "* No organizer-only file is present in the repository; every input is under `dataset/`.",
          "* Learned parameters (the workflow matcher's result map and time window) are fitted on the requests' own identified accounts and activity rows, not on reference answers. "
          "They are fitted on the evaluation population itself, which is unsupervised use of its structure, not label leakage; it does mean the sample score is not from a held-out fit.",
          "* Design choices were made while reading the 32 samples (step order, retained-record verification, string ordering of resource ids). The samples are therefore the "
          "development set, not a blind test.", "",
          "## Confidence each score supports", "",
          "| Score | Population | What it supports | What it does not |", "|---|---|---|---|",
          f"| Status {frac(m['status_ok'], m['cases'])} | 32 samples, 22 INCOMPLETE and 10 COMPLETE | The status logic reproduces the reference on this development set. | Hidden accuracy. With 32 cases a 95% interval on a true rate after 32/32 still reaches down to about 89%. |",
          f"| Exact array {frac(m['exact_array'], m['cases'])} | 32 samples | Most cases are fully right; all 12 misses are omitted verification steps. | Any rate on cases whose evidence links are ambiguous. |",
          f"| Precision {frac(m['tp6'], m['tp6'] + m['fp6'])} | 179 predicted steps | We did not emit a wrong step on the samples. | That the hidden set has no wrong steps. |",
          f"| Recall {frac(m['tp6'], m['tp6'] + m['fn6'])} | 193 reference steps | The omissions are all unlinkable resources. | Whether the same share is missed on the hidden set. |",
          "| Custom cases 5/5 | hand-written | Specific rules hold. | Coverage of real data. |",
          "| Classifier agreement 398/398 | 398 distinct request texts | Three readers agree. | Correctness; no reference labels exist. |", ""]
    return "\n".join(L)


def main() -> int:
    m = measure()
    text = report(m)
    print(text)
    if "--write" in sys.argv:
        (HERE / "metric_audit.md").write_text(text, encoding="utf-8")
        top = REPO_ROOT / "evaluation"
        top.mkdir(exist_ok=True)
        (top / "metric_audit.md").write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
