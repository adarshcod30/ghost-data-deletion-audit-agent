"""Cross-check the deterministic request classifier against two models on every request text.

    .venv/bin/python code/evaluation/classifier_crosscheck.py

The pipeline decides "does this request authorise deletion?" with the rule baseline in
ghostaudit/classifier.py, and that decision gates the whole case (a request that is not a deletion
request gets NOT_APPLICABLE and no steps). There is no gold label for the 518 requests, so this
script does the next best thing: it asks two independent readers (the primary and the second model
from config.py, temperature 0, cached) and lists every text on which any of the three disagree.

Agreement is not proof and disagreement is not an error. The report is the work list for reading
the disputed texts by eye. Nothing here changes output.csv by itself.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghostaudit.classifier import baseline_authorizes_deletion  # noqa: E402
from ghostaudit.common import REPO_ROOT, case_sort_key  # noqa: E402
from ghostaudit.config import PRIMARY_MODEL_ID, SECOND_MODEL_ID  # noqa: E402
from ghostaudit.data import load_dataset  # noqa: E402
from ghostaudit.llm import BedrockClient, LLMUnavailable, cost_usd, extract_json_object  # noqa: E402

PROMPT = (Path(__file__).resolve().parents[1] / "prompts" / "request_classifier.md").read_text(encoding="utf-8")
OUT_JSON = Path(__file__).resolve().parent / "classifier_crosscheck.json"
OUT_MD = Path(__file__).resolve().parent / "classifier_crosscheck.md"
MODELS = {"primary": PRIMARY_MODEL_ID, "second": SECOND_MODEL_ID}


def ask(client: BedrockClient, model_id: str, text: str) -> dict:
    """One classification. Same prompt and message shape as model_benchmark.py, so calls share the cache."""
    user = f"<request_text>{text}</request_text>"
    try:
        result = client.converse(model_id, user, system=PROMPT, max_tokens=700, purpose="classifier_crosscheck")
    except LLMUnavailable as exc:
        return {"error": str(exc)[:120]}
    parsed = extract_json_object(result.text)
    if not (isinstance(parsed, dict) and isinstance(parsed.get("authorizes_deletion"), bool)):
        return {"error": "invalid json", "raw": result.text[:160]}
    return {"decision": parsed["authorizes_deletion"], "type": parsed.get("request_type"),
            "language": parsed.get("language"), "evidence": parsed.get("evidence")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default=None)
    args = parser.parse_args()
    dataset = load_dataset()
    client = BedrockClient(profile=args.profile, cache_dir=REPO_ROOT / ".cache" / "llm")

    cases: dict[str, list[str]] = {}       # request text -> case ids that carry it
    for request in list(dataset.requests) + list(dataset.sample_requests):
        cases.setdefault(request.request_text, []).append(request.case_id)
    texts = sorted(cases)
    print(f"{len(texts)} distinct request texts across {sum(len(v) for v in cases.values())} cases")

    answers: dict[str, dict[str, dict]] = {name: {} for name in MODELS}
    for name, model_id in MODELS.items():
        with ThreadPoolExecutor(8) as pool:
            for text, out in zip(texts, pool.map(lambda t: ask(client, model_id, t), texts)):
                answers[name][text] = out
        bad = sum("error" in o for o in answers[name].values())
        print(f"{name:8s} {model_id}: {len(texts) - bad} valid, {bad} unusable")

    rows = []
    for text in texts:
        base, why = baseline_authorizes_deletion(text)
        primary, second = answers["primary"][text], answers["second"][text]
        rows.append({"cases": sorted(cases[text], key=case_sort_key), "text": text, "baseline": base,
                     "baseline_reason": why, "primary": primary, "second": second})

    def verdict(row, key):
        return row[key].get("decision") if "decision" in row[key] else None

    disputed = []
    for row in rows:
        votes = {"baseline": row["baseline"], "primary": verdict(row, "primary"), "second": verdict(row, "second")}
        if len({v for v in votes.values() if v is not None}) > 1 or any(v is None for v in votes.values()):
            disputed.append({**row, "votes": votes})

    def agree(a, b):
        pairs = [(x, y) for x, y in ((a(r), b(r)) for r in rows) if x is not None and y is not None]
        return sum(x == y for x, y in pairs), len(pairs)

    pair_rows = [("baseline vs primary", agree(lambda r: r["baseline"], lambda r: verdict(r, "primary"))),
                 ("baseline vs second", agree(lambda r: r["baseline"], lambda r: verdict(r, "second"))),
                 ("primary vs second", agree(lambda r: verdict(r, "primary"), lambda r: verdict(r, "second")))]
    case_counts = Counter()
    for row in rows:
        case_counts["baseline_not_deletion"] += len(row["cases"]) * (not row["baseline"])
        case_counts["all_cases"] += len(row["cases"])
    usage = client.ledger.summary()

    OUT_JSON.write_text(json.dumps({"models": MODELS, "texts": len(texts), "cases": case_counts["all_cases"],
                                    "pairwise_agreement": {k: list(v) for k, v in pair_rows},
                                    "disputed": disputed}, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                        encoding="utf-8")

    lines = ["# Classifier cross-check", "",
             "Generated by `code/evaluation/classifier_crosscheck.py`. It asks two models whether each request",
             "authorises deletion and lists every text on which the rule baseline and the two models do not all",
             "agree. There is no gold label for the hidden requests, so agreement is evidence and not proof.", "",
             f"* Primary reader: `{PRIMARY_MODEL_ID}`. Second reader: `{SECOND_MODEL_ID}`. Temperature 0, cached.",
             f"* Distinct request texts: **{len(texts)}** across **{case_counts['all_cases']}** cases "
             f"(518 hidden plus 32 sample).",
             f"* Cases the baseline treats as not a deletion request: **{case_counts['baseline_not_deletion']}**.", "",
             "| Pair | Agree | Compared |", "|---|---|---|"]
    lines += [f"| {name} | {a} | {n} |" for name, (a, n) in pair_rows]
    lines += ["", f"Texts with any disagreement or unusable answer: **{len(disputed)}**.", ""]
    for model_id, entry in sorted(usage.items()):
        lines.append(f"* `{model_id}`: {entry['calls']} calls this run ({entry['live_calls']} live, "
                     f"{entry['cached_calls']} cached), {entry['input_tokens']} input and {entry['output_tokens']} "
                     f"output tokens, about ${cost_usd(model_id, entry['input_tokens'], entry['output_tokens'])} "
                     f"for the live and cached tokens counted together.")
    lines += ["", "## Disputed texts", ""]
    for row in disputed:
        votes = row["votes"]
        show = lambda v: "n/a" if v is None else ("deletion" if v else "not deletion")
        lines += [f"### {', '.join(row['cases'][:4])}{' and more' if len(row['cases']) > 4 else ''}", "",
                  "> " + row["text"].replace("\n", " ")[:420], "",
                  f"* baseline: **{show(votes['baseline'])}** ({row['baseline_reason']})",
                  f"* primary: **{show(votes['primary'])}**, " + (f"type {row['primary'].get('type')}, evidence "
                  f"\"{row['primary'].get('evidence')}\"" if 'decision' in row['primary'] else row['primary'].get('error', '')),
                  f"* second: **{show(votes['second'])}**, " + (f"type {row['second'].get('type')}, evidence "
                  f"\"{row['second'].get('evidence')}\"" if 'decision' in row['second'] else row['second'].get('error', '')), ""]
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for name, (a, n) in pair_rows:
        print(f"{name:20s} {a}/{n}")
    print(f"disputed texts: {len(disputed)}; baseline not-deletion cases: {case_counts['baseline_not_deletion']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
