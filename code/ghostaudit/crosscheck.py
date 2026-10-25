"""Second opinion on the one decision that gates a whole case: does the request authorise deletion?

The rule baseline in classifier.py decides, and the decision is what ends up in output.csv. This stage
asks two models the same question, at temperature 0 through the cached client, and records where the
three readers disagree. A disagreement is reported, never applied: the output rows do not depend on
any model, so output.csv is byte-identical with or without this stage and on every run.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .classifier import baseline_authorizes_deletion
from .config import PRIMARY_MODEL_ID, SECOND_MODEL_ID
from .llm import BedrockClient, LLMUnavailable, extract_json_object

PROMPT = (Path(__file__).resolve().parents[1] / "prompts" / "request_classifier.md").read_text(encoding="utf-8")
MODELS = {"primary": PRIMARY_MODEL_ID, "second": SECOND_MODEL_ID}


def ask(client: BedrockClient, model_id: str, text: str, purpose: str = "classifier_crosscheck") -> dict:
    """One classification. The request text goes inside <request_text> tags as data, never as instructions."""
    user = f"<request_text>{text}</request_text>"
    try:
        result = client.converse(model_id, user, system=PROMPT, max_tokens=700, purpose=purpose)
    except LLMUnavailable as exc:
        return {"error": str(exc)[:120]}
    parsed = extract_json_object(result.text)
    if not (isinstance(parsed, dict) and isinstance(parsed.get("authorizes_deletion"), bool)):
        return {"error": "invalid json", "raw": result.text[:160]}
    return {"decision": parsed["authorizes_deletion"], "type": parsed.get("request_type"),
            "language": parsed.get("language"), "evidence": parsed.get("evidence")}


def crosscheck(client: BedrockClient, texts: list[str], workers: int = 8) -> list[dict]:
    """One row per distinct text, in sorted order: the baseline and both models' answers."""
    ordered = sorted(set(texts))
    answers = {}
    for name, model_id in MODELS.items():
        with ThreadPoolExecutor(workers) as pool:
            answers[name] = dict(zip(ordered, pool.map(lambda t: ask(client, model_id, t), ordered)))
    rows = []
    for text in ordered:
        base, why = baseline_authorizes_deletion(text)
        rows.append({"text": text, "baseline": base, "baseline_reason": why,
                     "primary": answers["primary"][text], "second": answers["second"][text]})
    return rows


def vote(row: dict, key: str) -> bool | None:
    return row[key].get("decision") if "decision" in row[key] else None


def is_disputed(row: dict) -> bool:
    votes = [row["baseline"], vote(row, "primary"), vote(row, "second")]
    return any(v is None for v in votes) or len(set(votes)) > 1
