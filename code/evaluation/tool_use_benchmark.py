"""Tool-use benchmark: can a model call tools correctly and branch on what a tool returns?

Scenario A: lookup_identity returns one match. The model must go straight to submit_result.
Scenario B: lookup_identity returns two candidates. The model must call inspect_candidate to
            see current emails, then submit the user whose current email equals the request.
Tool results are simulated here, so a pass depends only on the model.

Run from the repository root after model_benchmark.py:
    .venv/bin/python code/evaluation/tool_use_benchmark.py
"""
from __future__ import annotations

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghostaudit.common import REPO_ROOT  # noqa: E402
from ghostaudit.llm import BedrockClient, LLMUnavailable  # noqa: E402
import model_benchmark as mb  # noqa: E402

SYSTEM = (
    "You resolve which user a deletion request email belongs to. Always call lookup_identity "
    "first with the request email. If it returns exactly one match, call submit_result with that "
    "user_id. If it returns more than one candidate, call inspect_candidate for the candidates to "
    "see each current email, then call submit_result with the user whose current email equals the "
    "request email. Only use the tools. Do not answer in prose."
)
TOOLS = {"tools": [
    {"toolSpec": {"name": "lookup_identity", "description": "Find users that ever held an email.",
                  "inputSchema": {"json": {"type": "object", "properties": {"email": {"type": "string"}},
                                           "required": ["email"]}}}},
    {"toolSpec": {"name": "inspect_candidate", "description": "Show the current email of a user.",
                  "inputSchema": {"json": {"type": "object", "properties": {"user_id": {"type": "string"}},
                                           "required": ["user_id"]}}}},
    {"toolSpec": {"name": "submit_result", "description": "Submit the final user for this request.",
                  "inputSchema": {"json": {"type": "object", "properties": {
                      "user_id": {"type": "string"}, "reason": {"type": "string"}},
                      "required": ["user_id", "reason"]}}}},
]}

SCENARIOS = [
    {"kind": "A", "email": "mira.oduya@example.org", "matches": ["user_41"], "answer": "user_41",
     "current": {"user_41": "mira.oduya@example.org"}},
    {"kind": "A", "email": "tomas.vik@example.org", "matches": ["user_9"], "answer": "user_9",
     "current": {"user_9": "tomas.vik@example.org"}},
    {"kind": "A", "email": "hana.sato@example.org", "matches": ["user_312"], "answer": "user_312",
     "current": {"user_312": "hana.sato@example.org"}},
    {"kind": "B", "email": "lee.park@example.org", "matches": ["user_5", "user_6"], "answer": "user_6",
     "current": {"user_5": "l.park@example.net", "user_6": "lee.park@example.org"}},
    {"kind": "B", "email": "ana.cruz@example.org", "matches": ["user_20", "user_21"], "answer": "user_20",
     "current": {"user_20": "ana.cruz@example.org", "user_21": "acruz@example.com"}},
    {"kind": "B", "email": "ola.berg@example.org", "matches": ["user_88", "user_89"], "answer": "user_89",
     "current": {"user_88": "ola@example.net", "user_89": "ola.berg@example.org"}},
]


def run_scenario(client: BedrockClient, model_id: str, sc: dict) -> dict:
    messages = [{"role": "user", "content": [{"text": f"Request email: {sc['email']}"}]}]
    calls: list[str] = []
    submitted = None
    for _ in range(6):
        try:
            res = client.converse(model_id, system=SYSTEM, messages=messages, tool_config=TOOLS,
                                  max_tokens=500, purpose="tool_benchmark")
        except LLMUnavailable as exc:
            return {"ok": False, "why": f"error: {str(exc)[:60]}", "calls": calls}
        if not res.tool_calls:
            return {"ok": False, "why": "stopped without a tool call", "calls": calls}
        messages.append({"role": "assistant", "content": list(res.blocks)})
        results = []
        for call in res.tool_calls:
            name, args = call["name"], call.get("input") or {}
            calls.append(name)
            if name == "lookup_identity":
                payload = {"matches": sc["matches"]}
            elif name == "inspect_candidate":
                payload = {"user_id": args.get("user_id"), "current_email": sc["current"].get(args.get("user_id"), "unknown")}
            elif name == "submit_result":
                submitted = args.get("user_id")
                payload = {"status": "accepted"}
            else:
                payload = {"error": "unknown tool"}
            results.append({"toolResult": {"toolUseId": call["toolUseId"], "content": [{"json": payload}]}})
        messages.append({"role": "user", "content": results})
        if submitted is not None:
            break
    first_ok = bool(calls) and calls[0] == "lookup_identity"
    inspected = "inspect_candidate" in calls
    branch_ok = inspected if sc["kind"] == "B" else not inspected
    ok = first_ok and branch_ok and submitted == sc["answer"]
    why = "pass" if ok else f"calls={calls} submitted={submitted}"
    return {"ok": ok, "why": why, "calls": calls}


def main() -> int:
    client = BedrockClient(profile=None)
    ids = mb.resolve_model_ids(client)
    bench = json.loads((REPO_ROOT / "runs" / "model_benchmark.json").read_text(encoding="utf-8"))
    usable = [r["model"] for r in bench["results"]]
    rows = []
    def one(model: str) -> dict:
        outs = [run_scenario(client, ids[model], sc) for sc in SCENARIOS]
        return {"model": model, "passed": sum(o["ok"] for o in outs), "n": len(outs),
                "a": sum(o["ok"] for o, sc in zip(outs, SCENARIOS) if sc["kind"] == "A"),
                "b": sum(o["ok"] for o, sc in zip(outs, SCENARIOS) if sc["kind"] == "B"),
                "failures": [o["why"] for o in outs if not o["ok"]][:2]}
    with ThreadPoolExecutor(6) as pool:
        rows = list(pool.map(one, usable))
    for r in sorted(rows, key=lambda r: -r["passed"]):
        print(f"{r['model']:42s} {r['passed']}/{r['n']} (straight {r['a']}/3, branching {r['b']}/3) {r['failures']}")
    lines = ["# Tool-use benchmark", "",
             "Generated by `code/evaluation/tool_use_benchmark.py`. Simulated tools; a pass needs the right "
             "first call, the right branch and the right final user.", "",
             "| Model | Passed | Straight (A) | Branching (B) | First failures |", "|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: -r["passed"]):
        lines.append(f"| {r['model']} | {r['passed']}/{r['n']} | {r['a']}/3 | {r['b']}/3 | "
                     f"{'; '.join(r['failures']) or 'none'} |")
    (REPO_ROOT / "code" / "evaluation" / "tool_use_benchmark.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (REPO_ROOT / "runs" / "tool_use_benchmark.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
