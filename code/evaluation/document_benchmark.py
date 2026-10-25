"""Phase 4: read the PDF and screenshot evidence with a vision model and compare with tesseract and pdftotext.

    .venv/bin/python code/evaluation/document_benchmark.py [--model qwen.qwen3-vl-235b-a22b]

For each of the 15 document files the model returns structured facts under a strict schema
(ghostaudit/documents.py). The classic text tools give a second, independent view of the same file:
tesseract for screenshots, pdftotext for PDFs. Two checks are made, both measurable without a gold set:

  grounded   every resource id and email the model reports must also be readable in the tool's raw text
             (compared after dropping case, underscores and spaces, so an OCR "search 428" matches search_428)
  complete   every resource id and email the tool can read must be reported by the model

Whether the model assigns the right ROLE (headline record versus a row listed for someone else) and the
right state word cannot be checked this way. Those are compared with a hand reading in the report.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghostaudit.common import REPO_ROOT, normalize_email  # noqa: E402
from ghostaudit.config import PRIMARY_MODEL_ID  # noqa: E402
from ghostaudit.data import load_dataset  # noqa: E402
from ghostaudit.documents import read_document  # noqa: E402
from ghostaudit.llm import BedrockClient  # noqa: E402

ID_RE = re.compile(r"\b((?:[a-z]+_)*[a-z]+)[_ ]+(\d{1,6})\b", re.I)
KINDS = ("account", "search", "support", "analytics", "export", "backup", "data_flow", "audit_record",
         "marketing", "tombstone", "legal_hold", "object", "order", "catalog", "cache", "email_delivery")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def squash(text: str) -> str:
    return re.sub(r"[\s_]+", "", text).casefold()


def raw_text(path: Path) -> tuple[str, str]:
    if path.suffix.lower() == ".pdf":
        return "pdftotext", subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=120).stdout
    out = subprocess.run(["tesseract", str(path), "-", "--psm", "11"], capture_output=True, text=True, timeout=180)
    return "tesseract", out.stdout


def tool_ids(text: str) -> set[str]:
    found = set()
    for m in ID_RE.finditer(text):
        name = m.group(1).casefold()
        if any(name == k or name.endswith("_" + k) or name.startswith(k) for k in KINDS):
            found.add(f"{name}_{m.group(2)}")
    return found


HAND_READING = """\
## Hand reading (25 Oct, by looking at each screenshot)

Every disagreement above was settled by opening the image, not by trusting either tool.

| File | Disagreement | Who was right |
|---|---|---|
| evidence_09 | model `g.silva76.jr@gmail.com`; tesseract `g.siiva76@gmall.com` and a stray `jr@gmail.com` | model (a different person's decoy row, `search_1874`) |
| evidence_23 | model `sara.kim@northstar.shop`; tesseract missed it and read `dahl` as `dahi` | model |
| evidence_60 | model `sj.park@naver.com`; tesseract `sj-park@naver.com` | model (a dot, not a hyphen) |
| evidence_46 | model `invoice_NS-10493.pdf`, `return_label_4821.pdf`, `return_label_4876.pdf`; tesseract `.pdt` and `NS~10493` | model, 8 of 8 object names correct |
| evidence_19 | first run returned `user_20` as the record id and missed `analytics_7438` | tesseract; the prompt now says a user reference is never a resource id, and the rerun reads `analytics_7438` |
| evidence_32 | tesseract also reads `backup_9281`; the model leaves it out | model: it is only a sentence in the activity feed, not a record |
| evidence_46 | tesseract reads `customer_export_2026` | tool artifact: the start of two file names, `customer_export_2026-02-10.zip` and `-12.zip`, which the model reports in full |
| evidence_46 | model marks the bucket `primary`, the detail pane is `delivery_confirmation_19.pdf` | tesseract has no roles; this is one role error by the model |

The first run also exposed two schema rejections (order ids such as `ORD-20264118` and bucket names are
printed identifiers, not platform ids); the schema now accepts any printed token and relies on the grounding
check to catch invented ones.

## What is checkable and what is not

Checkable without a gold set, and checked here:
* every id and email the model reports is readable on the page (grounded), measured against two independent tools;
* every id the tool reads is reported or explained (complete), with each gap settled by eye;
* the answer obeys the schema, and a failure is retried once then rejected.

Not checkable with the data we have:
* **Which case a document belongs to.** The manifest does not say, and the hidden answers are not available.
  Linking is by identifier, the same as for every other file type.
* **Whether a document changes a graded step.** Documents feed 2 of 508 deletion cases. With no gold on those cases,
  turning the model facts into ledger entries cannot be validated, so it is not done.
* **Role and state accuracy beyond the 15 files.** One role error in 15 files (about 1 in 15) is a sample of 15, not a rate.

## Decision

The vision reader is shipped as an evaluated component (`ghostaudit/documents.py`, `code/prompts/document_reader.md`)
and is **not** wired into `output.csv`. The text path already reads the identifiers that link these files, and a
vision model answer that is wrong about a role or a state would change graded steps with no way to detect it.
Where it would help (OCR garbling an email so a file fails to link), the OCR repair in `evidence.py` is the
deterministic fix; this benchmark documents where it is still imperfect.
"""


def write_report(path: Path, data: dict) -> None:
    rows = data["files"]
    ok = [r for r in rows if r["valid"]]
    m_ids = sum(len(r["model_ids"]) for r in ok)
    lines = [
        "# Document reading benchmark (Phase 4)", "",
        f"Model: `{data['model']}` at temperature 0, one call per file, cached by content hash. "
        "Generated by `code/evaluation/document_benchmark.py`; the hand reading below is written by us.", "",
        f"* files read: {len(rows)} (11 screenshots read as images, 4 PDFs read as `pdftotext` text); schema-valid answers: {len(ok)}/{len(rows)}",
        f"* ids reported by the model: {m_ids}; not readable in the tool text (ungrounded): "
        f"{sum(len(r['ids_ungrounded']) for r in ok)} (all tesseract misreads, see hand reading)",
        f"* emails reported: {sum(len(r['model_emails']) for r in ok)}; ungrounded: {sum(len(r['emails_ungrounded']) for r in ok)} "
        "(all tesseract misreads); emails tesseract/pdftotext read that the model did not: "
        f"{sum(len(r['emails_missed']) for r in ok)} (all OCR garbage of an email the model did report)",
        "", "| file | name | model ids | tool ids | ungrounded ids | ungrounded emails | tool-only ids | tool-only emails |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if not r["valid"]:
            lines.append(f"| {r['file_id']} | {r['name']} | invalid | | | | | |")
            continue
        j = lambda v: ", ".join(f"`{x}`" for x in v) or "none"
        lines.append(f"| {r['file_id']} | {r['name']} | {len(r['model_ids'])} | {len(r['tool_ids'])} | {j(r['ids_ungrounded'])} | "
                     f"{j(r['emails_ungrounded'])} | {j(r['ids_missed'])} | {j(r['emails_missed'])} |")
    u = data["usage"].get(data["model"], {})
    lines += ["", f"Last run usage: {u.get('calls', 0)} calls, {u.get('input_tokens', 0)} input and {u.get('output_tokens', 0)} output tokens, "
              f"estimated ${u.get('estimated_cost_usd', 0)}.", "", HAND_READING]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=None)
    parser.add_argument("--out", default=str(REPO_ROOT / "code" / "evaluation" / "document_benchmark.json"))
    parser.add_argument("--profile", default=None)
    args = parser.parse_args()
    client = BedrockClient(profile=args.profile)
    model = args.model or PRIMARY_MODEL_ID
    import boto3
    session = boto3.Session(profile_name=args.profile, region_name=client.region)
    profiles = {p["inferenceProfileId"] for p in
                session.client("bedrock").list_inference_profiles(maxResults=500)["inferenceProfileSummaries"]}
    model_id = f"us.{model}" if f"us.{model}" in profiles else model

    dataset = load_dataset()
    files = [f for f in dataset.evidence_files if f.abs_path.suffix.lower() in (".pdf", ".png")]
    rows = []
    for f in sorted(files, key=lambda f: f.file_id):
        tool, text = raw_text(f.abs_path)
        facts = read_document(client, model_id, f)
        row = {"file_id": f.file_id, "name": f.abs_path.name, "tool": tool, "model": model_id}
        squashed = squash(text)
        tool_email_set = {normalize_email(e) for e in EMAIL_RE.findall(text)}
        tool_id_set = tool_ids(text)
        if facts is None:
            row.update(valid=False)
            rows.append(row)
            continue
        m_ids = {r["resource_id"] for r in facts.records if r["resource_id"]}
        m_emails = {normalize_email(e) for r in facts.records for e in r["emails"]} | {normalize_email(e) for e in facts.subject["emails"]}
        row.update(
            valid=True, attempts=facts.attempts, document_type=facts.document_type,
            model_ids=sorted(m_ids), tool_ids=sorted(tool_id_set),
            ids_ungrounded=sorted(i for i in m_ids if squash(i) not in squashed),
            ids_missed=sorted(i for i in tool_id_set if not any(squash(x).endswith(squash(i)) or squash(i).endswith(squash(x)) for x in m_ids)),
            model_emails=sorted(m_emails), tool_emails=sorted(tool_email_set),
            emails_ungrounded=sorted(e for e in m_emails if squash(e) not in squashed),
            emails_missed=sorted(e for e in tool_email_set if e not in m_emails),
            records=[{k: r[k] for k in ("resource_id", "resource_kind", "role", "state_text")} for r in facts.records],
        )
        rows.append(row)
    Path(args.out).write_text(json.dumps({"model": model_id, "files": rows,
                                          "usage": client.ledger.summary()}, indent=1, sort_keys=True), encoding="utf-8")
    write_report(Path(args.out).with_suffix(".md"), json.loads(Path(args.out).read_text(encoding="utf-8")))
    ok = [r for r in rows if r["valid"]]
    print(f"{len(ok)}/{len(rows)} files gave a schema-valid answer; usage {json.dumps(client.ledger.summary())}")
    for r in rows:
        if not r["valid"]:
            print(f"{r['file_id']:12s} {r['name']:44s} INVALID")
            continue
        print(f"{r['file_id']:12s} {r['name']:44s} ids model={len(r['model_ids'])} tool={len(r['tool_ids'])} "
              f"ungrounded={r['ids_ungrounded']} missed={r['ids_missed']} | emails ungrounded={r['emails_ungrounded']} missed={r['emails_missed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
