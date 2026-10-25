"""Command line entry point for the deletion-audit agent.

Usage (from the repository root):
    python3 code/main.py identities          # Phase 1 gate: resolve every request email
    python3 code/main.py index               # Phase 2: index every evidence file, refuse a partial index
    python3 code/main.py run                 # answer every request, verify the rows, write output.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghostaudit.common import REPO_ROOT, case_sort_key  # noqa: E402
from ghostaudit.data import DatasetError, load_dataset  # noqa: E402
from ghostaudit.evidence import EvidenceIndexError, build_index  # noqa: E402
from ghostaudit.identity import IdentityResolver  # noqa: E402
from ghostaudit.pipeline import Pipeline  # noqa: E402
from ghostaudit.verify import serialize_steps, verify_row  # noqa: E402


def cmd_identities(_: argparse.Namespace) -> int:
    try:
        dataset = load_dataset()
    except DatasetError as exc:
        print(exc, file=sys.stderr)
        return 2

    resolver = IdentityResolver(dataset.identities, dataset.audit_log)
    problems = resolver.hash_anomalies()
    out_dir = REPO_ROOT / "runs"
    out_dir.mkdir(exist_ok=True)

    total_bad = 0
    for label, requests in (("requests", dataset.requests), ("samples", dataset.sample_requests)):
        subjects = [resolver.resolve(r) for r in sorted(requests, key=lambda r: case_sort_key(r.case_id))]
        kinds = Counter((s.resolution, s.match_kind) for s in subjects)
        anomalies = sum(1 for s in subjects if s.anomalies)
        unresolved = [s.case_id for s in subjects if not s.resolved]
        total_bad += len(unresolved)
        print(f"{label}: {len(subjects)} cases, "
              + ", ".join(f"{res}/{kind}={n}" for (res, kind), n in sorted(kinds.items(), key=str))
              + f", with anomalies={anomalies}")
        if unresolved:
            print(f"  UNRESOLVED: {unresolved[:10]}")
        if label == "requests":
            with (out_dir / "identity_resolution.csv").open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["case_id", "resolution", "user_id", "match_kind", "alias_count", "anomalies"])
                for s in subjects:
                    writer.writerow([s.case_id, s.resolution, s.user_id, s.match_kind,
                                     len(s.aliases), "; ".join(s.anomalies)])
    if problems:
        print(f"hash cross-check problems: {len(problems)}", file=sys.stderr)
        for line in problems[:10]:
            print("  " + line, file=sys.stderr)
        return 1
    print("hash cross-check: snapshot and audit-log hashes agree with sha256(email) for every user")
    return 1 if total_bad else 0


def cmd_index(_: argparse.Namespace) -> int:
    try:
        dataset = load_dataset()
        index = build_index(dataset)
    except (DatasetError, EvidenceIndexError) as exc:
        print(exc, file=sys.stderr)
        return 2
    kinds = Counter(r.kind for r in index.records)
    summary = {
        "evidence_files": len(dataset.evidence_files), "files_indexed": len(index.files),
        "records": len(index.records), "records_by_kind": dict(sorted(kinds.items())),
        "scopes": len(index.scopes), "distinct_resource_ids": len(index._by_resource),
        "distinct_identifiers": len(index._by_identifier),
        "prefix_system": dict(sorted(index.prefix_system.items())),
        "prefix_conflicts": {k: sorted(v) for k, v in index.prefix_conflicts.items()},
    }
    out_dir = REPO_ROOT / "runs"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "evidence_index_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"indexed {summary['files_indexed']}/{summary['evidence_files']} evidence files into "
          f"{summary['records']} records and {summary['scopes']} scopes")
    print("records by kind: " + ", ".join(f"{k}={v}" for k, v in summary["records_by_kind"].items()))
    print(f"prefix to system conflicts: {len(index.prefix_conflicts)}")
    return 1 if index.prefix_conflicts else 0


def cmd_run(_: argparse.Namespace) -> int:
    """Answer every request, verify every row against the contract, then write output.csv."""
    try:
        dataset = load_dataset()
        pipeline = Pipeline(dataset)
    except (DatasetError, EvidenceIndexError) as exc:
        print(exc, file=sys.stderr)
        return 2
    evidence_times = {f.file_id: f.captured_at for f in dataset.evidence_files}
    evidence_times.update({a.activity_id: a.event_time for a in dataset.activity})
    evidence_times.update({e.audit_id: e.event_time for e in dataset.audit_log})
    rows, problems, audit, unidentified_cases = [], [], [], []
    for request in sorted(dataset.requests, key=lambda r: case_sort_key(r.case_id)):
        answer = pipeline.answer(request)
        unidentified = answer.status == "COMPLETE" and not answer.steps and answer.note.startswith("no resource")
        if unidentified:
            unidentified_cases.append(request.case_id)
        problems += verify_row(request.case_id, answer.status, answer.steps, request.audit_at, evidence_times,
                               allow_unidentified=unidentified)
        rows.append((request.case_id, answer.status, serialize_steps(answer.steps)))
        audit.append({"case_id": request.case_id, "status": answer.status, "note": answer.note,
                      "user_id": answer.ledger.subject.user_id if answer.ledger else None,
                      "entries": [{"resource_id": e.resource_id, "system_id": e.system_id, "state": e.state,
                                   "evidence_id": e.evidence_id, "inferred": e.inferred}
                                  for e in (answer.ledger.entries if answer.ledger else ())],
                      "workflow_account": pipeline.workflow.account.get(request.case_id)})
    out_dir = REPO_ROOT / "runs"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "audit.jsonl").write_text("\n".join(json.dumps(a, ensure_ascii=False, sort_keys=True) for a in audit) + "\n", encoding="utf-8")
    if problems:
        print(f"{len(problems)} contract problems; output.csv not written", file=sys.stderr)
        for line in problems[:20]:
            print("  " + line, file=sys.stderr)
        return 1
    with (REPO_ROOT / "output.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        writer.writerows(rows)
    counts = Counter(status for _, status, _ in rows)
    steps = sum(len(json.loads(blob)) for _, _, blob in rows)
    print(f"wrote {len(rows)} rows to output.csv: {dict(sorted(counts.items()))}, {steps} steps, 0 contract problems")
    print(f"workflow account links: {pipeline.workflow.stats}")
    print(f"unidentified cases (COMPLETE, no steps): {len(unidentified_cases)} {unidentified_cases}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="main.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("identities", help="resolve every request email to a user (Phase 1 gate)")
    sub.add_parser("index", help="index every evidence file (Phase 2)")
    sub.add_parser("run", help="answer every request and write output.csv (verified)")
    args = parser.parse_args(argv)
    return {"identities": cmd_identities, "index": cmd_index, "run": cmd_run}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
