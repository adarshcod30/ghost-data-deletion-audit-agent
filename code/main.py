"""Command line entry point for the deletion-audit agent.

Usage (from the repository root):
    python3 code/main.py identities          # Phase 1 gate: resolve every request email
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ghostaudit.common import REPO_ROOT, case_sort_key  # noqa: E402
from ghostaudit.data import DatasetError, load_dataset  # noqa: E402
from ghostaudit.identity import IdentityResolver  # noqa: E402


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="main.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("identities", help="resolve every request email to a user (Phase 1 gate)")
    args = parser.parse_args(argv)
    return {"identities": cmd_identities}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
