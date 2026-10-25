"""Build code.zip from a clean tree: README, code and the two required reports. No dataset, caches, venv or keys.

    python3 code/tools/package_submission.py OUTPUT_ZIP

File order and timestamps are fixed, so the same tree gives the same archive. The build stops if a file looks
like it holds a credential.
"""
from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {"__pycache__", ".pytest_cache", ".venv", ".cache", "runs", "dataset", ".git", ".claude"}
SKIP_SUFFIXES = {".pyc", ".zip", ".csv", ".log"}
SECRET = re.compile(r"AKIA[0-9A-Z]{16}|aws_secret_access_key\s*=|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|sso_session|aws_session_token\s*=", re.I)


def files() -> list[Path]:
    wanted = [ROOT / "README.md", ROOT / "evaluation" / "evaluation_report.md", ROOT / "evaluation" / "usage_report.md"]
    for path in (ROOT / "code").rglob("*"):
        if path.is_file() and not (set(path.relative_to(ROOT).parts) & SKIP_DIRS) and path.suffix not in SKIP_SUFFIXES \
                and path.name != ".DS_Store":
            wanted.append(path)
    return sorted(set(wanted), key=lambda p: p.relative_to(ROOT).as_posix())


def main() -> int:
    out = Path(sys.argv[1])
    members = files()
    for path in members:
        if path.suffix in {".py", ".md", ".json", ".txt"} and SECRET.search(path.read_text(encoding="utf-8", errors="ignore")):
            # the detector's own pattern lives in this file
            if path.name != "package_submission.py":
                print(f"refusing: {path.relative_to(ROOT)} looks like it holds a credential", file=sys.stderr)
                return 1
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in members:
            info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), date_time=(2026, 10, 25, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    print(f"{out}: {len(members)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
