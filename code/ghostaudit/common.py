"""Shared helpers: paths, timestamps and identifier normalisation.

Everything that decides whether two identifier strings are "the same" lives here so
the loader, the identity resolver and the evidence matcher agree by construction.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# code/ghostaudit/common.py -> repository root is two levels above the package.
REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp (trailing Z allowed) into an aware UTC datetime."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_email(value: str) -> str:
    """Canonical form used for every email comparison: NFKC, trimmed, case-folded."""
    return unicodedata.normalize("NFKC", value).strip().casefold()


def normalize_phone(value: str) -> str:
    """Digits only with a leading plus, so '+1 (202) 555-0103' == '+12025550103'.

    Returns '' when the value has no digits. National numbers without a country code
    are not guessed at; they simply normalise to their own digits.
    """
    digits = re.sub(r"\D", "", value)
    return f"+{digits}" if digits else ""


def email_hash(email: str) -> str:
    """SHA-256 of the normalised email, the scheme used by user_identities.csv."""
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def case_sort_key(case_id: str) -> tuple[str, int]:
    """Natural order for ids like case_33 < case_100.

    A plain string sort would put case_100 before case_33. The input file and the public sample
    answers are both in natural order, so this is the order we emit.
    """
    match = re.fullmatch(r"(.*?)(\d+)", case_id)
    if not match:
        return (case_id, -1)
    return (match.group(1), int(match.group(2)))
