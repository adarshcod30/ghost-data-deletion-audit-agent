import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

from custom_cases import run_custom_cases  # noqa: E402


def test_every_custom_case_passes():
    failed = [r["name"] for r in run_custom_cases() if not r["passed"]]
    assert failed == []
