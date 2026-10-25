"""The README and the generated reports must say what the code and the data say."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CODE = ROOT / "code"
README = (ROOT / "README.md").read_text(encoding="utf-8") if (ROOT / "README.md").is_file() else ""
EVAL = CODE / "evaluation"


def markdown_files():
    return [p for p in [ROOT / "README.md", *EVAL.glob("*.md"), *(CODE / "prompts").glob("*.md")] if p.is_file()]


def test_no_em_or_en_dashes_in_markdown():
    bad = [p.name for p in markdown_files() if re.search("[–—]", p.read_text(encoding="utf-8"))]
    assert bad == []


def test_readme_model_ids_match_config():
    from ghostaudit.config import PRIMARY_MODEL_ID, SECOND_MODEL_ID
    assert PRIMARY_MODEL_ID in README and SECOND_MODEL_ID in README


def test_readme_commands_exist_in_main():
    main = (CODE / "main.py").read_text(encoding="utf-8")
    for command in re.findall(r"python3 code/main\.py (\w+)", README):
        assert f'"{command}"' in main, command
    for flag in re.findall(r"(--[a-z-]+)", " ".join(re.findall(r"`python3 code/main\.py [^`]*`", README))):
        assert flag in main, flag


def test_readme_files_exist():
    for path in re.findall(r"`(code/[\w./-]+\.(?:py|md))`", README):
        assert (ROOT / path).is_file(), path


def test_readme_sample_numbers_match_the_evaluation_report():
    report = (EVAL / "evaluation_report.md").read_text(encoding="utf-8")
    for token in ("32/32", "20/32", "0.9275", "0.9624"):
        assert token in README and token in report, token


def test_readme_usage_numbers_match_the_usage_report():
    report = (EVAL / "usage_report.md").read_text(encoding="utf-8")
    for token in ("750", "467047", "26555", "0.2586"):
        assert token in README and token in report, token


def test_one_determinism_contract_and_no_contradiction():
    text = README.lower() + "".join(p.read_text(encoding="utf-8").lower() for p in EVAL.glob("*.md"))
    assert "not deterministic" not in text and "nondeterministic" not in text and "non-deterministic" not in text
    assert README.count("## Determinism Contract") == 1


def test_required_reports_exist_and_have_required_sections():
    report = (EVAL / "evaluation_report.md").read_text(encoding="utf-8")
    for heading in ("accuracy", "Sequence accuracy", "Custom evaluation cases", "Failures found and improvements made"):
        assert heading in report, heading
    usage = (EVAL / "usage_report.md").read_text(encoding="utf-8")
    for needle in ("Input tokens", "Output tokens", "Average tokens per request", "Estimated cost per request", "Total"):
        assert needle in usage, needle


def test_usage_report_matches_usage_json_when_present():
    path = ROOT / "runs" / "usage.json"
    if not path.is_file():
        pytest.skip("no run recorded in this checkout")
    usage = json.loads(path.read_text(encoding="utf-8"))
    report = (EVAL / "usage_report.md").read_text(encoding="utf-8")
    for model, m in usage["models"].items():
        assert model in report and str(m["input_tokens"]) in report


def test_top_level_evaluation_copies_are_identical():
    top = ROOT / "evaluation"
    if not top.is_dir():
        pytest.skip("no top-level evaluation folder in this checkout")
    for name in ("evaluation_report.md", "usage_report.md"):
        assert (top / name).read_text(encoding="utf-8") == (EVAL / name).read_text(encoding="utf-8"), name
