"""Regression tests from the security and reliability review (synthetic data only)."""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

from adversarial_world import World  # noqa: E402
from ghostaudit.data import DatasetError  # noqa: E402

CODE = Path(__file__).resolve().parents[1]


def test_evidence_path_cannot_leave_the_dataset_folder():
    w = World()
    w.files.append(("evidence_77", "../outside.json", "test_export", "2026-06-01T00:00:00Z"))
    (w.root.parent / "outside.json").write_text("{}", encoding="utf-8")
    try:
        with pytest.raises(DatasetError, match="leaves the dataset folder"):
            w.build()
    finally:
        (w.root.parent / "outside.json").unlink(missing_ok=True)
        w.close()


def test_run_leaves_no_partial_file_and_writes_whole_output(tmp_path):
    target = tmp_path / "out.csv"
    done = subprocess.run([sys.executable, str(CODE / "main.py"), "run", "--no-models", "--output", str(target)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr[-300:]
    assert target.is_file() and not (tmp_path / "out.csv.partial").exists()
    assert len(target.read_text(encoding="utf-8").splitlines()) == 519


def test_run_output_names_no_personal_data():
    done = subprocess.run([sys.executable, str(CODE / "main.py"), "run", "--no-models", "--output", "/dev/null"], capture_output=True, text=True)
    assert "@" not in done.stdout + done.stderr


def test_no_shell_or_unsafe_deserialisation_in_the_package():
    text = "".join(p.read_text(encoding="utf-8") for p in (CODE / "ghostaudit").glob("*.py"))
    for needle in ("shell=True", "pickle", "yaml.load", "os.system", "eval("):
        assert needle not in text, needle
