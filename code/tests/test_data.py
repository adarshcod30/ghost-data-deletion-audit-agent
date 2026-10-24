import shutil
from pathlib import Path

import pytest

from ghostaudit.common import DATASET_DIR, case_sort_key, normalize_phone, parse_ts
from ghostaudit.data import DatasetError, load_dataset


def test_real_dataset_shapes(dataset):
    assert len(dataset.requests) == 518
    assert len(dataset.sample_requests) == 32
    assert len(dataset.identities) == 850
    assert len(dataset.audit_log) == 306
    assert len(dataset.activity) == 4011
    assert len(dataset.rules) == 15
    assert len(dataset.evidence_files) == 94
    assert len(dataset.sample_output) == 32


def test_every_evidence_file_resolves_on_disk(dataset):
    assert all(item.abs_path.is_file() for item in dataset.evidence_files)


def test_timestamps_are_aware_utc(dataset):
    for request in dataset.requests:
        assert request.audit_at.tzinfo is not None
        assert request.requested_at <= request.audit_at


def test_case_ids_follow_natural_order(dataset):
    ids = [r.case_id for r in dataset.requests]
    assert ids == sorted(ids, key=case_sort_key)
    # A plain string sort would differ, which is why the output order is explicit.
    assert ids != sorted(ids)
    assert case_sort_key("case_33") < case_sort_key("case_100")


def test_parse_ts_handles_z_and_offsets():
    assert parse_ts("2026-09-03T11:30:00Z") == parse_ts("2026-09-03T17:00:00+05:30")


def test_phone_normalisation():
    assert normalize_phone("+1 (202) 555-0103") == "+12025550103"
    assert normalize_phone("+212 6 48 27 15 93") == "+212648271593"
    assert normalize_phone("n/a") == ""


@pytest.fixture()
def dataset_copy(tmp_path: Path) -> Path:
    """A writable copy of the CSV files, with the evidence directory symlinked."""
    target = tmp_path / "dataset"
    target.mkdir()
    for csv_file in DATASET_DIR.glob("*.csv"):
        shutil.copy(csv_file, target / csv_file.name)
    (target / "evidence").symlink_to(DATASET_DIR / "evidence")
    return target


def test_copy_loads_cleanly(dataset_copy):
    assert len(load_dataset(dataset_copy).requests) == 518


def test_bad_header_is_rejected(dataset_copy):
    path = dataset_copy / "user_identities.csv"
    path.write_text(path.read_text(encoding="utf-8").replace("email_hash", "hash", 1), encoding="utf-8")
    with pytest.raises(DatasetError, match="user_identities.csv: header"):
        load_dataset(dataset_copy)


def test_duplicate_ids_and_unknown_users_are_rejected(dataset_copy):
    path = dataset_copy / "user_audit_log.csv"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines.append(lines[1])  # duplicate audit_id
    lines.append("audit_9999,user_NOPE,2026-01-01T00:00:00Z,phone,a,b")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(DatasetError) as info:
        load_dataset(dataset_copy)
    text = str(info.value)
    assert "duplicate audit_id" in text
    assert "unknown user user_NOPE" in text


def test_missing_evidence_file_is_rejected(dataset_copy):
    path = dataset_copy / "evidence_files.csv"
    path.write_text(path.read_text(encoding="utf-8").replace("evidence/logs/", "evidence/gone/", 1),
                    encoding="utf-8")
    with pytest.raises(DatasetError, match="missing file"):
        load_dataset(dataset_copy)
