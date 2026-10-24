import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghostaudit.data import load_dataset  # noqa: E402


@pytest.fixture(scope="session")
def dataset():
    return load_dataset()
