"""Regression tests from the adversarial review. Each attack builds a tiny synthetic dataset (fictional example.test data)
and runs the real loader, indexer, pipeline and row verifier. See code/evaluation/adversarial_attacks.py."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

from adversarial_attacks import ATTACKS  # noqa: E402

# Documented open defects: reproduced, not fixed because the contract has no way to express a correct answer
# or the specification is ambiguous. They are listed in evaluation/adversarial_review.md.
OPEN = {"P3b"}


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda f: f.__name__)
def test_attack_is_not_silently_exploitable(attack):
    outcome = attack()
    if outcome["id"] in OPEN:
        pytest.skip("documented open defect")
    assert outcome["verdict"] in ("blocked", "detected"), (outcome["id"], outcome["actual"])


def test_real_false_complete_defects_stay_fixed():
    fixed = {"E3", "E3b", "E6", "E6b", "E6c", "I3b", "O3", "O3b", "O4", "O1"}
    verdicts = {f().get("id"): f()["verdict"] for f in ATTACKS if f.__name__.upper() in {x.upper() for x in fixed}}
    assert all(v in ("blocked", "detected") for v in verdicts.values()), verdicts
