"""One object that answers a request: resolve identity, build the ledger, plan the steps."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Dataset
from .evidence import EvidenceIndex, build_index
from .identity import IdentityResolver
from .ledger import CaseLedger, build_ledger
from .models import DeletionRequest
from .planner import plan_steps
from .policy import Policy


@dataclass(frozen=True, slots=True)
class Answer:
    case_id: str
    status: str
    steps: list
    ledger: CaseLedger | None


class Pipeline:
    def __init__(self, dataset: Dataset, index: EvidenceIndex | None = None) -> None:
        self.dataset = dataset
        self.index = index or build_index(dataset)
        self.resolver = IdentityResolver(dataset.identities, dataset.audit_log)
        self.policy = Policy(dataset.rules)

    def answer(self, request: DeletionRequest) -> Answer:
        subject = self.resolver.resolve(request)
        if not subject.resolved:
            return Answer(request.case_id, "INCOMPLETE", [], None)
        ledger = build_ledger(request, subject, self.index, self.policy)
        status, steps = plan_steps(ledger)
        return Answer(request.case_id, status, steps, ledger)
