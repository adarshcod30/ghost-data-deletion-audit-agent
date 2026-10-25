"""One object that answers a request: resolve identity, build the ledger, plan the steps."""
from __future__ import annotations

from dataclasses import dataclass

from .models import Dataset
from .classifier import baseline_authorizes_deletion
from .evidence import EvidenceIndex, build_index
from .identity import IdentityResolver
from .ledger import CaseLedger, build_ledger, relevant_resources
from .workflow import WorkflowLinks, link_through_workflow
from .models import DeletionRequest
from .planner import plan_steps
from .policy import Policy


@dataclass(frozen=True, slots=True)
class Answer:
    case_id: str
    status: str
    steps: list
    ledger: CaseLedger | None
    note: str = ""  # why the case was treated as it was (classification reason, identity failure)


class Pipeline:
    def __init__(self, dataset: Dataset, index: EvidenceIndex | None = None) -> None:
        self.dataset = dataset
        self.index = index or build_index(dataset)
        self.resolver = IdentityResolver(dataset.identities, dataset.audit_log)
        self.policy = Policy(dataset.rules)
        # Anonymous resources are linked through the activity log across ALL cases at once, because
        # the match works by elimination (every case owns exactly one account deletion row).
        everyone = list(dataset.requests) + list(dataset.sample_requests)
        self._relevant = {r.case_id: relevant_resources(r, self.resolver.resolve(r), self.index)
                          for r in everyone if self.resolver.resolve(r).resolved}
        self.workflow: WorkflowLinks = link_through_workflow(everyone, dataset.activity, self.index, self._relevant)

    def answer(self, request: DeletionRequest) -> Answer:
        authorizes, why = baseline_authorizes_deletion(request.request_text)
        if not authorizes:
            return Answer(request.case_id, "NOT_APPLICABLE", [], None, why)
        subject = self.resolver.resolve(request)
        if not subject.resolved:
            return Answer(request.case_id, "INCOMPLETE", [], None, f"identity not resolved: {subject.reason}")
        extra = tuple(x for x in (self.workflow.account.get(request.case_id),) if x)
        ledger = build_ledger(request, subject, self.index, self.policy, extra)
        status, steps = plan_steps(ledger)
        return Answer(request.case_id, status, steps, ledger, why)
