"""The resolved case ledger: every resource that belongs to the subject, with its state at audit_at.

Everything downstream (status, findings, remediation, verification, order) is a function of
this ledger. Nothing is written to a step that is not a ledger entry.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .common import case_sort_key
from .evidence import EvidenceIndex, resource_prefix
from .identity import Subject
from .linking import RETAINED_PREFIXES, admissible, link_resources
from .models import DeletionRequest
from .policy import Policy
from .state import Observation, interpret


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    resource_id: str
    system_id: str
    prefix: str
    action: str | None            # DELETE | REDACT | ANONYMIZE | RETAIN | FLOW | None
    state: str                    # state at audit_at, or UNKNOWN
    evidence_id: str              # file that proves that state ("" when none)
    observation: Observation | None
    inferred: bool = False        # True when no observation exists and the state is assumed


@dataclass(frozen=True, slots=True)
class CaseLedger:
    case_id: str
    subject: Subject
    entries: tuple[LedgerEntry, ...] = field(default_factory=tuple)
    dropped: tuple[tuple[str, str], ...] = ()   # (resource_id, reason): linked to the subject but left out of the ledger


def observations_for(resource_id: str, index: EvidenceIndex, audit_at=None) -> list[Observation]:
    out: list[Observation] = []
    for rec in index.for_resource(resource_id):
        if rec.kind == "log_trace":
            continue  # traces link resources; each line states its own outcome
        if audit_at is not None and not admissible(rec, audit_at):
            continue
        obs = interpret(rec, resource_id)
        if obs is not None:
            out.append(obs)
    return out


def _recency(o: Observation) -> tuple:
    """Latest wins. On an exact timestamp tie the unsafe reading (data still there) wins, never the file number."""
    return (o.time, o.state in NON_FINAL_STATES, case_sort_key(o.file_id))


def choose_observation(observations: list[Observation], request: DeletionRequest) -> Observation | None:
    """The state at audit_at.

    Prefer the latest observation made at or before audit_at in a file that was itself captured by
    then, because only such a file may be cited. If every observation sits in a later export (the
    log lines are dated before audit_at but the file was captured after), use the latest of those
    for the state and leave the citation empty. A sighting dated after audit_at is never used.
    """
    citable = [o for o in observations if o.time <= request.audit_at and o.file_captured_at <= request.audit_at]
    if citable:
        return max(citable, key=_recency)
    dated = [o for o in observations if o.time <= request.audit_at]
    if dated:
        return max(dated, key=_recency)
    retained = [o for o in observations if resource_prefix(o.resource_id) in RETAINED_PREFIXES]
    if retained:  # append-only records: seen in a later snapshot, so they existed
        return min(retained, key=lambda o: (o.time, case_sort_key(o.file_id)))
    return None


def find_citation(resource_id: str, state: str, system: str, request: DeletionRequest, index: EvidenceIndex,
                  observations: list[Observation]) -> str:
    """The best file that may be cited for a resource in a given state at audit_at.

    In order: an observation that shows this state in a file captured by then; any record captured by
    then that names the resource (an unreadable mention still shows the resource was in that file);
    for an absent record, a snapshot that covers the system and does not contain it. Empty when none.
    """
    same = [o for o in observations if o.state == state and o.file_captured_at <= request.audit_at
            and o.time <= request.audit_at]
    if same:
        return max(same, key=lambda o: (o.time, case_sort_key(o.file_id))).file_id
    if state != "ABSENT":
        named = [r for r in index.for_resource(resource_id) if r.captured_at <= request.audit_at
                 and r.kind not in ("log_trace",)]
        if named:
            return max(named, key=lambda r: (r.record_time or r.captured_at, case_sort_key(r.file_id))).file_id
        return ""
    return absence_proof(system, resource_id, request, index)


def absence_proof(system: str, resource_id: str, request: DeletionRequest, index: EvidenceIndex) -> str:
    """A file that covers `system` at or before audit_at and does not contain the resource."""
    mentioned = {r.file_id for r in index.for_resource(resource_id)}
    best = None
    for scope in index.scopes:
        if scope.system != system or scope.file_id in mentioned or scope.snapshot_at > request.audit_at:
            continue
        if index.file_times.get(scope.file_id, request.audit_at) > request.audit_at:
            continue  # only a file captured by audit_at may be cited, whatever its internal snapshot time
        if best is None or (scope.snapshot_at, case_sort_key(scope.file_id)) > (best.snapshot_at, case_sort_key(best.file_id)):
            best = scope
    return best.file_id if best else ""


NON_FINAL_STATES = {"PRESENT", "IDENTIFIABLE", "ACTIVE"}


def relevant_resources(request: DeletionRequest, subject: Subject, index: EvidenceIndex) -> list[str]:
    """Resources that belong to this case. Which resources belong to a case does not depend on time (a
    user's account id is the same on every date); their state and citations are bounded by audit_at.

    A resource linked only by evidence dated before the request counts only if that evidence shows
    data that still exists (present, identifiable or active). A lookup that came back empty months
    earlier says nothing about this request.
    """
    keep: list[str] = []
    for resource_id, records in link_resources(subject, index).items():
        after = [r for r in records if (r.record_time or r.captured_at) >= request.requested_at]
        if not after:
            states = [o.state for r in records if (o := interpret(r, resource_id)) is not None]
            if not any(state in NON_FINAL_STATES for state in states):
                continue
        keep.append(resource_id)
    return sorted(keep, key=case_sort_key)


def build_ledger(request: DeletionRequest, subject: Subject, index: EvidenceIndex, policy: Policy,
                 workflow_resources: tuple[str, ...] = ()) -> CaseLedger:
    """`workflow_resources` are anonymous resources tied to this case through the activity log
    (see workflow.py); they are added to the identifier-linked ones."""
    entries: list[LedgerEntry] = []
    dropped: list[tuple[str, str]] = []
    resource_ids = sorted(set(relevant_resources(request, subject, index)) | set(workflow_resources), key=case_sort_key)
    for resource_id in resource_ids:
        prefix = resource_prefix(resource_id)
        system = index.system_of(resource_id)
        if system is None:
            dropped.append((resource_id, "no system known for this id prefix"))
            continue
        found = observations_for(resource_id, index, request.audit_at)
        obs = choose_observation(found, request)
        if obs is None:
            if prefix == "account":
                # Linked by another record (a search document names its source account) but no live
                # profile was ever observed: the account is gone, proved by a snapshot that covers
                # the account service and does not contain it.
                entries.append(LedgerEntry(resource_id, system, prefix, policy.action(prefix), "ABSENT",
                                           absence_proof(system, resource_id, request, index), None, inferred=True))
            else:
                dropped.append((resource_id, "linked, but no admissible record states its condition"))
            continue
        action = policy.action(prefix, obs.subtype)
        if action is None:
            dropped.append((resource_id, "no policy action for this resource type"))
            continue
        cited = obs.file_id if obs.file_captured_at <= request.audit_at else ""
        if not cited:
            cited = find_citation(resource_id, obs.state, system, request, index, found)
        entries.append(LedgerEntry(resource_id, system, prefix, action, obs.state, cited, obs))
    return CaseLedger(request.case_id, subject, tuple(entries), tuple(dropped))
