"""Identity resolution: request email -> user -> every identifier valid at audit_at.

Model
-----
user_identities.csv is a snapshot of the *current* identity. user_audit_log.csv records
each change as (old_value -> new_value) at a time. For each (user, field) we rebuild a
timeline of spans:

    old_0 --(event 1)--> new_1 --(event 2)--> new_2 ... == snapshot value

A request is evaluated at its own `audit_at`, so a span only counts when it started at
or before that moment. Anything that took effect later is reported as `future` and is
never used as an alias (the spec: evidence created later must not change the answer).

Every alias carries the row that proves it (an audit_id, or the user_id of the snapshot
for fields that never changed), so later phases can cite or reject it.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Sequence

from .common import email_hash, normalize_email, normalize_phone
from .models import AuditEvent, DeletionRequest, Identity

STRONG = "strong"
WEAK = "weak"


@dataclass(frozen=True, slots=True)
class Span:
    """One value a field held, and the interval it held it."""

    value: str            # normalised
    raw: str
    valid_from: datetime | None   # None: held since before the first logged change
    valid_until: datetime | None  # None: still held at snapshot time
    source_kind: str      # identity_snapshot | audit_log
    source_id: str        # user_id (snapshot) or audit_id

    def known_at(self, moment: datetime) -> bool:
        return self.valid_from is None or self.valid_from <= moment

    def current_at(self, moment: datetime) -> bool:
        return self.known_at(moment) and (self.valid_until is None or self.valid_until > moment)


@dataclass(frozen=True, slots=True)
class Alias:
    kind: str          # user_id | email | email_hash | phone | name
    value: str         # normalised form used for matching
    raw: str           # as stored
    status: str        # current | historical
    strength: str      # strong | weak (a name alone must never match a record)
    source_kind: str   # identity_snapshot | audit_log | derived
    source_id: str
    valid_until: datetime | None


@dataclass(frozen=True, slots=True)
class Subject:
    case_id: str
    request_email: str
    audit_at: datetime
    resolution: str              # resolved | unresolved | ambiguous
    user_id: str | None
    match_kind: str | None       # current | historical (how the request email matched)
    aliases: tuple[Alias, ...]
    candidates: tuple[str, ...]
    reason: str
    anomalies: tuple[str, ...]

    @property
    def resolved(self) -> bool:
        return self.resolution == "resolved"

    def values(self, *kinds: str, status: str | None = None) -> frozenset[str]:
        return frozenset(
            a.value for a in self.aliases
            if a.kind in kinds and (status is None or a.status == status)
        )

    def strong_values(self) -> frozenset[str]:
        """Identifiers safe to match a record on (never the name)."""
        return frozenset(a.value for a in self.aliases if a.strength == STRONG)


_FIELDS = ("email", "email_hash", "phone")


def _normalise(field_name: str, value: str) -> str:
    if field_name == "email":
        return normalize_email(value)
    if field_name == "phone":
        return normalize_phone(value)
    return value.strip().casefold()  # email_hash


class IdentityResolver:
    """Resolve requests against the identity snapshot and the audit log."""

    def __init__(self, identities: Sequence[Identity], audit_log: Iterable[AuditEvent]) -> None:
        self._identities = {i.user_id: i for i in identities}
        events: dict[tuple[str, str], list[AuditEvent]] = defaultdict(list)
        for event in audit_log:
            events[(event.user_id, event.field_name)].append(event)
        for key in events:
            # audit_id breaks ties so ordering never depends on file order.
            events[key].sort(key=lambda e: (e.event_time, e.audit_id))
        self._events = events
        self.timeline_anomalies: dict[str, list[str]] = defaultdict(list)
        self._timelines: dict[tuple[str, str], tuple[Span, ...]] = {}
        # email value -> users that ever held it (candidate lookup only).
        self._email_holders: dict[str, set[str]] = defaultdict(set)
        for user_id, identity in self._identities.items():
            for field_name in _FIELDS:
                spans = self._build_timeline(identity, field_name)
                self._timelines[(user_id, field_name)] = spans
                if field_name == "email":
                    for span in spans:
                        self._email_holders[span.value].add(user_id)

    # ------------------------------------------------------------------ timelines
    def _snapshot_value(self, identity: Identity, field_name: str) -> str:
        return {"email": identity.email, "phone": identity.phone,
                "email_hash": identity.email_hash}[field_name]

    def _build_timeline(self, identity: Identity, field_name: str) -> tuple[Span, ...]:
        events = self._events.get((identity.user_id, field_name), [])
        snapshot = self._snapshot_value(identity, field_name)
        if not events:
            return (Span(_normalise(field_name, snapshot), snapshot, None, None,
                         "identity_snapshot", identity.user_id),)
        spans: list[Span] = [
            Span(_normalise(field_name, events[0].old_value), events[0].old_value,
                 None, events[0].event_time, "audit_log", events[0].audit_id)
        ]
        for index, event in enumerate(events):
            if index > 0 and _normalise(field_name, events[index - 1].new_value) != _normalise(
                field_name, event.old_value
            ):
                self.timeline_anomalies[identity.user_id].append(
                    f"{field_name} chain gap before {event.audit_id}"
                )
            until = events[index + 1].event_time if index + 1 < len(events) else None
            spans.append(Span(_normalise(field_name, event.new_value), event.new_value,
                              event.event_time, until, "audit_log", event.audit_id))
        if spans[-1].value != _normalise(field_name, snapshot):
            self.timeline_anomalies[identity.user_id].append(
                f"{field_name} last audit value differs from snapshot"
            )
        return tuple(spans)

    def timeline(self, user_id: str, field_name: str) -> tuple[Span, ...]:
        return self._timelines[(user_id, field_name)]

    # ------------------------------------------------------------------ resolution
    def _email_status(self, user_id: str, norm_email: str, moment: datetime) -> str | None:
        """current | historical | future | None for a user holding this email."""
        best: str | None = None
        for span in self._timelines[(user_id, "email")]:
            if span.value != norm_email:
                continue
            if span.current_at(moment):
                return "current"
            if span.known_at(moment):
                best = "historical"
            elif best is None:
                best = "future"
        return best

    def resolve(self, request: DeletionRequest) -> Subject:
        return self.resolve_email(request.case_id, request.email, request.audit_at)

    def resolve_email(self, case_id: str, email: str, audit_at: datetime) -> Subject:
        norm = normalize_email(email)
        holders = self._email_holders.get(norm, set())
        statuses = {u: self._email_status(u, norm, audit_at) for u in holders}
        current = sorted(u for u, s in statuses.items() if s == "current")
        historical = sorted(u for u, s in statuses.items() if s == "historical")
        future = sorted(u for u, s in statuses.items() if s == "future")

        def failed(resolution: str, reason: str, candidates: Sequence[str]) -> Subject:
            return Subject(case_id, email, audit_at, resolution, None, None, (),
                           tuple(candidates), reason, ())

        if len(current) == 1:
            user_id, kind = current[0], "current"
            notes = [f"email is also a past alias of {u}" for u in historical]
        elif not current and len(historical) == 1:
            user_id, kind, notes = historical[0], "historical", []
        elif current or historical:
            return failed("ambiguous", "email maps to more than one user at audit_at",
                          current + historical)
        elif future:
            return failed("unresolved", "email only became a user's identifier after audit_at", future)
        else:
            return failed("unresolved", "email is not held by any user", [])

        anomalies = tuple(notes) + tuple(self.timeline_anomalies.get(user_id, ()))
        return Subject(
            case_id=case_id, request_email=email, audit_at=audit_at, resolution="resolved",
            user_id=user_id, match_kind=kind,
            aliases=self._aliases_at(user_id, audit_at), candidates=(user_id,),
            reason=f"request email is a {kind} email of {user_id}", anomalies=anomalies,
        )

    # ------------------------------------------------------------------ aliases
    def _aliases_at(self, user_id: str, moment: datetime) -> tuple[Alias, ...]:
        identity = self._identities[user_id]
        aliases: list[Alias] = [
            Alias("user_id", user_id.casefold(), user_id, "current", STRONG,
                  "identity_snapshot", user_id, None),
            Alias("name", identity.name.strip().casefold(), identity.name, "current", WEAK,
                  "identity_snapshot", user_id, None),
        ]
        for field_name in ("email", "phone"):
            for span in self._timelines[(user_id, field_name)]:
                if not span.known_at(moment):
                    continue  # took effect after audit_at: never usable
                status = "current" if span.current_at(moment) else "historical"
                aliases.append(Alias(field_name, span.value, span.raw, status, STRONG,
                                     span.source_kind, span.source_id, span.valid_until))
                if field_name == "email":
                    aliases.append(Alias("email_hash", email_hash(span.raw), email_hash(span.raw),
                                         status, STRONG, "derived", span.source_id,
                                         span.valid_until))
        return tuple(aliases)

    def hash_anomalies(self) -> list[str]:
        """Cross-check derived hashes against the hashes stored in the snapshot and log."""
        problems: list[str] = []
        for user_id, identity in self._identities.items():
            if email_hash(identity.email) != identity.email_hash.casefold():
                problems.append(f"{user_id}: snapshot email_hash is not sha256(email)")
            logged = {s.value for s in self._timelines[(user_id, "email_hash")]}
            derived = {email_hash(s.raw) for s in self._timelines[(user_id, "email")]}
            if logged != derived:
                problems.append(f"{user_id}: logged email_hash values differ from derived")
        return problems
