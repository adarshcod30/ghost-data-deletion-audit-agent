"""Policy: what treatment each kind of resource requires, read from deletion_rules.csv.

The mapping from a resource id prefix to a data category is domain knowledge about this
platform (a search_ id is a search index entry). It is validated against the category names in
the rules file and against the record_type values stated inside the evidence.
"""
from __future__ import annotations

from .models import Rule

PREFIX_CATEGORY: dict[str, str] = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "cache": "CACHE_ENTRY",
    "support": "SUPPORT_MESSAGE",
    "object": "SUPPORT_ATTACHMENT",
    "analytics": "ANALYTICS_PROFILE",
    "telemetry": "PRODUCT_TELEMETRY",
    "export": "USER_EXPORT",
    "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "backup": "BACKUP_ARCHIVE",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "data_flow": "DATA_FLOW",  # a process, not a stored record: it is disabled, never deleted
}


class Policy:
    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self._action = {r.data_category: r.required_action for r in rules}

    def category(self, prefix: str, subtype: str = "") -> str | None:
        if prefix == "support" and subtype == "attachment":
            return "SUPPORT_ATTACHMENT"
        if prefix in ("analytics", "telemetry") and subtype == "marketing":
            return "MARKETING_PROFILE"  # an opt-in contact kept in the analytics platform
        return PREFIX_CATEGORY.get(prefix)

    def action(self, prefix: str, subtype: str = "") -> str | None:
        """DELETE, REDACT, ANONYMIZE or RETAIN; FLOW for data flows; None for an unknown type."""
        category = self.category(prefix, subtype)
        if category == "DATA_FLOW":
            return "FLOW"
        return self._action.get(category) if category else None
