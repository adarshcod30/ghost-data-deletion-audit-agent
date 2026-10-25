"""Does this request authorise deletion? Deterministic baseline.

The default is "yes": every request in the data that is not a clearly different kind of request is a
deletion request, and the non-English ones (Portuguese, Korean, Japanese, Spanish, French) contain
no English deletion word at all, so a keyword filter for deletion would misclassify them. The
baseline therefore looks for explicit signs of a *different* request instead: access or a copy of the
data, export or download, correcting or changing a detail, login help, marketing opt-out only,
invoices, or an instruction to keep or not delete the account.

A model reads every request as well (see agent.py); this baseline is what runs with no provider and
what the model is cross-checked against.
"""
from __future__ import annotations

import re

NEGATED_DELETION = re.compile(
    r"(do\s*n[o']?t|don'?t|dont|never|without|not)\s+(\w+\s+){0,4}(delet\w*|remov\w*|clos\w*|eras\w*|wip\w*|cancel\w*)"
    r"|(keep|leave|retain)\s+(my|the|this)\s+(\w+\s+){0,2}(account|profile|records?|history|data|orders?|purchase)"
    r"|(keep|leave)\s+(the\s+)?account\s+(as it is|active|open)"
    r"|(still|continue to)\s+(use|want)", re.I)
OTHER_REQUEST = re.compile(
    r"\b(copy of|download|portable format|export|send me (a copy|everything|my data)|what (data|information) (do you|you) (hold|have))\b"
    r"|\b(reset|resetting)\b.{0,20}\b(password|login)\b|\bcan'?t (access|log ?in|sign ?in)\b|\blocked out\b"
    r"|\b(misspelled|typo|incorrect|out of date|outdated)\b|\b(replace|update|change|correct)\b.{0,40}\b(name|email address|e-?mail|phone|mobile|number|address|surname)\b"
    r"|\b(marketing|promotional|newsletter|sms promotions?)\b.{0,40}\b(only|unsubscribe|stop|opt)\b|\bunsubscribe\b|\bopt[- ]?out\b|\bremove me from (the )?marketing\b"
    r"|\b(invoices?|receipts?)\b", re.I)
DELETION_WORDS = re.compile(r"\b(delet\w*|erase\w*|erasure|remov\w*|clos\w*|wipe\w*|forget)\b", re.I)


def baseline_authorizes_deletion(text: str) -> tuple[bool, str]:
    """(authorises deletion, reason). Defaults to True; flips only on an explicit other request."""
    if NEGATED_DELETION.search(text):
        return False, "asks to keep or not delete the account"
    other = OTHER_REQUEST.search(text)
    if other:
        # An explicit deletion of the whole account alongside e.g. "invoices" still counts as deletion.
        if DELETION_WORDS.search(text) and re.search(r"\b(account|profile|personal data)\b", text, re.I) \
                and not re.search(r"\b(only|just)\b", text, re.I) and not NEGATED_DELETION.search(text) \
                and not re.search(r"\b(update|change|correct|replace|fix)\b", text, re.I):
            return True, "deletion request that also mentions " + other.group(0)
        return False, f"different request ({other.group(0).strip()})"
    return True, "no sign of a different request"
