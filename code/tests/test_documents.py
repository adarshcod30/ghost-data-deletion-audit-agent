"""The document reader's schema is the gate between a model answer and anything we use."""
from ghostaudit.documents import validate
from ghostaudit.llm import BedrockClient

GOOD = {"document_type": "console_screenshot",
        "subject": {"emails": ["a.b@example.org"], "phones": [], "user_ids": ["user_1"], "names": []},
        "records": [{"resource_id": "export_0007", "resource_kind": "export", "role": "primary", "state_text": "Ready",
                     "emails": ["a.b@example.org"], "user_ids": [], "quote": "export_0007"}]}


def test_valid_answer_passes():
    assert validate(GOOD) == []


def test_printed_ids_beyond_platform_ids_are_allowed():
    rec = dict(GOOD["records"][0], resource_id="ORD-20264118", resource_kind="order")
    assert validate({**GOOD, "records": [rec]}) == []


def test_null_resource_id_allowed():
    rec = dict(GOOD["records"][0], resource_id=None, resource_kind="other")
    assert validate({**GOOD, "records": [rec]}) == []


def test_extra_or_missing_keys_rejected():
    assert validate({**GOOD, "extra": 1})
    assert validate({"document_type": "other", "subject": GOOD["subject"]})
    assert validate(dict(GOOD, records=[dict(GOOD["records"][0], verdict="delete")]))


def test_bad_enum_email_and_id_rejected():
    assert validate({**GOOD, "document_type": "invoice"})
    assert validate(dict(GOOD, records=[dict(GOOD["records"][0], role="owner")]))
    assert validate(dict(GOOD, records=[dict(GOOD["records"][0], resource_kind="database")]))
    assert validate(dict(GOOD, records=[dict(GOOD["records"][0], emails=["not an email"])]))
    assert validate(dict(GOOD, records=[dict(GOOD["records"][0], resource_id="has spaces")]))
    assert validate("not an object") and validate(None)


def test_image_bytes_are_hashed_into_the_cache_key():
    msg = lambda b: [{"role": "user", "content": [{"image": {"format": "png", "source": {"bytes": b}}}]}]
    key = lambda b: BedrockClient._key("m", "s", "", 100, 0.0, msg(b), None)
    assert key(b"aaa") == key(b"aaa")
    assert key(b"aaa") != key(b"aab")
