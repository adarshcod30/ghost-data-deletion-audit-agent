import json

from ghostaudit.config import PRIMARY_MODEL_ID, SECOND_MODEL_ID
from ghostaudit.llm import BedrockClient, PRICES_PER_MTOK, cost_usd, extract_json_object


class FakeRuntime:
    """Stands in for bedrock-runtime so cache and ledger behaviour is tested offline."""

    def __init__(self, blocks):
        self.blocks, self.calls = blocks, 0

    def converse(self, **request):
        self.calls += 1
        return {"output": {"message": {"role": "assistant", "content": self.blocks}},
                "usage": {"inputTokens": 100, "outputTokens": 20}, "stopReason": "end_turn"}


def client_with(tmp_path, blocks):
    client = BedrockClient(cache_dir=tmp_path)
    client._client = FakeRuntime(blocks)
    return client


def test_second_call_is_served_from_cache_with_original_tokens(tmp_path):
    client = client_with(tmp_path, [{"text": "hello"}])
    first = client.converse("m", "hi", system="s")
    second = client.converse("m", "hi", system="s")
    assert (first.cached, second.cached) == (False, True)
    assert client._client.calls == 1
    assert second.text == "hello" and second.input_tokens == 100 and second.output_tokens == 20
    assert second.latency_s == first.latency_s  # original latency survives the cache
    summary = client.ledger.summary()["m"]
    assert summary["calls"] == 2 and summary["live_calls"] == 1 and summary["cached_calls"] == 1
    assert summary["input_tokens"] == 200 and summary["output_tokens"] == 40


def test_reasoning_blocks_are_dropped_and_tool_calls_survive_the_cache(tmp_path):
    blocks = [{"reasoningContent": {"reasoningText": {"text": "thinking"}}},
              {"toolUse": {"toolUseId": "t1", "name": "lookup_identity", "input": {"email": "a@b.c"}}}]
    client = client_with(tmp_path, blocks)
    live = client.converse("m", "x", tool_config={"tools": []})
    cached = client.converse("m", "x", tool_config={"tools": []})
    assert live.tool_calls == cached.tool_calls
    assert cached.tool_calls[0]["name"] == "lookup_identity"
    assert all("reasoningContent" not in b for b in cached.blocks)


def test_cache_key_changes_with_prompt_and_tools(tmp_path):
    client = client_with(tmp_path, [{"text": "ok"}])
    client.converse("m", "a")
    client.converse("m", "b")
    client.converse("m", "a", tool_config={"tools": [1]})
    assert client._client.calls == 3


def test_cost_is_known_only_for_priced_models():
    assert cost_usd(PRIMARY_MODEL_ID, 1_000_000, 1_000_000) == 0.26 + 1.33
    assert cost_usd("some.unpriced-model", 10, 10) is None


def test_chosen_models_are_priced_and_distinct():
    assert PRIMARY_MODEL_ID in PRICES_PER_MTOK and SECOND_MODEL_ID in PRICES_PER_MTOK
    assert PRIMARY_MODEL_ID != SECOND_MODEL_ID


def test_extract_json_object_handles_fences_escapes_and_prose():
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json_object('x {"a": "q\\"}"} y') == {"a": 'q"}'}
    assert extract_json_object('noise {"a": {"b": 2}} more') == {"a": {"b": 2}}
    assert extract_json_object("no json here") is None
    assert extract_json_object("[1, 2]") is None
