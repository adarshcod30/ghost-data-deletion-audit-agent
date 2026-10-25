"""Amazon Bedrock client: Converse API, temperature 0, content-addressed cache, usage ledger.

Every call is recorded in a UsageLedger so evaluation/usage_report.md can be generated from
what actually ran. A cached response keeps the token counts of the original call and is
counted separately, so a cold re-run from the shipped cache reports the same usage.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .common import REPO_ROOT

DEFAULT_REGION = "us-east-1"
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "llm"

# Bedrock on-demand prices in USD per 1M tokens (input, output), standard tier, us-east-1.
# Source: AWS Price List API (service AmazonBedrockFoundationModels), queried 2026-10-25.
# For Qwen3-VL the API returns one rate for standard, flex and batch. A model that is not
# listed has no price on record and its cost is reported as unknown, never guessed.
PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "qwen.qwen3-vl-235b-a22b": (0.26, 1.33),
    "moonshotai.kimi-k2.5": (0.60, 3.00),
    "us.amazon.nova-pro-v1:0": (0.80, 3.20),
}

_RETRYABLE = {"ThrottlingException", "ModelTimeoutException", "ServiceUnavailableException",
              "InternalServerException", "ModelNotReadyException"}


class LLMUnavailable(Exception):
    """The provider cannot serve this request (no access, expired session, unknown model)."""


@dataclass(frozen=True, slots=True)
class LLMResult:
    text: str
    input_tokens: int
    output_tokens: int
    latency_s: float
    cached: bool
    model_id: str
    stop_reason: str
    tool_calls: tuple[dict, ...] = ()   # [{"toolUseId", "name", "input"}]
    blocks: tuple[dict, ...] = ()       # assistant text and toolUse blocks, to continue a loop


class UsageLedger:
    """Thread-safe per-model call and token totals, split by purpose."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: list[dict] = []

    def record(self, model_id: str, purpose: str, result: LLMResult) -> None:
        with self._lock:
            self._rows.append({"model": model_id, "purpose": purpose, "cached": result.cached,
                               "in": result.input_tokens, "out": result.output_tokens,
                               "latency": result.latency_s})

    def summary(self) -> dict[str, dict]:
        out: dict[str, dict] = defaultdict(lambda: {"calls": 0, "live_calls": 0, "cached_calls": 0,
                                                     "input_tokens": 0, "output_tokens": 0})
        with self._lock:
            for row in self._rows:
                entry = out[row["model"]]
                entry["calls"] += 1
                entry["cached_calls" if row["cached"] else "live_calls"] += 1
                entry["input_tokens"] += row["in"]
                entry["output_tokens"] += row["out"]
        for model, entry in out.items():
            entry["estimated_cost_usd"] = cost_usd(model, entry["input_tokens"], entry["output_tokens"])
        return dict(out)


def cost_usd(model_id: str, input_tokens: int, output_tokens: int) -> float | None:
    price = PRICES_PER_MTOK.get(model_id)
    if price is None:
        return None
    return round((input_tokens * price[0] + output_tokens * price[1]) / 1_000_000, 6)


class BedrockClient:
    def __init__(self, profile: str | None = None, region: str = DEFAULT_REGION,
                 cache_dir: Path | None = DEFAULT_CACHE_DIR, ledger: UsageLedger | None = None,
                 max_retries: int = 3) -> None:
        self.profile, self.region = profile, region
        self.cache_dir = cache_dir
        self.ledger = ledger or UsageLedger()
        self.max_retries = max_retries
        self._client = None
        self._lock = threading.Lock()

    def _runtime(self):
        with self._lock:
            if self._client is None:
                try:
                    import boto3  # imported lazily so deterministic mode needs no dependency
                    session = boto3.Session(profile_name=self.profile, region_name=self.region)
                    self._client = session.client("bedrock-runtime")
                except Exception as exc:  # missing package, bad profile, missing crt extra
                    raise LLMUnavailable(f"{type(exc).__name__}: {exc}") from exc
            return self._client

    @staticmethod
    def _key(model_id: str, system: str, user: str, max_tokens: int, temperature: float,
             messages: list | None = None, tool_config: dict | None = None) -> str:
        parts: list = [model_id, system, user, max_tokens, temperature]
        if messages is not None or tool_config is not None:
            parts += [messages, tool_config]
        def _bytes_as_digest(value):  # image bytes enter the key as their hash
            if isinstance(value, bytes):
                return "sha256:" + hashlib.sha256(value).hexdigest()
            raise TypeError(f"not serialisable: {type(value)}")
        return hashlib.sha256(json.dumps(parts, ensure_ascii=False, sort_keys=True, default=_bytes_as_digest).encode("utf-8")).hexdigest()

    def converse(self, model_id: str, user: str = "", system: str = "", max_tokens: int = 400,
                 temperature: float = 0.0, purpose: str = "", messages: list | None = None,
                 tool_config: dict | None = None) -> LLMResult:
        """One model turn. Pass `messages` (and `tool_config`) to continue a tool loop."""
        key = self._key(model_id, system, user, max_tokens, temperature, messages, tool_config)
        path = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if path is not None and path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            blocks = tuple(data.get("blocks", ()))
            # latency_s is the original live latency, kept so reports do not depend on cache state.
            result = LLMResult(data["text"], data["input_tokens"], data["output_tokens"],
                               data.get("latency_s", 0.0), True, model_id, data.get("stop_reason", ""),
                               tuple(b["toolUse"] for b in blocks if "toolUse" in b), blocks)
            self.ledger.record(model_id, purpose, result)
            return result

        request = {"modelId": model_id,
                   "messages": messages if messages is not None
                   else [{"role": "user", "content": [{"text": user}]}],
                   "inferenceConfig": {"maxTokens": max_tokens, "temperature": temperature}}
        if tool_config:
            request["toolConfig"] = tool_config
        if system:
            request["system"] = [{"text": system}]
        client = self._runtime()
        for attempt in range(self.max_retries + 1):
            started = time.time()
            try:
                response = client.converse(**request)
                break
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
                if code in _RETRYABLE and attempt < self.max_retries:
                    time.sleep(1.5 * (2 ** attempt))
                    continue
                raise LLMUnavailable(f"{code}: {str(exc)[:200]}") from exc
        raw = response["output"]["message"]["content"]
        # Keep only text and toolUse blocks: reasoning blocks are dropped from text and replay.
        blocks = tuple(b for b in raw if "text" in b or "toolUse" in b)
        text = "".join(b["text"] for b in blocks if "text" in b)
        usage = response.get("usage", {})
        result = LLMResult(text, usage.get("inputTokens", 0), usage.get("outputTokens", 0),
                           round(time.time() - started, 3), False, model_id,
                           response.get("stopReason", ""),
                           tuple(b["toolUse"] for b in blocks if "toolUse" in b), blocks)
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"text": result.text, "input_tokens": result.input_tokens,
                                        "output_tokens": result.output_tokens,
                                        "stop_reason": result.stop_reason, "model_id": model_id,
                                        "latency_s": result.latency_s, "blocks": list(blocks)}, ensure_ascii=False), encoding="utf-8")
        self.ledger.record(model_id, purpose, result)
        return result


def extract_json_object(text: str) -> dict | None:
    """First balanced JSON object in a model reply, or None. Tolerates fences and prose."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for index in range(start, len(text)):
            ch = text[index]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        value = json.loads(text[start:index + 1])
                    except json.JSONDecodeError:
                        break
                    return value if isinstance(value, dict) else None
        start = text.find("{", start + 1)
    return None
