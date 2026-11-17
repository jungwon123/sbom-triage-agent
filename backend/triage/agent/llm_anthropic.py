"""Anthropic adapter: manual tool-use loop on the Messages API (default model claude-fable-5-2, D34).

- Fable 5.2 always thinks: no `thinking` parameter; depth via output_config.effort (LLM_EFFORT).
- Forced tool_choice is rejected on this model, so tools stay on `auto`.
- Server-side refusal fallback is on for models that support it.
- The conversation is append-only: assistant content goes back unchanged.
"""
from __future__ import annotations

import os
from typing import Any

import anthropic

from .llm import EventLog, LLMError, ToolCaller

FALLBACK_MODELS = {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TURNS = 12


class AnthropicSession:
    def __init__(self, llm: AnthropicLLM, system: str, user: str, tools: list[dict], schema: dict,
                 max_tool_calls: int, log: EventLog, key: str):
        self.llm, self.system, self.tools, self.schema = llm, system, tools, schema
        self.max_tool_calls, self.log, self.key = max_tool_calls, log, key
        self.messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        self.tool_calls = 0

    def _create(self):
        output_config: dict[str, Any] = {"effort": self.llm.effort}
        if self.llm.use_format:
            output_config["format"] = {"type": "json_schema", "schema": self.schema}
        kwargs: dict[str, Any] = dict(model=self.llm.model, max_tokens=16000, system=self.system,
                                      messages=self.messages, output_config=output_config)
        if self.tools:
            kwargs["tools"] = self.tools
        if self.llm.model in FALLBACK_MODELS:
            return self.llm.client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
        return self.llm.client.messages.create(**kwargs)

    def run(self, call_tool: ToolCaller) -> str:
        for _ in range(MAX_TURNS):
            try:
                res = self._create()
            except anthropic.BadRequestError as e:
                if self.llm.use_format and "format" in str(e.message).lower():
                    self.llm.use_format = False   # schema feature rejected: rely on Pydantic validation
                    self.log({"type": "llm_notice", "key": self.key, "msg": "output_config.format rejected, retrying without"})
                    continue
                raise LLMError(f"bad request: {e.message}") from e
            except anthropic.RateLimitError as e:
                raise LLMError("rate limited") from e
            except anthropic.APIStatusError as e:
                raise LLMError(f"api error {e.status_code}") from e
            except anthropic.APIConnectionError as e:
                raise LLMError("connection error") from e
            u = res.usage
            self.log({"type": "llm_response", "key": self.key, "model": res.model, "stop_reason": res.stop_reason,
                      "input_tokens": u.input_tokens, "output_tokens": u.output_tokens})
            if res.stop_reason == "refusal":
                raise LLMError("refused")
            if res.stop_reason == "max_tokens":
                raise LLMError("max_tokens")
            self.messages.append({"role": "assistant", "content": res.content})
            if res.stop_reason == "pause_turn":
                continue
            uses = [b for b in res.content if b.type == "tool_use"]
            if not uses:
                text = "".join(b.text for b in res.content if b.type == "text").strip()
                if not text:
                    raise LLMError("empty answer")
                return text
            results = []
            for b in uses:
                self.tool_calls += 1
                if self.tool_calls > self.max_tool_calls:
                    out, err = "Tool budget used up. Answer now with the final JSON verdict.", True
                else:
                    out, err = call_tool(b.name, b.input)
                self.log({"type": "tool_call", "key": self.key, "tool": b.name, "input": b.input,
                          "is_error": err, "output": out[:600]})
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out, "is_error": err})
            self.messages.append({"role": "user", "content": results})
        raise LLMError("too many turns")

    def followup(self, message: str, call_tool: ToolCaller) -> str:
        self.messages.append({"role": "user", "content": message})
        return self.run(call_tool)


class AnthropicLLM:
    name = "anthropic"

    def __init__(self) -> None:
        self.model = os.environ.get("LLM_MODEL", "claude-fable-5-2")
        self.effort = os.environ.get("LLM_EFFORT", "high")
        self.use_format = True
        self.client = anthropic.Anthropic(max_retries=3)

    def start(self, system: str, user: str, tools: list[dict], schema: dict,
              max_tool_calls: int, log: EventLog, key: str) -> AnthropicSession:
        return AnthropicSession(self, system, user, tools, schema, max_tool_calls, log, key)
