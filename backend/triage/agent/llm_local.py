"""Local LLM adapter: any OpenAI-compatible Chat Completions server inside the network
(Ollama, vLLM, LM Studio). Used as the model that is allowed to read source code.

LOCAL_LLM_BASE_URL (default http://localhost:11434/v1) and LOCAL_LLM_MODEL come from .env.
Run against Ollama with qwen2.5:7b on 2026-11-23 (HANDOFF D35); check a server with `python -m triage doctor --llm`.
"""
from __future__ import annotations

import json
import os
from typing import Any

import openai

from .llm import EventLog, LLMError, ToolCaller

MAX_TURNS = 12


class LocalSession:
    def __init__(self, llm: LocalLLM, system: str, user: str, tools: list[dict], schema: dict,
                 max_tool_calls: int, log: EventLog, key: str):
        self.llm, self.schema = llm, schema
        self.tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                         "parameters": t["input_schema"]}} for t in tools]
        self.max_tool_calls, self.log, self.key = max_tool_calls, log, key
        hint = "\nAnswer with one JSON object matching this schema:\n" + json.dumps(schema, ensure_ascii=False)
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system + hint},
                                               {"role": "user", "content": user}]
        self.tool_calls = 0

    def _create(self):
        kwargs: dict[str, Any] = dict(model=self.llm.model, messages=self.messages)
        if self.tools:
            kwargs["tools"] = self.tools
        # A forced JSON grammar stops local servers from emitting tool calls, so the schema is
        # enforced only when the session has no tools; otherwise Pydantic validates the answer.
        if self.llm.use_format and not self.tools:
            kwargs["response_format"] = {"type": "json_schema",
                                         "json_schema": {"name": "verdict", "schema": self.schema, "strict": True}}
        return self.llm.client.chat.completions.create(**kwargs)

    def run(self, call_tool: ToolCaller) -> str:
        for _ in range(MAX_TURNS):
            try:
                res = self._create()
            except openai.BadRequestError as e:
                if self.llm.use_format:
                    self.llm.use_format = False   # server without json_schema support: rely on Pydantic validation
                    self.log({"type": "llm_notice", "key": self.key, "msg": "response_format rejected, retrying without"})
                    continue
                raise LLMError(f"bad request: {str(e)[:200]}") from e
            except openai.APIStatusError as e:
                raise LLMError(f"api error {e.status_code}") from e
            except openai.APIConnectionError as e:
                raise LLMError(f"local LLM server not reachable at {self.llm.base_url}") from e
            msg = res.choices[0].message
            usage = getattr(res, "usage", None)
            self.log({"type": "llm_response", "key": self.key, "model": res.model, "provider": "local",
                      "input_tokens": getattr(usage, "prompt_tokens", None),
                      "output_tokens": getattr(usage, "completion_tokens", None)})
            calls = msg.tool_calls or []
            entry: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if calls:
                entry["tool_calls"] = [{"id": c.id, "type": "function",
                                        "function": {"name": c.function.name, "arguments": c.function.arguments}} for c in calls]
            self.messages.append(entry)
            if not calls:
                text = (msg.content or "").strip()
                if not text:
                    raise LLMError("empty answer")
                return text
            for c in calls:
                self.tool_calls += 1
                try:
                    args = json.loads(c.function.arguments or "{}")
                except ValueError:
                    out, err = "arguments were not valid JSON", True
                else:
                    if self.tool_calls > self.max_tool_calls:
                        out, err = "Tool budget used up. Answer now with the final JSON.", True
                    else:
                        out, err = call_tool(c.function.name, args)
                self.log({"type": "tool_call", "key": self.key, "tool": c.function.name, "input": c.function.arguments,
                          "is_error": err, "output": out[:600]})
                self.messages.append({"role": "tool", "tool_call_id": c.id, "content": ("ERROR: " if err else "") + out})
        raise LLMError("too many turns")

    def followup(self, message: str, call_tool: ToolCaller) -> str:
        self.messages.append({"role": "user", "content": message})
        return self.run(call_tool)


class LocalLLM:
    name = "local"

    def __init__(self) -> None:
        self.model = os.environ.get("LOCAL_LLM_MODEL", "")
        if not self.model:
            raise LLMError("set LOCAL_LLM_MODEL in .env (the model name on your local server)")
        self.base_url = os.environ.get("LOCAL_LLM_BASE_URL", "http://localhost:11434/v1")
        self.use_format = True
        # local servers ignore the key; the SDK only needs a non-empty value
        self.client = openai.OpenAI(base_url=self.base_url, api_key=os.environ.get("LOCAL_LLM_API_KEY", "local"),
                                    max_retries=1, timeout=300)

    def start(self, system: str, user: str, tools: list[dict], schema: dict,
              max_tool_calls: int, log: EventLog, key: str) -> LocalSession:
        return LocalSession(self, system, user, tools, schema, max_tool_calls, log, key)
