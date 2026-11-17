"""OpenAI adapter (finals fallback, D34): Responses API with function tools and a JSON schema.

Kept in its own file so the Anthropic path stays provider-specific. Model comes from OPENAI_MODEL.
Not exercised against the live API yet; run `python -m triage doctor --llm` with a key to check.
"""
from __future__ import annotations

import json
import os
from typing import Any

import openai

from .llm import EventLog, LLMError, ToolCaller

MAX_TURNS = 12


class OpenAISession:
    def __init__(self, llm: OpenAILLM, system: str, user: str, tools: list[dict], schema: dict,
                 max_tool_calls: int, log: EventLog, key: str):
        self.llm, self.system, self.schema = llm, system, schema
        self.tools = [{"type": "function", "name": t["name"], "description": t["description"],
                       "parameters": t["input_schema"], "strict": False} for t in tools]
        self.max_tool_calls, self.log, self.key = max_tool_calls, log, key
        self.items: list[Any] = [{"role": "user", "content": user}]
        self.tool_calls = 0

    def run(self, call_tool: ToolCaller) -> str:
        for _ in range(MAX_TURNS):
            try:
                res = self.llm.client.responses.create(
                    model=self.llm.model, instructions=self.system, input=self.items,
                    **({"tools": self.tools} if self.tools else {}),
                    text={"format": {"type": "json_schema", "name": "verdict", "schema": self.schema, "strict": True}},
                )
            except openai.APIStatusError as e:
                raise LLMError(f"api error {e.status_code}") from e
            except openai.APIConnectionError as e:
                raise LLMError("connection error") from e
            usage = getattr(res, "usage", None)
            self.log({"type": "llm_response", "key": self.key, "model": res.model, "status": res.status,
                      "input_tokens": getattr(usage, "input_tokens", None),
                      "output_tokens": getattr(usage, "output_tokens", None)})
            self.items += res.output
            calls = [o for o in res.output if o.type == "function_call"]
            if not calls:
                text = (res.output_text or "").strip()
                if not text:
                    raise LLMError("empty answer")
                return text
            for c in calls:
                self.tool_calls += 1
                try:
                    args = json.loads(c.arguments or "{}")
                except ValueError:
                    out, err = "arguments were not valid JSON", True
                else:
                    if self.tool_calls > self.max_tool_calls:
                        out, err = "Tool budget used up. Answer now with the final JSON verdict.", True
                    else:
                        out, err = call_tool(c.name, args)
                self.log({"type": "tool_call", "key": self.key, "tool": c.name, "input": c.arguments,
                          "is_error": err, "output": out[:600]})
                self.items.append({"type": "function_call_output", "call_id": c.call_id,
                                   "output": ("ERROR: " if err else "") + out})
        raise LLMError("too many turns")

    def followup(self, message: str, call_tool: ToolCaller) -> str:
        self.items.append({"role": "user", "content": message})
        return self.run(call_tool)


class OpenAILLM:
    name = "openai"

    def __init__(self) -> None:
        self.model = os.environ.get("OPENAI_MODEL", "")
        if not self.model:
            raise LLMError("set OPENAI_MODEL in .env (the model name the venue provides)")
        self.client = openai.OpenAI(max_retries=3)

    def start(self, system: str, user: str, tools: list[dict], schema: dict,
              max_tool_calls: int, log: EventLog, key: str) -> OpenAISession:
        return OpenAISession(self, system, user, tools, schema, max_tool_calls, log, key)
