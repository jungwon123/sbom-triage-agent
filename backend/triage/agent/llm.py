"""LLM adapter interface (HANDOFF 6.7, D34). Providers live in their own files.

A Session runs one conversation: tools are called through `call_tool`, the result is the final
JSON text. `followup` appends a message to the same conversation (used for the one retry).
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Protocol

ToolCaller = Callable[[str, dict], tuple[str, bool]]   # -> (result text, is_error)
EventLog = Callable[[dict], None]


class LLMError(Exception):
    """Any failure that should make the caller fall back to the rule result."""


class Session(Protocol):
    def run(self, call_tool: ToolCaller) -> str: ...
    def followup(self, message: str, call_tool: ToolCaller) -> str: ...


class LLM(Protocol):
    name: str

    def start(self, system: str, user: str, tools: list[dict[str, Any]], schema: dict,
              max_tool_calls: int, log: EventLog, key: str) -> Session: ...


def provider() -> str:
    """Model that writes the verdict. May run outside the network."""
    return os.environ.get("LLM_PROVIDER", "anthropic").lower()


def code_provider() -> str | None:
    """Model allowed to read source code. Unset means one model does both jobs (single stage)."""
    return (os.environ.get("LLM_CODE_PROVIDER") or "").lower() or None


def make(run_dir: str | None = None, name: str | None = None) -> LLM | None:
    """None means rule-only (provider "none")."""
    p = name or provider()
    if p == "none":
        return None
    if p == "anthropic":
        from .llm_anthropic import AnthropicLLM
        return AnthropicLLM()
    if p == "openai":
        from .llm_openai import OpenAILLM
        return OpenAILLM()
    if p == "local":
        from .llm_local import LocalLLM
        return LocalLLM()
    if p == "replay":
        from .llm_replay import ReplayLLM
        return ReplayLLM(os.environ.get("LLM_REPLAY_FROM") or run_dir)
    raise LLMError(f"unknown LLM provider {p}")
