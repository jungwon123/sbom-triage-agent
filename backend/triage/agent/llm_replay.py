"""Replay adapter: returns recorded final answers from a previous run (DEMO_MODE=replay, N7).

Reads <run_dir>/agent_answers.json written by a live agent run. No network.
"""
from __future__ import annotations

import json
import pathlib

from .llm import EventLog, LLMError, ToolCaller


class ReplaySession:
    def __init__(self, answers: list[str], key: str, log: EventLog):
        self.answers, self.key, self.log = list(answers), key, log

    def run(self, call_tool: ToolCaller) -> str:
        if not self.answers:
            raise LLMError(f"no recorded answer for {self.key}")
        self.log({"type": "llm_response", "key": self.key, "model": "replay"})
        return self.answers.pop(0)

    def followup(self, message: str, call_tool: ToolCaller) -> str:
        return self.run(call_tool)


class ReplayLLM:
    name = "replay"

    def __init__(self, run_dir: str | None):
        path = pathlib.Path(run_dir or "") / "agent_answers.json"
        if not path.exists():
            raise LLMError(f"replay needs {path}; set LLM_REPLAY_FROM to a run that used a live LLM")
        self.answers: dict[str, list[str]] = json.loads(path.read_text())

    def start(self, system: str, user: str, tools: list[dict], schema: dict,
              max_tool_calls: int, log: EventLog, key: str) -> ReplaySession:
        return ReplaySession(self.answers.get(key, []), key, log)
