# AGENTS.md

This project's rules and workflow live in two files. Read them before changing code.

- `CLAUDE.md`: what we build and the rules that must hold (schema first, rule vs LLM boundary, read-only agent, never execute LLM output, all external calls through `cache.py`, secrets only in `.env`).
- `HARNESS.md`: phases, gates and the progress log.

Quick start: `uv sync --extra openai`, `uv run python -m triage doctor`, `uv run pytest`.

- `kit/`: finals harness kit. Start with `kit/START.md`. Procedures are in `kit/claude/skills/<name>/SKILL.md`; read the one you are told to use.
- Do not add AI attribution (`Co-Authored-By`, "Generated with ...") to commit messages or PR descriptions.
- After changing `backend/triage/models.py`, run `uv run python scripts/gen_types.py` in the same commit.
