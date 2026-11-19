"""Two-stage mode: the in-network model reads code, the writer model never sees it."""
import json

from triage import score
from triage.agent import run as agent_run
from triage.agent.llm import LLMError
from tests.test_agent_contract import verdict

GOOD = verdict(proposed_bucket="NOW").model_dump_json()   # the fixture finding scores NOW

SECRET = "INTERNAL_SECRET_TOKEN_abc"


class Recorder:
    """Fake LLM that records every prompt it was given."""
    def __init__(self, name, answers, looks=True):
        self.name, self.answers, self.seen, self.tools, self.looks = name, list(answers), [], [], looks

    def start(self, system, user, tools, schema, max_tool_calls, log, key):
        self.seen.append(system + user)
        self.tools.append(tools)
        outer = self

        class S:
            def run(self, call_tool):
                if outer.looks:
                    call_tool("search_usages", {"package": "lib"})
                a = outer.answers.pop(0)
                if isinstance(a, Exception):
                    raise a
                return a
            followup = lambda self, m, c: self.run(c)  # noqa: E731
        return S()


CODE = json.dumps({"reachability": "used_symbol", "evidence_files": ["src/app.ts"]})


def finding(make_finding, runtime_site):
    site = runtime_site.model_copy(update={"snippet": f"const k = '{SECRET}'; import lib from 'lib'"})
    return make_finding(import_sites=[site])


def test_writer_gets_no_code_and_no_tools(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    reader, writer = Recorder("local", [CODE]), Recorder("anthropic", [GOOD])
    [t] = agent_run.run([f], tmp_path, writer, tmp_path, code_llm=reader)
    assert SECRET in reader.seen[0]            # the in-network model may see code
    assert SECRET not in writer.seen[0]        # the outside model must not
    assert "src/app.ts" not in writer.seen[0]  # not even file names
    assert writer.tools == [[]]
    assert t.decided_by == "agent" and t.code_read_by == "local_agent"


def test_reachability_comes_from_code_reader(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    [t] = agent_run.run([f], tmp_path, Recorder("anthropic", [GOOD]), tmp_path, code_llm=Recorder("local", [CODE]))
    assert json.loads(GOOD)["reachability"] == "imported_only"   # what the writer claimed
    assert t.reachability == "used_symbol" and t.evidence_files == ["src/app.ts"]


def test_reader_failure_skips_writer_and_falls_back(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    writer = Recorder("anthropic", [GOOD])
    [t] = agent_run.run([f], tmp_path, writer, tmp_path, code_llm=Recorder("local", [LLMError("server down")]))
    assert writer.seen == [] and t.decided_by == "agent_fallback"
    assert t.reachability == score.score(f).reachability and t.code_read_by == "rule"


def test_writer_failure_keeps_local_reachability(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    [t] = agent_run.run([f], tmp_path, Recorder("anthropic", [LLMError("refused")]), tmp_path,
                        code_llm=Recorder("local", [CODE]))
    assert t.decided_by == "agent_fallback" and t.final_bucket == t.rule_bucket
    assert t.reachability == "used_symbol"


def test_reader_only_mode_sends_nothing_outside(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    [t] = agent_run.run([f], tmp_path, None, tmp_path, code_llm=Recorder("local", [CODE]))
    assert t.decided_by == "agent" and t.final_bucket == t.rule_bucket and t.reachability == "used_symbol"


def test_tagged_run_writes_separate_files(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    agent_run.run([f], tmp_path, Recorder("anthropic", [GOOD]), tmp_path, code_llm=Recorder("local", [CODE]), tag="split")
    assert (tmp_path / "agent_answers.split.json").exists()
    assert not (tmp_path / "agent_answers.json").exists()


def test_reader_that_never_looks_is_rejected(make_finding, runtime_site, tmp_path):
    f = finding(make_finding, runtime_site)
    lazy = Recorder("local", [CODE, CODE], looks=False)
    [t] = agent_run.run([f], tmp_path, None, tmp_path, code_llm=lazy)
    assert t.decided_by == "agent_fallback" and t.code_read_by == "rule"


def test_revise_sends_no_logs_outside_in_two_stage_mode(make_finding):
    from triage.agent import prompts
    steps = [{"name": "test", "status": "failed", "log_tail": f"at src/pay/card.ts:12 {SECRET}"}]
    f = make_finding()
    assert SECRET in prompts.revise_prompt(f, {}, steps, ["1.0.1"])
    quiet = prompts.revise_prompt(f, {}, steps, ["1.0.1"], with_logs=False)
    assert SECRET not in quiet and "card.ts" not in quiet and '"status": "failed"' in quiet
