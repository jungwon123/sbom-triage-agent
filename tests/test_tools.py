import os

import pytest

from triage.agent.tools import RepoTools, ToolError, safe_path


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "src").mkdir(parents=True)
    (r / "src/app.js").write_text("const _ = require('lodash');\n_.merge({}, input);\n")
    (tmp_path / "secret.txt").write_text("outside")
    return r


def test_read_inside(repo):
    assert "require('lodash')" in RepoTools(repo, {}).call("read_file", {"path": "src/app.js"})


@pytest.mark.parametrize("path", ["../secret.txt", "/etc/passwd", "src/../../secret.txt", ""])
def test_outside_paths_rejected(repo, path):
    with pytest.raises(ToolError):
        safe_path(repo, path)


def test_symlink_escape_rejected(repo, tmp_path):
    os.symlink(tmp_path / "secret.txt", repo / "link.txt")
    with pytest.raises(ToolError):
        safe_path(repo, "link.txt")


def test_search_usages_with_symbol(repo):
    out = RepoTools(repo, {}).call("search_usages", {"package": "lodash", "symbol": "merge"})
    assert "src/app.js:1 [runtime]" in out and "src/app.js:2 [symbol]" in out


def test_unknown_tool_and_bad_symbol(repo):
    t = RepoTools(repo, {})
    with pytest.raises(ToolError):
        t.call("run_command", {"cmd": "ls"})
    with pytest.raises(ToolError):
        t.call("search_usages", {"package": "lodash", "symbol": "a;rm -rf"})


def test_no_write_or_exec_tools():
    from triage.agent.tools import SPECS
    assert {s["name"] for s in SPECS} == {"get_finding", "search_usages", "read_file", "get_advisory"}


def test_credential_files_are_not_readable(tmp_path):
    import pytest
    from triage.agent.tools import RepoTools, ToolError
    for name in (".env", ".env.production", ".npmrc", "server.pem", "config/secrets.yml", ".git/config", "id_rsa"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("TOKEN=abc")
        with pytest.raises(ToolError):
            RepoTools(tmp_path, {}).read_file(name)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "environment.ts").write_text("export const x = 1")
    assert "export const x" in RepoTools(tmp_path, {}).read_file("src/environment.ts")
