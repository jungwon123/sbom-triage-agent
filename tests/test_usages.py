"""Reachability mutations (HARNESS 3, ported from poc/mutation_test.py)."""
import pytest

from triage.enrich import usages


def state(pkg, files, eco="npm"):
    refs = usages.find(pkg, eco, files)
    kinds = {r.kind for r in refs}
    return "runtime" if "runtime" in kinds else "test" if kinds else "none"


@pytest.mark.parametrize("code,expected", [
    ("import lib from 'axios';\nlib();\n", "runtime"),
    ("const lib = require(\"axios\");\n", "runtime"),
    ("const lib = await import('axios');\n", "runtime"),
    ("import { get } from 'axios/lib/core';\n", "runtime"),
    ("// import lib from 'axios';\n", "none"),
    ("/* const a = require('axios') */\n", "none"),
    ("export const doc = \"const lib = require('axios')\";\n", "none"),
    ("import lib from 'axios-retry';\n", "none"),
])
def test_runtime_file(code, expected):
    assert state("axios", [("src/app/poc.ts", code)]) == expected


def test_test_file_is_test():
    assert state("axios", [("src/tests/poc.test.ts", "import lib from 'axios';\n")]) == "test"
    assert state("axios", [("e2e/a.ts", "import lib from 'axios';\n")]) == "test"


def test_java_imports():
    files = [("src/main/java/App.java", "package a;\nimport org.apache.logging.log4j.Logger;\n"),
             ("src/test/java/AppTest.java", "import org.apache.logging.log4j.LogManager;\n")]
    refs = usages.find("org.apache.logging.log4j:log4j-core", "Maven", files)
    assert [r.kind for r in refs] == ["runtime", "test"]
    assert usages.jvm_prefix("com.fasterxml.jackson.core:jackson-databind") == "com.fasterxml.jackson"
