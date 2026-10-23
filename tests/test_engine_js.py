"""The browser engine (site/engine.js) must agree with the Python reference.

Every test event, plus every test event with one field removed, plus every
scenario event checked against every rule of its log source.
"""

import json
import shutil
import subprocess

import pytest

from detlib.cli import ROOT, RULES, SCENARIO
from detlib.export import load_scenario
from detlib.rule import load_rules, matches

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def _cases():
    rules = load_rules(RULES)
    cases = []
    for r in rules:
        for ev in r.tests["match"] + r.tests["no_match"]:
            cases.append((r, ev))
            for k in ev:
                cases.append((r, {x: v for x, v in ev.items() if x != k}))
    for step in load_scenario(SCENARIO)["steps"]:
        for r in rules:
            if r.logsource == step["logsource"]:
                cases.append((r, step["event"]))
    return cases


def test_js_engine_agrees_with_python():
    cases = _cases()
    payload = json.dumps([{"rule": r.id, "event": ev} for r, ev in cases])
    out = subprocess.run([NODE, str(ROOT / "site" / "crosscheck.mjs")], input=payload,
                         capture_output=True, text=True, check=True).stdout
    js = json.loads(out)
    assert len(js) == len(cases) > 500
    diffs = [(r.id, ev) for (r, ev), j in zip(cases, js) if matches(r, ev) != j]
    assert diffs == []
