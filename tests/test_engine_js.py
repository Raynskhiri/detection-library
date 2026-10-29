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


def test_js_windows_event_fields_match_python():
    """The playground maps Windows EventData names itself; it must use the same table as schema.py."""
    from detlib.schema import WINEVENT_DATA

    script = "import('./site/engine.js').then(m => console.log(JSON.stringify(m.WINEVENT_DATA)))"
    out = subprocess.run([NODE, "--input-type=module", "-e", script.replace("./site", str(ROOT / "site"))],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == WINEVENT_DATA


def test_js_parses_a_security_event_xml():
    xml = ('<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4662</EventID></System>'
           '<EventData><Data Name="SubjectUserName">studentx</Data>'
           '<Data Name="Properties">%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}</Data></EventData></Event>')
    script = (f"import('{ROOT / 'site' / 'engine.js'}').then(m => console.log(JSON.stringify("
              f"m.parseSysmonXml({json.dumps(xml)}))))")
    out = json.loads(subprocess.run([NODE, "--input-type=module", "-e", script],
                                    capture_output=True, text=True, check=True).stdout)
    assert out["logsource"] == "windows_event"
    assert out["event"] == {"event.id": "4662", "subject.user": "studentx",
                            "object.properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"}
    rules = {r.id: r for r in load_rules(RULES)}
    assert matches(rules["DL-0046"], out["event"])
