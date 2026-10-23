"""Export the library for the browser playground (site/data/*.json).

The playground evaluates rules with its own small JavaScript engine
(site/engine.js). CI runs that engine against every rule's test events and the
intrusion scenario, so the browser and Python always agree.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from .compile import to_spl, to_xql
from .rule import Rule, matches
from .schema import SOURCES


def _ast(node):
    kind = node[0]
    if kind == "sel":
        return {"sel": node[1]}
    if kind == "not":
        return {"not": _ast(node[1])}
    return {kind: [_ast(node[1]), _ast(node[2])]}


def rule_json(r: Rule) -> dict:
    return {
        "id": r.id,
        "title": r.title,
        "description": r.description,
        "attack": r.attack,
        "tactic": r.tactic,
        "severity": r.severity,
        "logsource": r.logsource,
        "selections": {
            name: [{"field": p.field, "op": p.op, "all": p.match_all, "values": list(p.values)} for p in preds]
            for name, preds in r.selections.items()
        },
        "condition": _ast(r.condition),
        "condition_text": r.condition_text,
        "triage": r.triage,
        "false_positives": r.false_positives,
        "xql": to_xql(r),
        "spl": to_spl(r),
        "tests": {k: r.tests[k] for k in ("match", "no_match")},
    }


def load_scenario(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def check_scenario(rules: list[Rule], scenario: dict) -> list[str]:
    problems = []
    ids = {r.id for r in rules}
    for i, step in enumerate(scenario["steps"]):
        src = SOURCES.get(step["logsource"])
        if src is None:
            problems.append(f"step {i}: unknown logsource {step['logsource']}")
            continue
        unknown = set(step["event"]) - set(src.fields)
        if unknown:
            problems.append(f"step {i}: unknown fields {sorted(unknown)}")
        missing = set(step["expect"]) - ids
        if missing:
            problems.append(f"step {i}: expects unknown rules {sorted(missing)}")
        fired = sorted(r.id for r in rules if r.logsource == step["logsource"] and matches(r, step["event"]))
        if fired != sorted(step["expect"]):
            problems.append(f"step {i} ({step['title']}): fired {fired}, expected {sorted(step['expect'])}")
    return problems


def site_data(rules: list[Rule], scenario: dict) -> dict[str, str]:
    schema = {
        name: {"description": s.description, "fields": sorted(s.fields)} for name, s in SOURCES.items()
    }
    return {
        "rules.json": json.dumps({"rules": [rule_json(r) for r in rules], "logsources": schema},
                                 indent=1, ensure_ascii=False) + "\n",
        "scenario.json": json.dumps(scenario, indent=1, ensure_ascii=False) + "\n",
    }
