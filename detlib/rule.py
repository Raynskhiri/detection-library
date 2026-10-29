"""Rule model: loading, validation, the condition parser and the reference matcher.

A rule looks like this (see rules/ for real ones)::

    id: DL-0001
    title: PowerShell with an encoded command
    attack: [T1059.001, T1027]
    logsource: process_creation
    detection:
      selection:
        process.name: [powershell.exe, pwsh.exe]
        process.command_line|contains: [" -enc ", " -encodedcommand "]
      filter_sccm:
        parent.name: ccmexec.exe
      condition: selection and not filter_sccm

Inside a selection every field must match (AND). A list of values means any of
them (OR), unless the ``all`` modifier is used. Matching is case-insensitive.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .schema import MODIFIERS, SOURCES

ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
RULE_ID = re.compile(r"^DL-\d{4}$")
SEVERITIES = ("low", "medium", "high", "critical")
TACTICS = ("initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access",
           "discovery", "lateral-movement", "command-and-control", "exfiltration", "impact")
REQUIRED = ("id", "title", "description", "attack", "tactic", "severity", "logsource",
            "detection", "false_positives", "triage", "tests")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Predicate:
    field: str
    modifiers: tuple[str, ...]
    values: tuple[str, ...]

    @property
    def op(self) -> str:
        for m in ("contains", "startswith", "endswith", "re", "cidr"):
            if m in self.modifiers:
                return m
        return "eq"

    @property
    def match_all(self) -> bool:
        return "all" in self.modifiers


@dataclass
class Rule:
    id: str
    title: str
    description: str
    attack: list[str]
    tactic: str
    severity: str
    logsource: str
    selections: dict[str, list[Predicate]]
    condition: Any  # parsed AST
    condition_text: str
    false_positives: list[str]
    triage: list[str]
    tests: dict[str, list[dict]]
    references: list[str] = field(default_factory=list)
    path: Path | None = None

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "_", self.title.lower()).strip("_")


# ---------------------------------------------------------------- condition parser

TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


def parse_condition(text: str, names: set[str]):
    tokens = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise RuleError(f"bad condition near {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    i = 0

    def peek():
        return tokens[i] if i < len(tokens) else None

    def take():
        nonlocal i
        i += 1
        return tokens[i - 1]

    def expr():
        node = term()
        while peek() == "or":
            take()
            node = ("or", node, term())
        return node

    def term():
        node = factor()
        while peek() == "and":
            take()
            node = ("and", node, factor())
        return node

    def factor():
        t = peek()
        if t is None:
            raise RuleError("condition ends too early")
        if t == "not":
            take()
            return ("not", factor())
        if t == "(":
            take()
            node = expr()
            if take() != ")":
                raise RuleError("missing ')' in condition")
            return node
        take()
        if t not in names:
            raise RuleError(f"condition uses unknown selection {t!r}")
        return ("sel", t)

    ast = expr()
    if i != len(tokens):
        raise RuleError(f"unexpected {tokens[i]!r} in condition")
    return ast


def selections_used(ast) -> set[str]:
    if ast[0] == "sel":
        return {ast[1]}
    return set().union(*(selections_used(a) for a in ast[1:]))


# ---------------------------------------------------------------- loading

def _predicates(name: str, body: Any, source) -> list[Predicate]:
    if not isinstance(body, dict) or not body:
        raise RuleError(f"selection {name!r} must be a non-empty mapping")
    preds = []
    for key, raw in body.items():
        fname, *mods = key.split("|")
        if fname not in source.fields:
            raise RuleError(f"{name}: field {fname!r} is not available in {source.name}")
        bad = set(mods) - MODIFIERS
        if bad:
            raise RuleError(f"{name}: unknown modifier(s) {sorted(bad)}")
        values = raw if isinstance(raw, list) else [raw]
        if not values:
            raise RuleError(f"{name}: {key} has no values")
        values = tuple(str(v) for v in values)
        if "re" in mods:
            for v in values:
                re.compile(v)
        if "cidr" in mods:
            for v in values:
                ipaddress.ip_network(v, strict=False)
        if source.fields[fname].numeric and (set(mods) - {"all"} or not all(v.isdigit() for v in values)):
            raise RuleError(f"{name}: {fname} is numeric, use plain integer values")
        preds.append(Predicate(fname, tuple(mods), values))
    return preds


def load_rule(path: Path) -> Rule:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuleError(f"{path.name}: not a mapping")
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise RuleError(f"{path.name}: missing {missing}")
    if not RULE_ID.match(str(data["id"])):
        raise RuleError(f"{path.name}: id must look like DL-0001")
    if data["severity"] not in SEVERITIES:
        raise RuleError(f"{path.name}: severity must be one of {SEVERITIES}")
    if data["tactic"] not in TACTICS:
        raise RuleError(f"{path.name}: tactic must be one of {TACTICS}")
    if not data["attack"] or not all(ATTACK_ID.match(str(t)) for t in data["attack"]):
        raise RuleError(f"{path.name}: attack must list technique ids like T1059.001")
    source = SOURCES.get(data["logsource"])
    if source is None:
        raise RuleError(f"{path.name}: unknown logsource {data['logsource']!r}")

    det = dict(data["detection"])
    cond_text = det.pop("condition", None)
    if not cond_text:
        raise RuleError(f"{path.name}: detection needs a condition")
    try:
        selections = {n: _predicates(n, b, source) for n, b in det.items()}
        ast = parse_condition(str(cond_text), set(selections))
    except RuleError as e:
        raise RuleError(f"{path.name}: {e}") from None
    unused = set(selections) - selections_used(ast)
    if unused:
        raise RuleError(f"{path.name}: selections never used in the condition: {sorted(unused)}")

    tests = data["tests"] or {}
    if not tests.get("match") or not tests.get("no_match"):
        raise RuleError(f"{path.name}: tests need at least one 'match' and one 'no_match' event")
    for kind in ("match", "no_match"):
        for ev in tests[kind]:
            unknown = set(ev) - set(source.fields)
            if unknown:
                raise RuleError(f"{path.name}: test event uses unknown field(s) {sorted(unknown)}")

    for key in ("false_positives", "triage"):
        if not isinstance(data[key], list) or not data[key]:
            raise RuleError(f"{path.name}: {key} must be a non-empty list")

    return Rule(
        id=data["id"], title=data["title"], description=" ".join(str(data["description"]).split()),
        attack=[str(t) for t in data["attack"]], tactic=data["tactic"], severity=data["severity"],
        logsource=data["logsource"], selections=selections, condition=ast, condition_text=str(cond_text),
        false_positives=list(data["false_positives"]), triage=list(data["triage"]), tests=tests,
        references=list(data.get("references") or []), path=path,
    )


def load_rules(directory: Path) -> list[Rule]:
    rules = [load_rule(p) for p in sorted(directory.rglob("*.yml"))]
    seen: dict[str, Path] = {}
    for r in rules:
        if r.id in seen:
            raise RuleError(f"duplicate id {r.id} in {r.path} and {seen[r.id]}")
        seen[r.id] = r.path
    return sorted(rules, key=lambda r: r.id)


# ---------------------------------------------------------------- reference matcher

def _value_matches(op: str, actual: str, expected: str) -> bool:
    a, e = actual.lower(), expected.lower()
    if op == "eq":
        return a == e
    if op == "contains":
        return e in a
    if op == "startswith":
        return a.startswith(e)
    if op == "endswith":
        return a.endswith(e)
    if op == "re":
        return re.search(expected, actual, re.IGNORECASE) is not None
    if op == "cidr":
        try:
            return ipaddress.ip_address(actual) in ipaddress.ip_network(expected, strict=False)
        except ValueError:
            return False
    raise AssertionError(op)


def _predicate_matches(p: Predicate, event: dict) -> bool:
    if p.field not in event or event[p.field] is None:
        return False
    actual = str(event[p.field])
    hits = (_value_matches(p.op, actual, v) for v in p.values)
    return all(hits) if p.match_all else any(hits)


def _eval(ast, rule: Rule, event: dict) -> bool:
    kind = ast[0]
    if kind == "sel":
        return all(_predicate_matches(p, event) for p in rule.selections[ast[1]])
    if kind == "not":
        return not _eval(ast[1], rule, event)
    if kind == "and":
        return _eval(ast[1], rule, event) and _eval(ast[2], rule, event)
    if kind == "or":
        return _eval(ast[1], rule, event) or _eval(ast[2], rule, event)
    raise AssertionError(kind)


def matches(rule: Rule, event: dict) -> bool:
    """Reference semantics. Both compilers must agree with this."""
    return _eval(rule.condition, rule, event)
