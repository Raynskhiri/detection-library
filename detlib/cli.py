"""detlib: build, test and check the detection library.

    python -m detlib test            run every rule against its test events
    python -m detlib build           write build/ and docs/rules/
    python -m detlib build --check   fail if build/ or docs/ are out of date (CI)
    python -m detlib show DL-0001    print one rule in both languages
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .compile import to_spl, to_xql
from .rule import TACTICS, Rule, RuleError, load_rules, matches

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
BUILD = ROOT / "build"
DOCS = ROOT / "docs" / "rules"
START, END = "<!-- rules:start -->", "<!-- rules:end -->"


def run_tests(rules: list[Rule]) -> list[str]:
    failures = []
    for r in rules:
        for i, ev in enumerate(r.tests["match"]):
            if not matches(r, ev):
                failures.append(f"{r.id}: match[{i}] did not fire: {ev}")
        for i, ev in enumerate(r.tests["no_match"]):
            if matches(r, ev):
                failures.append(f"{r.id}: no_match[{i}] fired: {ev}")
    return failures


def rule_doc(r: Rule) -> str:
    attack = ", ".join(
        f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)" for t in r.attack)
    out = [
        f"# {r.id} · {r.title}",
        "",
        f"**ATT&CK:** {attack} · **Tactic:** {r.tactic} · **Severity:** {r.severity} · "
        f"**Data:** `{r.logsource}`",
        "",
        r.description,
        "",
        "## Cortex XDR (XQL)",
        "",
        "```sql",
        to_xql(r).rstrip(),
        "```",
        "",
        "## Splunk (SPL, Sysmon)",
        "",
        "```",
        to_spl(r).rstrip(),
        "```",
        "",
        "## Triage",
        "",
        *[f"{i}. {s}" for i, s in enumerate(r.triage, 1)],
        "",
        "## Known false positives",
        "",
        *[f"- {s}" for s in r.false_positives],
        "",
        f"## Tested with",
        "",
        f"{len(r.tests['match'])} events that must fire and {len(r.tests['no_match'])} that must not, "
        f"in [`{r.path.relative_to(ROOT).as_posix()}`](../../{r.path.relative_to(ROOT).as_posix()}).",
    ]
    if r.references:
        out += ["", "## References", "", *[f"- {u}" for u in r.references]]
    return "\n".join(out) + "\n"


def navigator_layer(rules: list[Rule]) -> str:
    counts = Counter(t for r in rules for t in r.attack)
    layer = {
        "name": "Rayen Skhiri detection library",
        "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": "17"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by github.com/Raynskhiri/detection-library",
        "techniques": [
            {"techniqueID": t, "score": n, "color": "",
             "comment": ", ".join(r.id for r in rules if t in r.attack)}
            for t, n in sorted(counts.items())
        ],
        "gradient": {"colors": ["#ffd8b0", "#f97316"], "minValue": 0, "maxValue": max(counts.values())},
    }
    return json.dumps(layer, indent=2) + "\n"


def rules_table(rules: list[Rule]) -> str:
    rows = ["| ID | Detection | ATT&CK | Tactic | Severity |", "|---|---|---|---|---|"]
    for t in TACTICS:
        for r in (r for r in rules if r.tactic == t):
            rows.append(f"| [{r.id}](docs/rules/{r.id}.md) | {r.title} | {', '.join(r.attack)} | "
                        f"{r.tactic} | {r.severity} |")
    return "\n".join(rows)


def outputs(rules: list[Rule]) -> dict[Path, str]:
    files: dict[Path, str] = {}
    for r in rules:
        name = f"{r.id}_{r.slug}"
        files[BUILD / "xql" / f"{name}.xql"] = to_xql(r)
        files[BUILD / "spl" / f"{name}.spl"] = to_spl(r)
        files[DOCS / f"{r.id}.md"] = rule_doc(r)
    files[BUILD / "attack-navigator-layer.json"] = navigator_layer(rules)
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    if START in text and END in text:
        head, rest = text.split(START, 1)
        _, tail = rest.split(END, 1)
        files[readme] = f"{head}{START}\n{rules_table(rules)}\n{END}{tail}"
    return files


def build(check: bool) -> int:
    rules = load_rules(RULES)
    stale = []
    wanted = outputs(rules)
    for path, content in wanted.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != content:
            stale.append(path)
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
    generated = {p for p in wanted}
    orphans = [p for d in (BUILD / "xql", BUILD / "spl", DOCS) if d.exists()
               for p in d.iterdir() if p not in generated]
    if check:
        if stale or orphans:
            for p in stale + orphans:
                print(f"out of date: {p.relative_to(ROOT)}")
            print("run: python -m detlib build")
            return 1
        print(f"build is up to date ({len(rules)} rules)")
        return 0
    for p in orphans:
        p.unlink()
    print(f"built {len(rules)} rules, {len(stale)} file(s) changed, {len(orphans)} removed")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="detlib", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("test")
    b = sub.add_parser("build")
    b.add_argument("--check", action="store_true")
    s = sub.add_parser("show")
    s.add_argument("rule_id")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "build":
            return build(args.check)
        rules = load_rules(RULES)
    except RuleError as e:
        print(f"rule error: {e}", file=sys.stderr)
        return 2
    if args.cmd == "test":
        failures = run_tests(rules)
        for f in failures:
            print(f"FAIL {f}")
        n = sum(len(r.tests["match"]) + len(r.tests["no_match"]) for r in rules)
        print(f"{len(rules)} rules, {n} test events, {len(failures)} failure(s)")
        return 1 if failures else 0
    if args.cmd == "show":
        r = next((r for r in rules if r.id == args.rule_id), None)
        if r is None:
            print(f"no rule {args.rule_id}", file=sys.stderr)
            return 2
        print(f"# {r.id} {r.title}\n\n-- XQL --\n{to_xql(r)}\n-- SPL --\n{to_spl(r)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
