from pathlib import Path

import pytest

from detlib.cli import RULES, build, run_tests
from detlib.compile import to_spl, to_xql
from detlib.rule import load_rules, matches
from detlib.schema import SOURCES

from .interp import run

ALL = load_rules(RULES)
EVENTS = [(r, kind, i, ev) for r in ALL for kind in ("match", "no_match")
          for i, ev in enumerate(r.tests[kind])]


def _row(rule, event, dialect):
    """Map a portable test event onto the backend's column names."""
    fields = SOURCES[rule.logsource].fields
    row = {}
    for name, value in event.items():
        f = fields[name]
        col = f.xql if dialect == "xql" else f.spl
        if f.numeric:
            value = int(value)
        elif dialect == "spl" and col in ("process_name", "parent_name", "file_name"):
            value = str(value).lower()  # the SPL eval prelude lower-cases basenames
        row[col] = value
    return row


def test_library_has_rules():
    assert len(ALL) >= 25
    assert len({r.id for r in ALL}) == len(ALL)


def test_every_rule_passes_its_own_tests():
    assert run_tests(ALL) == []


@pytest.mark.parametrize("rule,kind,i,event", EVENTS, ids=[f"{r.id}-{k}{i}" for r, k, i, _ in EVENTS])
@pytest.mark.parametrize("dialect", ["xql", "spl"])
def test_compiled_query_agrees_with_reference(rule, kind, i, event, dialect):
    expected = kind == "match"
    assert matches(rule, event) is expected
    query = to_xql(rule) if dialect == "xql" else to_spl(rule)
    assert run(query, dialect, _row(rule, event, dialect)) is expected, query


@pytest.mark.parametrize("rule", ALL, ids=[r.id for r in ALL])
def test_missing_fields_behave_like_the_reference(rule):
    """Drop each field in turn from every test event. XQL and SPL drop a row when
    the filter is null, so without the null guard a 'not filter' rule would stay
    silent on events that simply lack the filtered field."""
    queries = {"xql": to_xql(rule), "spl": to_spl(rule)}
    for ev in rule.tests["match"] + rule.tests["no_match"]:
        for missing in ev:
            partial = {k: v for k, v in ev.items() if k != missing}
            expected = matches(rule, partial)
            for dialect, q in queries.items():
                assert run(q, dialect, _row(rule, partial, dialect)) is expected, (missing, dialect, q)


def test_build_is_up_to_date():
    assert build(check=True) == 0, "run: python -m detlib build"


def test_every_rule_has_a_doc_page():
    docs = Path(RULES).parent / "docs" / "rules"
    assert {p.stem for p in docs.glob("DL-*.md")} == {r.id for r in ALL}
