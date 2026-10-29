"""Compile a rule to Cortex XQL and Splunk SPL.

Both compilers walk the same condition tree as the reference matcher in
``rule.py``, so a rule means the same thing everywhere:

* matching is case-insensitive;
* a missing field never matches, so ``not filter`` keeps events that lack the
  field (predicates under a ``not`` get an explicit null guard, because both
  XQL and SPL drop a row when the filter evaluates to null).
"""

from __future__ import annotations

import re

from .rule import Predicate, Rule
from .schema import SOURCES


def _lit(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _regex(p: Predicate, v: str) -> str:
    if p.op == "re":
        return "(?i)" + v
    esc = re.escape(v)
    return "(?i)" + {"contains": esc, "startswith": "^" + esc, "endswith": esc + "$"}[p.op]


# ---------------------------------------------------------------- XQL

def _xql_pred(p: Predicate, rule: Rule, guard: bool) -> str:
    f = SOURCES[rule.logsource].fields[p.field]
    col = f.xql
    if p.op == "eq":
        vals = p.values if f.numeric else [v.lower() for v in p.values]
        render = (lambda v: v) if f.numeric else _lit
        if len(vals) > 1 and not p.match_all:
            body = f"{col} in ({', '.join(render(v) for v in vals)})"
        else:
            body = " and ".join(f"{col} = {render(v)}" for v in vals)
    else:
        if p.op == "contains":
            parts = [f"{col} contains {_lit(v)}" for v in p.values]
        elif p.op == "cidr":
            parts = [f"incidr({col}, {_lit(v)})" for v in p.values]
        else:
            parts = [f"{col} ~= {_lit(_regex(p, v))}" for v in p.values]
        body = (" and " if p.match_all else " or ").join(parts)
        if len(parts) > 1:
            body = f"({body})"
    return f"({col} != null and {body})" if guard else body


def _xql_expr(ast, rule: Rule, neg: bool = False) -> str:
    kind = ast[0]
    if kind == "sel":
        preds = [_xql_pred(p, rule, neg) for p in rule.selections[ast[1]]]
        return preds[0] if len(preds) == 1 else "(" + " and ".join(preds) + ")"
    if kind == "not":
        return f"not ({_xql_expr(ast[1], rule, not neg)})"
    left, right = _xql_expr(ast[1], rule, neg), _xql_expr(ast[2], rule, neg)
    return f"({left} {kind} {right})"


def to_xql(rule: Rule) -> str:
    src = SOURCES[rule.logsource]
    expr = _xql_expr(rule.condition, rule)
    if expr.startswith("(") and _balanced_outer(expr):
        expr = expr[1:-1]
    lines = [
        "config case_sensitive = false",
        "| dataset = xdr_data",
        f"| filter {src.xql_filter}",
        *([f"| alter {', '.join(_used_alters(rule, src))}"] if src.xql_alters else []),
        f"| filter {expr}",
        f"| fields {', '.join(src.xql_columns)}",
        "| sort desc _time",
        "| limit 1000",
    ]
    return "\n".join(lines) + "\n"


def _used_alters(rule: Rule, src) -> list[str]:
    """Only the alter expressions for fields the rule filters on (plus the shown columns)."""
    used = {p.field for preds in rule.selections.values() for p in preds}
    wanted = {src.fields[f].xql for f in used} | set(src.xql_columns)
    return [a for a in src.xql_alters if a.split(" = ", 1)[0] in wanted]


# ---------------------------------------------------------------- SPL

def _spl_pred(p: Predicate, rule: Rule, guard: bool) -> str:
    f = SOURCES[rule.logsource].fields[p.field]
    col = f.spl
    if p.op == "eq":
        if f.numeric:
            vals = list(p.values)
            target = col
            render = lambda v: v  # noqa: E731
        else:
            vals = [v.lower() for v in p.values]
            target = f"lower({col})"
            render = _lit
        joiner = " AND " if p.match_all else " OR "
        body = joiner.join(f"{target}={render(v)}" for v in vals)
        if len(vals) > 1:
            body = f"({body})"
    else:
        if p.op == "cidr":
            parts = [f"cidrmatch({_lit(v)}, {col})" for v in p.values]
        else:
            parts = [f"match({col}, {_lit(_regex(p, v))})" for v in p.values]
        body = (" AND " if p.match_all else " OR ").join(parts)
        if len(parts) > 1:
            body = f"({body})"
    return f"(isnotnull({col}) AND {body})" if guard else body


def _spl_expr(ast, rule: Rule, neg: bool = False) -> str:
    kind = ast[0]
    if kind == "sel":
        preds = [_spl_pred(p, rule, neg) for p in rule.selections[ast[1]]]
        return preds[0] if len(preds) == 1 else "(" + " AND ".join(preds) + ")"
    if kind == "not":
        return f"NOT ({_spl_expr(ast[1], rule, not neg)})"
    left, right = _spl_expr(ast[1], rule, neg), _spl_expr(ast[2], rule, neg)
    return f"({left} {kind.upper()} {right})"


def to_spl(rule: Rule) -> str:
    src = SOURCES[rule.logsource]
    expr = _spl_expr(rule.condition, rule)
    if expr.startswith("(") and _balanced_outer(expr):
        expr = expr[1:-1]
    lines = [src.spl_base]
    if src.spl_evals:
        lines.append("| eval " + ", ".join(src.spl_evals))
    lines += [
        f"| where {expr}",
        f"| table {' '.join(src.spl_columns)}",
        "| sort - _time",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- helpers

def _balanced_outer(expr: str) -> bool:
    """True when the first '(' closes at the very end (safe to strip)."""
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(expr):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(expr) - 1:
                return False
    return depth == 0
