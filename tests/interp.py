"""A tiny interpreter for the subset of XQL and SPL that detlib emits.

It is not Cortex and it is not Splunk. It exists so the tests can run the
*compiled* filter against the same test events as the reference matcher and
prove the compilers keep the rule's meaning, including how both languages drop
a row when the filter evaluates to null (three-valued logic).

XQL: ``config case_sensitive = false`` makes ``=``, ``in`` and ``contains``
case-insensitive. SPL: ``=`` in ``where`` is case-sensitive, which is why the
compiler lower-cases both sides.
"""

from __future__ import annotations

import ipaddress
import re

TOKEN = re.compile(r'\s*(?:(?P<str>"(?:\\.|[^"\\])*")|(?P<num>\d+)|(?P<op>~=|!=|=|\(|\)|,)|(?P<word>[A-Za-z_][A-Za-z0-9_.]*))')


def tokenize(text: str):
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m:
            raise SyntaxError(f"cannot tokenize at {text[pos:pos + 30]!r}")
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "str":
            val = re.sub(r"\\(.)", r"\1", val[1:-1])
        elif kind == "num":
            val = int(val)
        out.append((kind, val))
        pos = m.end()
    return out


class Parser:
    def __init__(self, text: str, dialect: str):
        self.toks = tokenize(text)
        self.i = 0
        self.dialect = dialect

    def peek(self, k=0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else (None, None)

    def take(self, kind=None, val=None):
        tok = self.peek()
        if (kind and tok[0] != kind) or (val is not None and str(tok[1]).lower() != str(val).lower()):
            raise SyntaxError(f"expected {kind} {val!r}, got {tok!r}")
        self.i += 1
        return tok

    def is_word(self, w):
        k, v = self.peek()
        return k == "word" and v.lower() == w

    def parse(self):
        node = self.or_()
        if self.i != len(self.toks):
            raise SyntaxError(f"trailing tokens: {self.toks[self.i:]}")
        return node

    def or_(self):
        node = self.and_()
        while self.is_word("or"):
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.is_word("and"):
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.is_word("not"):
            self.take()
            return ("not", self.not_())
        return self.primary()

    def primary(self):
        if self.peek() == ("op", "("):
            self.take()
            node = self.or_()
            self.take("op", ")")
            return node
        left = self.operand()
        k, v = self.peek()
        if k == "op" and v in ("=", "!=", "~="):
            self.take()
            return (v, left, self.operand())
        if k == "word" and v.lower() == "contains":
            self.take()
            return ("contains", left, self.operand())
        if k == "word" and v.lower() == "in":
            self.take()
            self.take("op", "(")
            items = [self.operand()]
            while self.peek() == ("op", ","):
                self.take()
                items.append(self.operand())
            self.take("op", ")")
            return ("in", left, items)
        return ("bool", left)

    def operand(self):
        k, v = self.peek()
        if k in ("str", "num"):
            self.take()
            return ("lit", v)
        if k == "word" and v.lower() == "null":
            self.take()
            return ("lit", None)
        if k == "word" and self.peek(1) == ("op", "("):
            self.take()
            self.take("op", "(")
            args = []
            if self.peek() != ("op", ")"):
                args.append(self.operand_or_expr())
                while self.peek() == ("op", ","):
                    self.take()
                    args.append(self.operand_or_expr())
            self.take("op", ")")
            return ("call", v.lower(), args)
        if k == "word":
            self.take()
            return ("col", v)
        raise SyntaxError(f"unexpected {k} {v!r}")

    def operand_or_expr(self):
        return self.operand()


# ---------------------------------------------------------------- evaluation

def _and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def _or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def _cidr(net, ip):
    if ip is None:
        return None
    try:
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def evaluate(node, row: dict, dialect: str):
    ci = dialect == "xql"  # case_sensitive = false

    def norm(x):
        return x.lower() if ci and isinstance(x, str) else x

    def val(n):
        kind = n[0]
        if kind == "lit":
            return n[1]
        if kind == "col":
            return row.get(n[1])
        if kind == "call":
            name, args = n[1], [val(a) for a in n[2]]
            if name == "lower":
                return None if args[0] is None else str(args[0]).lower()
            if name == "isnotnull":
                return args[0] is not None
            if name == "match":
                return None if args[0] is None else re.search(args[1], str(args[0])) is not None
            if name == "cidrmatch":
                return _cidr(args[0], args[1])
            if name == "incidr":
                return _cidr(args[1], args[0])
            raise NameError(name)
        return ev(n)

    def ev(n):
        kind = n[0]
        if kind == "and":
            return _and(ev(n[1]), ev(n[2]))
        if kind == "or":
            return _or(ev(n[1]), ev(n[2]))
        if kind == "not":
            r = ev(n[1])
            return None if r is None else not r
        if kind == "bool":
            return val(n[1])
        if kind in ("=", "!="):
            a, b = val(n[1]), val(n[2])
            if b is None:  # x = null / x != null
                return (a is None) if kind == "=" else (a is not None)
            if a is None:
                return None
            eq = norm(a) == norm(b)
            return eq if kind == "=" else not eq
        if kind == "~=":
            a = val(n[1])
            return None if a is None else re.search(val(n[2]), str(a)) is not None
        if kind == "contains":
            a = val(n[1])
            return None if a is None else norm(val(n[2])) in norm(str(a))
        if kind == "in":
            a = val(n[1])
            return None if a is None else norm(a) in [norm(val(x)) for x in n[2]]
        return val(n)

    return ev(node)


def xql_filter_line(query: str) -> str:
    """The rule-specific filter: the second '| filter' stage."""
    stages = [s.strip() for s in query.split("\n| ")]
    filters = [s[len("filter "):] for s in stages if s.startswith("filter ")]
    return filters[-1]


def spl_where_line(query: str) -> str:
    for line in query.splitlines():
        if line.startswith("| where "):
            return line[len("| where "):]
    raise ValueError("no where clause")


def run(query: str, dialect: str, row: dict) -> bool:
    text = xql_filter_line(query) if dialect == "xql" else spl_where_line(query)
    return evaluate(Parser(text, dialect).parse(), row, dialect) is True
