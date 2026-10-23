// Reads [{rule, event}] as JSON on stdin, prints [true|false,...]. Used by tests/test_engine_js.py.
import { readFileSync } from "node:fs";
import { matches } from "./engine.js";
const { rules } = JSON.parse(readFileSync(new URL("data/rules.json", import.meta.url)));
const byId = Object.fromEntries(rules.map((r) => [r.id, r]));
const cases = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(cases.map((c) => matches(byId[c.rule], c.event))));
