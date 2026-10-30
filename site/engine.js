// Detection engine for the browser. Same semantics as detlib/rule.py:matches().
// CI runs this file in Node against every rule's test events and the intrusion
// scenario, so the playground can never drift from the Python reference.

// ---------------------------------------------------------------- matching

function ipv4ToInt(ip) {
  const parts = String(ip).trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function inCidr(ip, cidr) {
  const [net, bitsRaw] = cidr.split("/");
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(net);
  if (a === null || b === null) return false;
  if (bits === 0) return true;
  const size = 2 ** (32 - bits);
  return Math.floor(a / size) === Math.floor(b / size);
}

const regexCache = new Map();
function rx(pattern) {
  if (!regexCache.has(pattern)) regexCache.set(pattern, new RegExp(pattern, "i"));
  return regexCache.get(pattern);
}

function valueMatches(op, actual, expected) {
  const a = actual.toLowerCase();
  const e = expected.toLowerCase();
  switch (op) {
    case "eq": return a === e;
    case "contains": return a.includes(e);
    case "startswith": return a.startsWith(e);
    case "endswith": return a.endsWith(e);
    case "re": return rx(expected).test(actual);
    case "cidr": return inCidr(actual, expected);
    default: throw new Error(`unknown op ${op}`);
  }
}

function predicateMatches(p, event) {
  const raw = event[p.field];
  if (raw === undefined || raw === null) return false;
  const actual = String(raw);
  const hits = p.values.map((v) => valueMatches(p.op, actual, v));
  return p.all ? hits.every(Boolean) : hits.some(Boolean);
}

function evalNode(node, rule, event) {
  if ("sel" in node) return rule.selections[node.sel].every((p) => predicateMatches(p, event));
  if ("not" in node) return !evalNode(node.not, rule, event);
  if ("and" in node) return evalNode(node.and[0], rule, event) && evalNode(node.and[1], rule, event);
  if ("or" in node) return evalNode(node.or[0], rule, event) || evalNode(node.or[1], rule, event);
  throw new Error("bad condition node");
}

export function matches(rule, event) {
  return evalNode(rule.condition, rule, event);
}

/** Which selections were true for this event, for the "why it fired" view. */
export function explain(rule, event) {
  const out = {};
  for (const [name, preds] of Object.entries(rule.selections)) {
    out[name] = preds.map((p) => ({ ...p, hit: predicateMatches(p, event), actual: event[p.field] }));
  }
  return out;
}

export function evaluate(rules, logsource, event) {
  return rules.filter((r) => r.logsource === logsource && matches(r, event));
}

// ---------------------------------------------------------------- input parsing

const basename = (path) => {
  if (!path) return path;
  const parts = String(path).split(/[\\/]/);
  return parts[parts.length - 1];
};

const XML_DATA = /<Data\s+Name=["']([^"']+)["']\s*(?:\/>|>([\s\S]*?)<\/Data>)/gi;
const XML_EID = /<EventID[^>]*>\s*(\d+)\s*<\/EventID>/i;
const XML_PROVIDER = /<Provider\s+Name=["']([^"']+)["']/i;

function xmlUnescape(s) {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&amp;/g, "&");
}

const SYSMON = {
  1: "process_creation", 3: "network_connection", 11: "file_event",
  13: "registry_set", 22: "dns_query",
};

// Windows event log data fields (Security, PowerShell 4104): portable name -> EventData name.
// tests/test_engine_js.py checks this table against detlib/schema.py.
export const WINEVENT_DATA = {
  "subject.user": "SubjectUserName", "target.user": "TargetUserName", "service.name": "ServiceName",
  "ticket.encryption": "TicketEncryptionType", "ticket.transmitted_services": "TransmittedServices",
  "preauth.type": "PreAuthType", "object.class": "ObjectClass", "object.dn": "ObjectDN",
  "object.type": "ObjectType", "object.properties": "Properties", "attribute.name": "AttributeLDAPDisplayName",
  "attribute.value": "AttributeValue", "member.name": "MemberName", "logon.type": "LogonType",
  "logon.process": "LogonProcessName", "auth.package": "AuthenticationPackageName", "source.ip": "IpAddress",
  "share.name": "ShareName", "share.target": "RelativeTargetName", "cert.requester": "Requester",
  "cert.attributes": "Attributes", "cert.subject": "Subject", "sid_history": "SidHistory",
  "script.text": "ScriptBlockText",
};

/** Map a Windows Security or PowerShell event (XML or JSON field names) to the portable model. */
export function fromWindowsEvent(eventId, d) {
  const ev = { "event.id": String(eventId) };
  for (const [portable, name] of Object.entries(WINEVENT_DATA)) {
    const v = d[name];
    if (v !== undefined && v !== null && v !== "") ev[portable] = String(v);
  }
  return { logsource: "windows_event", event: ev };
}

/** Map Sysmon field names (from XML or JSON) to the portable model. */
export function fromSysmon(eventId, d, provider = "") {
  const logsource = SYSMON[eventId];
  if (!logsource || (provider && !/sysmon/i.test(provider))) {
    if (eventId >= 1100) return fromWindowsEvent(eventId, d);
    throw new Error(`Sysmon event ID ${eventId} is not covered (supported: 1, 3, 11, 13, 22, or a Windows Security / PowerShell event)`);
  }
  const ev = {};
  const set = (k, v) => { if (v !== undefined && v !== null && v !== "") ev[k] = String(v); };
  set("process.path", d.Image);
  set("process.name", basename(d.Image));
  set("user", d.User);
  if (logsource === "process_creation") {
    set("process.command_line", d.CommandLine);
    set("parent.path", d.ParentImage);
    set("parent.name", basename(d.ParentImage));
    set("parent.command_line", d.ParentCommandLine);
  } else if (logsource === "network_connection") {
    set("net.remote_ip", d.DestinationIp);
    set("net.remote_port", d.DestinationPort);
  } else if (logsource === "dns_query") {
    set("dns.query", d.QueryName);
  } else if (logsource === "registry_set") {
    if (d.TargetObject) {
      const i = d.TargetObject.lastIndexOf("\\");
      set("registry.key", i >= 0 ? d.TargetObject.slice(0, i) : d.TargetObject);
      set("registry.value", i >= 0 ? d.TargetObject.slice(i + 1) : "");
    }
    set("registry.data", d.Details);
  } else if (logsource === "file_event") {
    set("file.path", d.TargetFilename);
    set("file.name", basename(d.TargetFilename));
  }
  return { logsource, event: ev };
}

export function parseSysmonXml(xml) {
  const m = XML_EID.exec(xml);
  if (!m) throw new Error("No <EventID> found. Paste the full event XML (Event Viewer, Details tab, XML View).");
  const data = {};
  for (const [, name, value] of xml.matchAll(XML_DATA)) data[name] = xmlUnescape((value || "").trim());
  const prov = XML_PROVIDER.exec(xml);
  return fromSysmon(Number(m[1]), data, prov ? prov[1] : "");
}

export function parseJson(text, fieldNames) {
  const obj = JSON.parse(text);
  if (obj.EventID !== undefined || obj.EventCode !== undefined || obj.event_id !== undefined) {
    return fromSysmon(Number(obj.EventID ?? obj.EventCode ?? obj.event_id), obj);
  }
  if (obj.logsource && obj.event) return { logsource: obj.logsource, event: obj.event };
  if (obj.activityDisplayName || (obj.operationName && obj.properties && obj.properties.targetResources)) {
    return { logsource: "entra_audit", event: fromEntraAudit(obj) };
  }
  if (obj.appId || (obj.properties && obj.properties.appId)) {
    return { logsource: "entra_sp_signin", event: fromEntraSignIn(obj) };
  }
  const keys = Object.keys(obj);
  const guess = Object.entries(fieldNames).find(([, fields]) => keys.every((k) => fields.includes(k)) &&
    keys.some((k) => !["process.name", "process.path", "process.command_line", "user"].includes(k)));
  return { logsource: guess ? guess[0] : "process_creation", event: obj };
}

function compact(ev) {
  return Object.fromEntries(Object.entries(ev).filter(([, v]) => v !== undefined && v !== null && v !== ""));
}

/** An Entra ID audit record, as Microsoft Graph (directoryAudit) or Azure Monitor (properties.*) returns it. */
export function fromEntraAudit(obj) {
  const p = obj.properties || obj;
  const by = p.initiatedBy || {};
  const targets = p.targetResources || [];
  const first = targets[0] || {};
  const details = [];
  for (const t of targets) {
    if (t.displayName) details.push(t.displayName);
    for (const m of t.modifiedProperties || []) if (m.newValue) details.push(m.newValue);
  }
  const ua = (p.additionalDetails || []).find((d) => /^user-agent$/i.test(d.key || ""));
  return compact({
    "audit.operation": obj.activityDisplayName || obj.operationName,
    "audit.category": p.category || obj.category,
    "audit.result": p.result || obj.resultType,
    "initiator.app": by.app && by.app.displayName,
    "initiator.app_id": by.app && by.app.appId,
    "initiator.user": by.user && by.user.userPrincipalName,
    "target.type": first.type,
    "target.name": first.displayName,
    "target.details": details.join(" | "),
    "user_agent": ua && ua.value,
  });
}

/** An Entra ID service principal sign-in, as Microsoft Graph or Azure Monitor returns it. */
export function fromEntraSignIn(obj) {
  const p = obj.properties || obj;
  const status = p.status || {};
  return compact({
    "signin.app_id": p.appId,
    "signin.app_name": p.appDisplayName,
    "signin.sp_name": p.servicePrincipalName,
    "signin.ip": p.ipAddress || obj.callerIpAddress,
    "user_agent": p.userAgent,
    "signin.resource": p.resourceDisplayName,
    "signin.error_code": status.errorCode === undefined ? undefined : String(status.errorCode),
    "signin.type": Array.isArray(p.signInEventTypes) ? p.signInEventTypes.join(",") : obj.category,
  });
}

/** A FortiGate key=value log line. Keeps the fields the fortigate rules know (fg.*). */
export function parseFortiGate(line, fieldNames) {
  const known = new Set((fieldNames && fieldNames.fortigate) || []);
  const event = {};
  for (const [, key, quoted, bare] of line.matchAll(/\b([a-z_]+)=(?:"([^"]*)"|(\S*))/g)) {
    const name = `fg.${key}`;
    if ((!known.size || known.has(name)) && !(name in event)) event[name] = quoted ?? bare;
  }
  return { logsource: "fortigate", event };
}

/** A bare command line, as an analyst would copy it from an alert. */
export function parseCommandLine(line, parent) {
  const cmd = line.trim();
  let first;
  if (cmd.startsWith('"')) first = cmd.slice(1, cmd.indexOf('"', 1) > 0 ? cmd.indexOf('"', 1) : undefined);
  else first = cmd.split(/\s+/)[0];
  let name = basename(first).toLowerCase();
  if (name && !name.includes(".")) name += ".exe";
  const event = { "process.name": name, "process.command_line": cmd };
  if (first.includes("\\")) event["process.path"] = first;
  if (parent) event["parent.name"] = parent.toLowerCase();
  return { logsource: "process_creation", event };
}

export function autoParse(text, fieldNames, parent) {
  const t = text.trim();
  if (!t) return null;
  if (t.startsWith("<")) return { kind: "Event XML", ...parseSysmonXml(t) };
  // A web server error log line, for example "[Tue Oct 20 ...] [php:error] [pid 1] [client ...] PHP Fatal error: ..."
  if (/^\[[A-Z][a-z]{2} [A-Z][a-z]{2} /.test(t) || /^\[\d{4}-\d{2}-\d{2}/.test(t)) {
    return { kind: "Web server log", logsource: "web_server_error", event: { "log.message": t } };
  }
  // A FortiGate syslog line: key=value pairs with a logid, for example 'logid="0100044547" type="event" ...'
  if (/\blogid="?\d+/.test(t)) return { kind: "FortiGate log", ...parseFortiGate(t, fieldNames) };
  if (t.startsWith("{")) return { kind: "JSON", ...parseJson(t, fieldNames) };
  return { kind: "Command line", ...parseCommandLine(t, parent) };
}
