<h1 align="center">Detection Library</h1>

<p align="center">
  <b>Write a detection once. Get Cortex XDR XQL and Splunk SPL. Prove it with test events.</b><br>
  29 hunts for the things that actually show up in Windows intrusions, from the first macro to deleted shadow copies.
</p>

<p align="center">
  <a href="https://github.com/Raynskhiri/detection-library/actions/workflows/tests.yml"><img src="https://github.com/Raynskhiri/detection-library/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/rules-29-F97316" alt="29 rules">
  <img src="https://img.shields.io/badge/output-Cortex%20XQL%20%7C%20Splunk%20SPL-FA582D" alt="XQL and SPL">
  <img src="https://img.shields.io/badge/mapped%20to-MITRE%20ATT%26CK-C8102E" alt="MITRE ATT&CK">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT">
</p>

---

## Why this exists

Most query collections are a folder of strings. Nobody knows if they still work, what they
miss, or what to do when one fires. Every rule here comes with four things:

1. **One source of truth.** A short YAML rule with portable field names.
2. **Two native outputs.** Ready-to-paste XQL for Cortex XDR (`xdr_data`) and SPL for Splunk with Sysmon.
3. **Proof.** Events that must fire and events that must not. CI runs the rule *and the compiled XQL and SPL* against them.
4. **What to do next.** Triage steps and the false positives you will actually meet.

## One rule, both languages

```yaml
id: DL-0016
title: LSASS memory dumped with comsvcs.dll or ProcDump
attack: [T1003.001]
logsource: process_creation
detection:
  comsvcs:
    process.name: rundll32.exe
    process.command_line|contains: comsvcs
  minidump:
    process.command_line|re: '(minidump|#\+?0*24\b)'
  procdump:
    process.name: [procdump.exe, procdump64.exe, procdump64a.exe]
    process.command_line|contains: lsass
  condition: (comsvcs and minidump) or procdump
tests:
  match:
    - process.name: rundll32.exe
      process.command_line: 'rundll32 comsvcs.dll #24 624 C:\Users\Public\x.bin full'
  no_match:
    - process.name: rundll32.exe
      process.command_line: 'rundll32.exe comsvcs.dll,DllRegisterServer'
```

becomes

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name = "rundll32.exe" and action_process_image_command_line contains "comsvcs"
          and action_process_image_command_line ~= "(?i)(minidump|#\\+?0*24\\b)")
      or (action_process_image_name in ("procdump.exe", "procdump64.exe", "procdump64a.exe")
          and action_process_image_command_line contains "lsass")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
```

and

```
`sysmon` EventCode=1
| eval process_name=lower(mvindex(split(Image,"\\"),-1)), parent_name=lower(mvindex(split(ParentImage,"\\"),-1))
| where (lower(process_name)="rundll32.exe" AND match(CommandLine, "(?i)comsvcs") AND match(CommandLine, "(?i)(minidump|#\\+?0*24\\b)"))
     OR ((lower(process_name)="procdump.exe" OR ...) AND match(CommandLine, "(?i)lsass"))
| table _time host User ParentImage Image CommandLine
```

(Wrapped here for reading; the generated files are in [`build/`](build) and on each rule's page.)

## The rules

<!-- rules:start -->
| ID | Detection | ATT&CK | Tactic | Severity |
|---|---|---|---|---|
| [DL-0001](docs/rules/DL-0001.md) | PowerShell with an encoded command | T1059.001, T1027 | execution | high |
| [DL-0002](docs/rules/DL-0002.md) | PowerShell download cradle that runs what it fetched | T1059.001, T1105 | execution | high |
| [DL-0003](docs/rules/DL-0003.md) | Office application starts a shell or script host | T1204.002, T1566.001 | execution | high |
| [DL-0004](docs/rules/DL-0004.md) | mshta runs a remote HTA or inline script | T1218.005 | execution | high |
| [DL-0005](docs/rules/DL-0005.md) | regsvr32 loads a remote scriptlet (Squiblydoo) | T1218.010 | execution | high |
| [DL-0006](docs/rules/DL-0006.md) | rundll32 runs script or loads from a URL | T1218.011 | execution | high |
| [DL-0007](docs/rules/DL-0007.md) | Script host runs a script from a user-writable folder | T1059.005, T1059.007 | execution | medium |
| [DL-0008](docs/rules/DL-0008.md) | WMIC creates a process, locally or on another host | T1047 | execution | medium |
| [DL-0009](docs/rules/DL-0009.md) | Run key points to a user-writable path or a script host | T1547.001 | persistence | medium |
| [DL-0010](docs/rules/DL-0010.md) | Scheduled task created to run a script host or a file in a user-writable path | T1053.005 | persistence | medium |
| [DL-0011](docs/rules/DL-0011.md) | Service created with a suspicious binary path | T1543.003, T1569.002 | persistence | high |
| [DL-0012](docs/rules/DL-0012.md) | Microsoft Defender disabled or given exclusions | T1562.001 | defense-evasion | high |
| [DL-0013](docs/rules/DL-0013.md) | Windows event logs cleared from the command line | T1070.001 | defense-evasion | high |
| [DL-0014](docs/rules/DL-0014.md) | Windows system process name running from the wrong folder | T1036.005 | defense-evasion | high |
| [DL-0015](docs/rules/DL-0015.md) | certutil used to download or decode a file | T1105, T1140 | defense-evasion | high |
| [DL-0016](docs/rules/DL-0016.md) | LSASS memory dumped with comsvcs.dll or ProcDump | T1003.001 | credential-access | critical |
| [DL-0017](docs/rules/DL-0017.md) | SAM, SYSTEM, SECURITY hives or NTDS.dit copied for offline cracking | T1003.002, T1003.003, T1003.004 | credential-access | critical |
| [DL-0018](docs/rules/DL-0018.md) | Kerberoasting or AS-REP roasting tool run | T1558.003, T1558.004 | credential-access | high |
| [DL-0019](docs/rules/DL-0019.md) | Mimikatz modules on the command line | T1003.001, T1003.006, T1550.002, T1558.001 | credential-access | critical |
| [DL-0020](docs/rules/DL-0020.md) | Domain admin groups, domain controllers or trusts enumerated with built-in tools | T1069.002, T1087.002, T1482, T1018 | discovery | medium |
| [DL-0021](docs/rules/DL-0021.md) | BloodHound collector (SharpHound) run | T1087.002, T1069.002, T1482 | discovery | high |
| [DL-0022](docs/rules/DL-0022.md) | PsExec service runs a command | T1569.002, T1021.002 | lateral-movement | medium |
| [DL-0023](docs/rules/DL-0023.md) | Impacket wmiexec or smbexec style command | T1047, T1021.002, T1569.002 | lateral-movement | high |
| [DL-0024](docs/rules/DL-0024.md) | Command started through WinRM remoting | T1021.006 | lateral-movement | medium |
| [DL-0025](docs/rules/DL-0025.md) | Living-off-the-land binary connects to the internet | T1105, T1218 | command-and-control | medium |
| [DL-0026](docs/rules/DL-0026.md) | Connection to common Tor ports from a non-Tor process | T1090.003 | command-and-control | medium |
| [DL-0027](docs/rules/DL-0027.md) | Script host or LOLBin looks up a paste site, file drop or tunnel service | T1102, T1105, T1572 | command-and-control | medium |
| [DL-0028](docs/rules/DL-0028.md) | rclone copies data to a remote | T1567.002, T1048 | exfiltration | high |
| [DL-0029](docs/rules/DL-0029.md) | Shadow copies, backups or boot recovery removed | T1490 | impact | critical |
<!-- rules:end -->

ATT&CK Navigator layer: [`build/attack-navigator-layer.json`](build/attack-navigator-layer.json). Open it at
[mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) to see the coverage map.

## Use it

**Cortex XDR:** open a rule page in [`docs/rules`](docs/rules), copy the XQL into *Query Builder → XQL Search*,
or take the file from [`build/xql`](build/xql). Good candidates for BIOCs or scheduled correlation rules once tuned.

**Splunk:** the SPL uses a `sysmon` macro so it fits any index layout. Define it once:

```
[sysmon]
definition = index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

(Settings → Advanced search → Search macros. Field names follow the Splunk Add-on for Sysmon.)

**From the command line:**

```bash
pip install -r requirements.txt
python -m detlib show DL-0029       # print one rule in both languages
python -m detlib test               # run every rule against its test events
python -m detlib build              # regenerate build/, docs/rules/ and the table above
```

## Write a rule

Copy any file in [`rules/`](rules), give it the next ID, and fill in:

| Key | What goes in it |
|---|---|
| `logsource` | `process_creation`, `network_connection`, `dns_query`, `registry_set` or `file_event` |
| `detection` | named selections plus a `condition` using `and`, `or`, `not` and parentheses |
| field modifiers | none (equals), `contains`, `startswith`, `endswith`, `re`, `cidr`, and `all` to require every value |
| `tests` | at least one `match` and one `no_match` event, using the same portable field names |
| `triage`, `false_positives` | what an analyst should do, and what will fool the rule |

Inside a selection every field must match. A list of values means *any of them*. Matching is case-insensitive.
Field names per log source are in [`detlib/schema.py`](detlib/schema.py).

## How it is tested

* **Reference matcher.** Each rule runs against its own events (`python -m detlib test`): 29 rules, 112 events.
* **Compiled output, executed.** The test suite carries a small interpreter for the subset of XQL and SPL the
  compiler emits ([`tests/interp.py`](tests/interp.py)). Every test event is mapped to XDR and Sysmon column names
  and run through the *generated* query. Both must agree with the reference.
* **Missing fields.** Each field is removed from each event in turn. XQL and SPL drop a row when a filter is null,
  so a careless `not filter` would silently hide events that lack the field. The compiler adds null guards, and the
  tests prove they work.
* **Mutation-checked.** Removing the null guard, the `(?i)` flag or the string escaping makes the suite fail.
* **Drift.** CI fails if `build/` or `docs/` are out of date with the rules.

**Honest limit:** the interpreter is not Cortex and not Splunk. The generated queries have not yet been run
against a live XDR tenant or Splunk instance from this repository. If one errors on your platform, please open
an issue with the message.

## Related

* [Maghreb Threat Watch](https://github.com/Raynskhiri/maghreb-threat-watch): daily lookalike-domain watch for North
  African brands. It publishes its own XQL and SPL hunts for the domains it finds.
* [MalwareScope](https://github.com/Raynskhiri/MalwareScope): sandbox and ML malware analysis. Its behavioural
  scorer looks at the same techniques these rules hunt for.

## Author

**Rayen Skhiri**, SOC analyst and AppSec engineer · [rayenskhiri.online](https://rayenskhiri.online) ·
[LinkedIn](https://www.linkedin.com/in/rayen-skhiri)

MIT licensed. Test events are synthetic: the IPs are from documentation ranges and the names are made up.
