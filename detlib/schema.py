"""Log sources and the field model shared by every backend.

A rule uses portable field names (``process.name``, ``dns.query``, ...). Each backend
maps them to its own schema: Cortex XDR ``xdr_data`` for XQL, Sysmon through the
Splunk Add-on for Microsoft Sysmon for SPL.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "all"}


@dataclass(frozen=True)
class Field:
    xql: str
    spl: str
    numeric: bool = False


@dataclass(frozen=True)
class LogSource:
    name: str
    description: str
    xql_filter: str
    spl_base: str
    spl_evals: tuple[str, ...]
    fields: dict[str, Field] = field(default_factory=dict)
    xql_columns: tuple[str, ...] = ()
    spl_columns: tuple[str, ...] = ()
    # XQL ``alter`` expressions run before the rule filter (for example to pull
    # named values out of a Windows event's data fields).
    xql_alters: tuple[str, ...] = ()
    # Most sources live in xdr_data. Logs sent through an XDR Collector or broker land in their own dataset.
    xql_dataset: str = "xdr_data"


def _basename(src: str, dst: str) -> str:
    # Last path segment, lower-cased. Sysmon only ships full paths.
    return f'{dst}=lower(mvindex(split({src},"\\\\"),-1))'


PROCESS_FIELDS = {
    "process.name": Field("action_process_image_name", "process_name"),
    "process.path": Field("action_process_image_path", "Image"),
    "process.command_line": Field("action_process_image_command_line", "CommandLine"),
    "parent.name": Field("actor_process_image_name", "parent_name"),
    "parent.path": Field("actor_process_image_path", "ParentImage"),
    "parent.command_line": Field("actor_process_command_line", "ParentCommandLine"),
    "user": Field("actor_effective_username", "User"),
}

# For non-process events the "process" is the one that acted (the actor).
ACTOR_FIELDS = {
    "process.name": Field("actor_process_image_name", "process_name"),
    "process.path": Field("actor_process_image_path", "Image"),
    "process.command_line": Field("actor_process_command_line", "CommandLine"),
    "user": Field("actor_effective_username", "User"),
}

# Windows event log data fields (Security, PowerShell Operational). Each portable name maps
# to the EventData name Windows writes. Cortex XDR keeps them in action_evtlog_data_fields;
# the Splunk Add-on for Windows (XmlWinEventLog) extracts them under the same names.
WINEVENT_DATA = {
    "subject.user": "SubjectUserName",
    "target.user": "TargetUserName",
    "service.name": "ServiceName",
    "ticket.encryption": "TicketEncryptionType",
    "ticket.transmitted_services": "TransmittedServices",
    "preauth.type": "PreAuthType",
    "object.class": "ObjectClass",
    "object.dn": "ObjectDN",
    "object.type": "ObjectType",
    "object.properties": "Properties",
    "attribute.name": "AttributeLDAPDisplayName",
    "attribute.value": "AttributeValue",
    "member.name": "MemberName",
    "logon.type": "LogonType",
    "logon.process": "LogonProcessName",
    "auth.package": "AuthenticationPackageName",
    "source.ip": "IpAddress",
    "share.name": "ShareName",
    "share.target": "RelativeTargetName",
    "cert.requester": "Requester",
    "cert.attributes": "Attributes",
    "cert.subject": "Subject",
    "sid_history": "SidHistory",
    "script.text": "ScriptBlockText",
}


# FortiGate event, VPN and traffic logs (key=value syslog). Each portable name maps to the
# FortiOS field. In Cortex XDR the Broker VM syslog applet lands them in fortinet_fortigate_raw;
# the alters below pull each field out of _raw_log so the rules work even when the dataset was
# ingested without the Fortinet parser. The Fortinet FortiGate Add-on for Splunk extracts the
# same names. Fields that can hold spaces (logdesc, msg, cfgattr) are always quoted by FortiOS.
FORTIGATE_TOKENS = ("logid", "type", "subtype", "action", "status", "user", "srcip", "dstip", "dstport",
                    "ui", "method", "cfgpath", "cfgobj", "tunneltype", "remip", "reason", "devname")
FORTIGATE_QUOTED = ("logdesc", "msg", "cfgattr")


def _fg_alter(name: str) -> str:
    if name in FORTIGATE_QUOTED:
        rx = f'\\\\b{name}=\\"([^\\"]*)\\"'
    else:
        rx = f'\\\\b{name}=\\"?([^\\"\\\\s]*)'
    expr = f'arrayindex(regextract(_raw_log, "{rx}"), 0)'
    if name == "dstport":
        expr = f"to_integer({expr})"
    return f"fg_{name} = {expr}"


FORTIGATE_FIELDS = {
    f"fg.{n}": Field(f"fg_{n}", n, numeric=(n == "dstport"))
    for n in FORTIGATE_TOKENS + FORTIGATE_QUOTED
}


def _evt_alias(portable: str) -> str:
    return "evt_" + portable.replace(".", "_")


WINEVENT_FIELDS = {
    "event.id": Field("action_evtlog_event_id", "EventCode", numeric=True),
    **{k: Field(_evt_alias(k), v) for k, v in WINEVENT_DATA.items()},
}

SOURCES: dict[str, LogSource] = {
    "process_creation": LogSource(
        name="process_creation",
        description="A process started (Sysmon EID 1, XDR PROCESS_START)",
        xql_filter="event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START",
        spl_base="`sysmon` EventCode=1",
        spl_evals=(_basename("Image", "process_name"), _basename("ParentImage", "parent_name")),
        fields=PROCESS_FIELDS,
        xql_columns=("_time", "agent_hostname", "actor_effective_username", "actor_process_image_name",
                     "action_process_image_name", "action_process_image_command_line"),
        spl_columns=("_time", "host", "User", "ParentImage", "Image", "CommandLine"),
    ),
    "network_connection": LogSource(
        name="network_connection",
        description="An outbound network connection (Sysmon EID 3, XDR NETWORK)",
        xql_filter="event_type = ENUM.NETWORK and action_remote_ip != null",
        spl_base="`sysmon` EventCode=3",
        spl_evals=(_basename("Image", "process_name"),),
        fields={**ACTOR_FIELDS,
                "net.remote_ip": Field("action_remote_ip", "DestinationIp"),
                "net.remote_port": Field("action_remote_port", "DestinationPort", numeric=True)},
        xql_columns=("_time", "agent_hostname", "actor_process_image_name", "actor_process_command_line",
                     "action_remote_ip", "action_remote_port"),
        spl_columns=("_time", "host", "Image", "DestinationIp", "DestinationPort"),
    ),
    "dns_query": LogSource(
        name="dns_query",
        description="A DNS lookup (Sysmon EID 22, XDR NETWORK with dns_query_name)",
        xql_filter="event_type = ENUM.NETWORK and dns_query_name != null",
        spl_base="`sysmon` EventCode=22",
        spl_evals=(_basename("Image", "process_name"),),
        fields={**ACTOR_FIELDS, "dns.query": Field("dns_query_name", "QueryName")},
        xql_columns=("_time", "agent_hostname", "actor_process_image_name", "dns_query_name"),
        spl_columns=("_time", "host", "Image", "QueryName"),
    ),
    "registry_set": LogSource(
        name="registry_set",
        description="A registry value was written (Sysmon EID 13, XDR REGISTRY_SET_VALUE)",
        xql_filter="event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE",
        spl_base="`sysmon` EventCode=13",
        spl_evals=(_basename("Image", "process_name"),
                   'reg_key=replace(TargetObject,"\\\\\\\\[^\\\\\\\\]*$","")',
                   'reg_value=mvindex(split(TargetObject,"\\\\"),-1)'),
        fields={**ACTOR_FIELDS,
                "registry.key": Field("action_registry_key_name", "reg_key"),
                "registry.value": Field("action_registry_value_name", "reg_value"),
                "registry.data": Field("action_registry_data", "Details")},
        xql_columns=("_time", "agent_hostname", "actor_process_image_name", "action_registry_key_name",
                     "action_registry_value_name", "action_registry_data"),
        spl_columns=("_time", "host", "Image", "TargetObject", "Details"),
    ),
    "file_event": LogSource(
        name="file_event",
        description="A file was created or written (Sysmon EID 11, XDR FILE)",
        xql_filter="event_type = ENUM.FILE and event_sub_type in (ENUM.FILE_CREATE_NEW, ENUM.FILE_WRITE)",
        spl_base="`sysmon` EventCode=11",
        spl_evals=(_basename("Image", "process_name"), _basename("TargetFilename", "file_name")),
        fields={**ACTOR_FIELDS,
                "file.path": Field("action_file_path", "TargetFilename"),
                "file.name": Field("action_file_name", "file_name")},
        xql_columns=("_time", "agent_hostname", "actor_process_image_name", "action_file_path"),
        spl_columns=("_time", "host", "Image", "TargetFilename"),
    ),
    "web_server_error": LogSource(
        name="web_server_error",
        description="A line from the web server error log, including PHP errors (Apache error.log; "
                    "XDR Collector dataset apache_httpd_raw, Splunk sourcetype apache:error)",
        xql_filter="_raw_log != null",
        spl_base="`apache_error`",
        spl_evals=(),
        fields={"log.message": Field("_raw_log", "_raw")},
        xql_columns=("_time", "_raw_log"),
        spl_columns=("_time", "host", "_raw"),
        xql_dataset="apache_httpd_raw",
    ),
    "fortigate": LogSource(
        name="fortigate",
        description="A FortiGate log line: event/system (admin logins, config changes), event/vpn and traffic "
                    "(syslog to a Broker VM, XDR dataset fortinet_fortigate_raw; Splunk Fortinet FortiGate Add-on)",
        xql_filter="_raw_log != null",
        spl_base="`fortigate`",
        spl_evals=(),
        fields=FORTIGATE_FIELDS,
        xql_columns=("_time", "fg_devname", "fg_logid", "fg_user", "fg_srcip", "fg_ui", "fg_logdesc", "fg_msg"),
        spl_columns=("_time", "devname", "logid", "user", "srcip", "ui", "logdesc", "msg"),
        xql_alters=tuple(_fg_alter(n) for n in FORTIGATE_TOKENS + FORTIGATE_QUOTED),
        xql_dataset="fortinet_fortigate_raw",
    ),
    "windows_event": LogSource(
        name="windows_event",
        description="A Windows event log record: Security (4662, 4769, 5136, 4887...) or PowerShell 4104 "
                    "(XDR EVENT_LOG, Splunk Add-on for Windows)",
        xql_filter="event_type = ENUM.EVENT_LOG",
        spl_base="`wineventlog`",
        spl_evals=(),
        fields=WINEVENT_FIELDS,
        xql_columns=("_time", "agent_hostname", "action_evtlog_event_id", "evt_subject_user", "evt_target_user",
                     "action_evtlog_message"),
        spl_columns=("_time", "host", "EventCode", "SubjectUserName", "TargetUserName", "Message"),
        xql_alters=tuple(f'{_evt_alias(k)} = json_extract_scalar(action_evtlog_data_fields, "$.{v}")'
                         for k, v in WINEVENT_DATA.items()),
    ),
}
