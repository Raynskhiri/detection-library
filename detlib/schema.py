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
}
