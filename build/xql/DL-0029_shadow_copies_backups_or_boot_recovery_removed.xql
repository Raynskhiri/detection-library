config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter ((((action_process_image_name = "vssadmin.exe" and action_process_image_command_line ~= "(?i)(delete\\s+shadows|resize\\s+shadowstorage)") or (action_process_image_name = "wmic.exe" and (action_process_image_command_line contains "shadowcopy" and action_process_image_command_line contains "delete"))) or (action_process_image_name in ("powershell.exe", "pwsh.exe") and (action_process_image_command_line contains "win32_shadowcopy" and action_process_image_command_line contains "delete"))) or (action_process_image_name = "wbadmin.exe" and action_process_image_command_line ~= "(?i)delete\\s+(catalog|systemstatebackup|backup)")) or (action_process_image_name = "bcdedit.exe" and (action_process_image_command_line contains "recoveryenabled no" or action_process_image_command_line contains "bootstatuspolicy ignoreallfailures"))
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
