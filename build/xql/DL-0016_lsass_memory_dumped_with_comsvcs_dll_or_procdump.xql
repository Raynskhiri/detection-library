config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter ((action_process_image_name = "rundll32.exe" and action_process_image_command_line contains "comsvcs") and action_process_image_command_line ~= "(?i)(minidump|#\\+?0*24\\b)") or (action_process_image_name in ("procdump.exe", "procdump64.exe", "procdump64a.exe") and action_process_image_command_line contains "lsass")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
