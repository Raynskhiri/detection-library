config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name = "wevtutil.exe" and action_process_image_command_line ~= "(?i)\\s(cl|clear-log)\\s") or (action_process_image_name in ("powershell.exe", "pwsh.exe") and (action_process_image_command_line contains "clear-eventlog" or action_process_image_command_line contains "remove-eventlog" or action_process_image_command_line contains "clearlog"))
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
