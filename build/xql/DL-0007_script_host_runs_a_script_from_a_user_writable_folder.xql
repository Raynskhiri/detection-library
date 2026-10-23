config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name in ("wscript.exe", "cscript.exe") and (action_process_image_command_line contains "\\appdata\\" or action_process_image_command_line contains "\\temp\\" or action_process_image_command_line contains "\\downloads\\" or action_process_image_command_line contains "\\users\\public\\" or action_process_image_command_line contains "\\desktop\\")) and action_process_image_command_line ~= "(?i)\\.(js|jse|vbs|vbe|wsf|wsh)\\b"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
