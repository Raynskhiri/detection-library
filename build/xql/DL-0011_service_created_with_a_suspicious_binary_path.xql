config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name = "sc.exe" and action_process_image_command_line contains " create ") and (action_process_image_command_line contains "\\appdata\\" or action_process_image_command_line contains "\\temp\\" or action_process_image_command_line contains "\\users\\public\\" or action_process_image_command_line contains "\\programdata\\" or action_process_image_command_line contains "powershell" or action_process_image_command_line contains "cmd /c" or action_process_image_command_line contains "cmd.exe /c" or action_process_image_command_line contains "%comspec%" or action_process_image_command_line contains "mshta" or action_process_image_command_line contains "rundll32" or action_process_image_command_line contains "regsvr32")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
