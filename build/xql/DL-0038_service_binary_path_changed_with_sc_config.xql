config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name = "sc.exe" and (action_process_image_command_line contains "config" and action_process_image_command_line contains "binpath")) or (action_process_image_command_line contains "invoke-serviceabuse" or action_process_image_command_line contains "write-servicebinary" or action_process_image_command_line contains "install-servicebinary")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
