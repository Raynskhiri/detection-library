config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_command_line contains "sekurlsa::" or action_process_image_command_line contains "lsadump::" or action_process_image_command_line contains "kerberos::" or action_process_image_command_line contains "token::elevate" or action_process_image_command_line contains "dpapi::" or action_process_image_command_line contains "privilege::debug" or action_process_image_command_line contains "crypto::" or action_process_image_command_line contains "invoke-mimikatz"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
