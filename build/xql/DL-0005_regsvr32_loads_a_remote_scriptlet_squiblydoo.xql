config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name = "regsvr32.exe" and (action_process_image_command_line contains "/i:http" or action_process_image_command_line contains "-i:http" or action_process_image_command_line contains "scrobj.dll" or action_process_image_command_line contains "/i:\\\\" or action_process_image_command_line contains "-i:\\\\")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
