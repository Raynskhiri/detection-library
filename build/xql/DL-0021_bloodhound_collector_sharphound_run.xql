config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name = "sharphound.exe" or (action_process_image_command_line contains "sharphound" or action_process_image_command_line contains "invoke-bloodhound" or action_process_image_command_line contains "collectionmethod" or action_process_image_command_line contains "bloodhound.py" or action_process_image_command_line contains "--zipfilename")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
