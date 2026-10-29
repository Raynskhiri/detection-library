config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name in ("net.exe", "net1.exe") and (action_process_image_command_line contains "localgroup" and action_process_image_command_line contains "administrators" and action_process_image_command_line contains "/add")) or (action_process_image_command_line contains "add-localgroupmember" and action_process_image_command_line contains "administrators")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
