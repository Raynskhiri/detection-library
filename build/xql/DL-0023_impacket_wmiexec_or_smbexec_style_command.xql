config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name = "cmd.exe" and action_process_image_command_line ~= "(?i)\\\\\\\\127\\.0\\.0\\.1\\\\admin\\$\\\\__\\d"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
