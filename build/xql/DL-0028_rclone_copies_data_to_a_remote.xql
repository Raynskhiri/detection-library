config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_command_line ~= "(?i)\\s(copy|copyto|sync|move)\\s" and (action_process_image_name = "rclone.exe" or (action_process_image_command_line contains "--multi-thread-streams" or action_process_image_command_line contains "--no-check-certificate" or action_process_image_command_line contains "--transfers" or action_process_image_command_line contains "--ignore-existing" or action_process_image_command_line contains "--max-age" or action_process_image_command_line contains "--auto-confirm"))
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
