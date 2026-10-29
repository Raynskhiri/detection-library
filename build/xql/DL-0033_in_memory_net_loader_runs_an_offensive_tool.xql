config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter ((action_process_image_command_line contains "-path" and action_process_image_command_line contains "-args") and action_process_image_command_line ~= "(?i)(https?://|\\\\\\\\|rubeus|safetykatz|certify|sharphound|seatbelt|standin|sharpup|winpeas)") or (action_process_image_command_line contains "netloader" or action_process_image_command_line contains "loader.exe -path")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
