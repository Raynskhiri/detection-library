config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter ((action_process_image_command_line contains "certify" and action_process_image_command_line ~= "(?i)\\b(find|request|download|cas|pkiobjects)\\b") or (action_process_image_command_line contains "certipy" and action_process_image_command_line ~= "(?i)\\b(find|req|auth|shadow|forge|ca)\\b")) or (action_process_image_command_line contains "forgecert" or action_process_image_command_line contains "/onbehalfof:" or action_process_image_command_line contains "/altname:" or action_process_image_command_line contains "-upn ")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
