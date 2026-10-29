config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_command_line contains "add-domainobjectacl" or action_process_image_command_line contains "set-domainobject" or action_process_image_command_line contains "add-domaingroupmember" or action_process_image_command_line contains "set-domainuserpassword" or action_process_image_command_line contains "set-domainobjectowner" or action_process_image_command_line contains "add-objectacl") or (action_process_image_command_line contains "standin" and action_process_image_command_line ~= "(?i)(--computer\\b.*--sid|--group\\b.*--add|--setuserrights|--grant|--spn|--setpassword)")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
