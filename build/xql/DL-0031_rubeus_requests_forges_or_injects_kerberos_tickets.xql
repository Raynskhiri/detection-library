config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_command_line ~= "(?i)\\b(asktgt|asktgs|s4u|ptt|tgtdeleg|golden|silver|diamond|monitor|harvest|dump|triage|createnetonly|renew)\\b" and ((action_process_image_command_line contains "/rc4:" or action_process_image_command_line contains "/aes256:" or action_process_image_command_line contains "/aes128:" or action_process_image_command_line contains "/ticket:" or action_process_image_command_line contains "/impersonateuser:" or action_process_image_command_line contains "/msdsspn:" or action_process_image_command_line contains "/certificate:" or action_process_image_command_line contains "/krbkey:" or action_process_image_command_line contains "/ptt" or action_process_image_command_line contains "/nowrap" or action_process_image_command_line contains "/interval:") or action_process_image_command_line contains "rubeus")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
