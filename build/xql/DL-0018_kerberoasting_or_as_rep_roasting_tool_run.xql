config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_command_line contains "kerberoast" or action_process_image_command_line contains "asreproast" or action_process_image_command_line contains "get-domainspnticket" or action_process_image_command_line contains "request-spnticket" or action_process_image_command_line contains "getuserspns" or action_process_image_command_line contains "getnpusers" or action_process_image_command_line contains "/format:hashcat"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
