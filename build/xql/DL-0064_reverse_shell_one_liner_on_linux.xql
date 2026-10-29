config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_command_line ~= "(?i)(/dev/(tcp|udp)/|\\bbash\\s+-i\\b|\\bnc(at)?\\b.*\\s-(e|c)\\s|mkfifo\\s|socat\\b.*exec:|socket\\.socket\\(|pty\\.spawn\\(|IO::Socket::INET)"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
