config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_remote_ip != null
| filter action_remote_port in (9001, 9030, 9050, 9051, 9150) and not ((actor_process_image_name != null and actor_process_image_name in ("tor.exe", "firefox.exe")))
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, action_remote_ip, action_remote_port
| sort desc _time
| limit 1000
