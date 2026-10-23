config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter ((action_process_image_name in ("powershell.exe", "pwsh.exe") and (action_process_image_command_line contains "set-mppreference" or action_process_image_command_line contains "add-mppreference")) and (action_process_image_command_line contains "disablerealtimemonitoring" or action_process_image_command_line contains "disablebehaviormonitoring" or action_process_image_command_line contains "disableioavprotection" or action_process_image_command_line contains "disablescriptscanning" or action_process_image_command_line contains "disableblockatfirstseen" or action_process_image_command_line contains "exclusionpath" or action_process_image_command_line contains "exclusionprocess" or action_process_image_command_line contains "exclusionextension")) or (action_process_image_name in ("sc.exe", "net.exe", "net1.exe") and action_process_image_command_line contains "windefend")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
