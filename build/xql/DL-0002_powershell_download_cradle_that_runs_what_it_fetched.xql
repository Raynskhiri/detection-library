config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (action_process_image_name in ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and (action_process_image_command_line contains "downloadstring" or action_process_image_command_line contains "downloadfile" or action_process_image_command_line contains "downloaddata" or action_process_image_command_line contains "net.webclient" or action_process_image_command_line contains "invoke-webrequest" or action_process_image_command_line contains "iwr " or action_process_image_command_line contains "invoke-restmethod" or action_process_image_command_line contains "irm " or action_process_image_command_line contains "start-bitstransfer")) and action_process_image_command_line ~= "(?i)(\\biex\\b|invoke-expression|\\|\\s*iex)"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
