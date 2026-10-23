config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (((action_process_image_name in ("net.exe", "net1.exe") and (action_process_image_command_line contains "group" and action_process_image_command_line contains "/domain")) and (action_process_image_command_line contains "domain admins" or action_process_image_command_line contains "enterprise admins" or action_process_image_command_line contains "schema admins" or action_process_image_command_line contains "domain controllers" or action_process_image_command_line contains "administrators")) or (action_process_image_name = "nltest.exe" and (action_process_image_command_line contains "/domain_trusts" or action_process_image_command_line contains "/dclist" or action_process_image_command_line contains "/all_trusts" or action_process_image_command_line contains "/trusted_domains" or action_process_image_command_line contains "/dsgetdc"))) or (action_process_image_command_line contains "adfind" or action_process_image_command_line contains "trustdmp" or action_process_image_command_line contains "objectcategory=computer")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
