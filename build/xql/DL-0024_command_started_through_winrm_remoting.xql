config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter actor_process_image_name = "wsmprovhost.exe" and action_process_image_name in ("cmd.exe", "powershell.exe", "whoami.exe", "net.exe", "net1.exe", "nltest.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "reg.exe", "schtasks.exe", "sc.exe")
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
