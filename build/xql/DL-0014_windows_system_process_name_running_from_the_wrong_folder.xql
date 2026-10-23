config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter action_process_image_name in ("svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe", "lsm.exe") and not ((action_process_image_path != null and action_process_image_path ~= "(?i)^(\\\\\\\\\\?\\\\)?[a-z]:\\\\windows\\\\(system32|syswow64)\\\\[^\\\\]+$"))
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
