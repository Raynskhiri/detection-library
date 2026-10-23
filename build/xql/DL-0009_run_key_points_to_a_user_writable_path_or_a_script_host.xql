config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE
| filter action_registry_key_name contains "\\software\\microsoft\\windows\\currentversion\\run" and ((action_registry_data contains "\\appdata\\" or action_registry_data contains "\\temp\\" or action_registry_data contains "\\users\\public\\" or action_registry_data contains "\\programdata\\" or action_registry_data contains "\\downloads\\") or (action_registry_data contains "powershell" or action_registry_data contains "mshta" or action_registry_data contains "wscript" or action_registry_data contains "cscript" or action_registry_data contains "rundll32" or action_registry_data contains "regsvr32" or action_registry_data contains "cmd.exe /c" or action_registry_data contains "cmd /c"))
| fields _time, agent_hostname, actor_process_image_name, action_registry_key_name, action_registry_value_name, action_registry_data
| sort desc _time
| limit 1000
