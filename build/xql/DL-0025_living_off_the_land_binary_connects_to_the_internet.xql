config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_remote_ip != null
| filter actor_process_image_name in ("certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe", "cmstp.exe", "odbcconf.exe", "msxsl.exe", "hh.exe") and not ((action_remote_ip != null and (incidr(action_remote_ip, "10.0.0.0/8") or incidr(action_remote_ip, "172.16.0.0/12") or incidr(action_remote_ip, "192.168.0.0/16") or incidr(action_remote_ip, "127.0.0.0/8") or incidr(action_remote_ip, "169.254.0.0/16") or incidr(action_remote_ip, "100.64.0.0/10"))))
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, action_remote_ip, action_remote_port
| sort desc _time
| limit 1000
