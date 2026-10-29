config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_script_text = json_extract_scalar(action_evtlog_data_fields, "$.ScriptBlockText")
| filter action_evtlog_event_id = 4104 and (evt_script_text contains "find-interestingdomainacl" or evt_script_text contains "invoke-sharefinder" or evt_script_text contains "get-domainobjectacl" or evt_script_text contains "invoke-userhunter" or evt_script_text contains "find-localadminaccess" or evt_script_text contains "invoke-allchecks" or evt_script_text contains "invoke-serviceabuse" or evt_script_text contains "invoke-mimikatz" or evt_script_text contains "invoke-kerberoast" or evt_script_text contains "get-sqlserverlinkcrawl" or evt_script_text contains "get-sqlinstancedomain" or evt_script_text contains "find-psremotinglocaladminaccess" or evt_script_text contains "invoke-portscan" or evt_script_text contains "function get-domainuser")
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
