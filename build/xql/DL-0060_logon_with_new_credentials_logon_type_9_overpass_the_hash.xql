config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_logon_type = json_extract_scalar(action_evtlog_data_fields, "$.LogonType"), evt_logon_process = json_extract_scalar(action_evtlog_data_fields, "$.LogonProcessName")
| filter action_evtlog_event_id = 4624 and evt_logon_type = "9" and evt_logon_process contains "seclogo"
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
