config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_share_name = json_extract_scalar(action_evtlog_data_fields, "$.ShareName"), evt_share_target = json_extract_scalar(action_evtlog_data_fields, "$.RelativeTargetName")
| filter action_evtlog_event_id = 5145 and evt_share_name ~= "(?i)IPC\\$$" and evt_share_target in ("spoolss", "efsrpc", "netdfs")
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
