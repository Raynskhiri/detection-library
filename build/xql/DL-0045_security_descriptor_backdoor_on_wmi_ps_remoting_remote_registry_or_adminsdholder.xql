config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_script_text = json_extract_scalar(action_evtlog_data_fields, "$.ScriptBlockText")
| filter action_evtlog_event_id = 4104 and (evt_script_text contains "set-remotewmi" or evt_script_text contains "set-remotepsremoting" or evt_script_text contains "add-remoteregbackdoor" or evt_script_text contains "get-remotemachineaccounthash" or evt_script_text contains "get-remotelocalaccounthash" or evt_script_text contains "get-remotecachedcredential" or evt_script_text contains "cn=adminsdholder" or evt_script_text contains "-rights dcsync" or evt_script_text contains "invoke-sdpropagator")
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
