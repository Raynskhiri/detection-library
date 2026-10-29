config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_script_text = json_extract_scalar(action_evtlog_data_fields, "$.ScriptBlockText")
| filter action_evtlog_event_id = 4104 and (evt_script_text contains "amsiinitfailed" or evt_script_text contains "amsiscanbuffer" or evt_script_text contains "amsiutils" or evt_script_text contains "amsicontext" or evt_script_text contains "amsiopensession" or evt_script_text contains "amsi.dll" or evt_script_text contains "etweventwrite" or evt_script_text contains "psetwlogprovider" or evt_script_text contains "cachedgrouppolicysettings")
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
