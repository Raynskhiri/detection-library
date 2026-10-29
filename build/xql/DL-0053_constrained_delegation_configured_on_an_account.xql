config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_attribute_name = json_extract_scalar(action_evtlog_data_fields, "$.AttributeLDAPDisplayName")
| filter action_evtlog_event_id = 5136 and evt_attribute_name = "msds-allowedtodelegateto"
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
