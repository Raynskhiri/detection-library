config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_ticket_transmitted_services = json_extract_scalar(action_evtlog_data_fields, "$.TransmittedServices")
| filter action_evtlog_event_id = 4769 and evt_ticket_transmitted_services ~= "(?i)\\w"
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
