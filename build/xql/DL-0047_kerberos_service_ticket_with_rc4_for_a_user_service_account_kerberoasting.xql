config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.EVENT_LOG
| alter evt_subject_user = json_extract_scalar(action_evtlog_data_fields, "$.SubjectUserName"), evt_target_user = json_extract_scalar(action_evtlog_data_fields, "$.TargetUserName"), evt_service_name = json_extract_scalar(action_evtlog_data_fields, "$.ServiceName"), evt_ticket_encryption = json_extract_scalar(action_evtlog_data_fields, "$.TicketEncryptionType")
| filter ((action_evtlog_event_id = 4769 and evt_ticket_encryption = "0x17") and not ((evt_service_name != null and evt_service_name ~= "(?i)\\$$"))) and not ((evt_service_name != null and evt_service_name ~= "(?i)^krbtgt"))
| fields _time, agent_hostname, action_evtlog_event_id, evt_subject_user, evt_target_user, action_evtlog_message
| sort desc _time
| limit 1000
