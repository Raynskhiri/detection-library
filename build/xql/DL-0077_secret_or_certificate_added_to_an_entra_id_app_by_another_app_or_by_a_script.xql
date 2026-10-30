config case_sensitive = false
| dataset = msft_azure_ad_audit_raw
| filter activityDisplayName != null
| alter aud_operation = activityDisplayName, aud_initiator_app = json_extract_scalar(initiatedBy, "$.app.displayName"), aud_initiator_user = json_extract_scalar(initiatedBy, "$.user.userPrincipalName"), aud_target_type = json_extract_scalar(targetResources, "$[0].type"), aud_target_name = json_extract_scalar(targetResources, "$[0].displayName"), aud_targets = to_string(targetResources), aud_user_agent = arrayindex(regextract(to_string(additionalDetails), "User-Agent\\\",\\\"value\\\":\\\"([^\\\"]*)"), 0)
| filter aud_operation ~= "(?i)^(add service principal credentials|update application.*certificates and secrets)" and (aud_initiator_app ~= "(?i).+" or aud_user_agent ~= "(?i)(python-requests|python-urllib|curl/|go-http-client|azure-toolkit)")
| fields _time, aud_operation, aud_initiator_app, aud_initiator_user, aud_target_type, aud_target_name, aud_user_agent, aud_targets
| sort desc _time
| limit 1000
