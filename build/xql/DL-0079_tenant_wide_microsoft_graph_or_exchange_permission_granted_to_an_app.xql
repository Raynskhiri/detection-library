config case_sensitive = false
| dataset = msft_azure_ad_audit_raw
| filter activityDisplayName != null
| alter aud_operation = activityDisplayName, aud_initiator_app = json_extract_scalar(initiatedBy, "$.app.displayName"), aud_initiator_user = json_extract_scalar(initiatedBy, "$.user.userPrincipalName"), aud_target_type = json_extract_scalar(targetResources, "$[0].type"), aud_target_name = json_extract_scalar(targetResources, "$[0].displayName"), aud_targets = to_string(targetResources), aud_user_agent = arrayindex(regextract(to_string(additionalDetails), "User-Agent\\\",\\\"value\\\":\\\"([^\\\"]*)"), 0)
| filter aud_operation in ("add app role assignment to service principal", "add app role assignment grant to user", "consent to application") and (aud_targets contains "RoleManagement.ReadWrite.Directory" or aud_targets contains "AppRoleAssignment.ReadWrite.All" or aud_targets contains "Application.ReadWrite.All" or aud_targets contains "Directory.ReadWrite.All" or aud_targets contains "Mail.ReadWrite" or aud_targets contains "Mail.Read" or aud_targets contains "Files.ReadWrite.All" or aud_targets contains "Sites.FullControl.All" or aud_targets contains "full_access_as_app")
| fields _time, aud_operation, aud_initiator_app, aud_initiator_user, aud_target_type, aud_target_name, aud_user_agent, aud_targets
| sort desc _time
| limit 1000
