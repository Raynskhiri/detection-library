config case_sensitive = false
| dataset = msft_azure_ad_raw
| filter appId != null
| alter si_app_id = appId, si_app_name = appDisplayName, si_sp_name = servicePrincipalName, si_ip = ipAddress, si_user_agent = userAgent, si_resource = resourceDisplayName, si_error = json_extract_scalar(status, "$.errorCode")
| filter si_app_id in ("506e08f9-6e9a-4da4-942b-a099a03644ae", "2399d300-6fca-4e6a-a686-399fefe75b83", "24205314-2b89-4e07-a2a4-579e898a5640", "b78f6a77-d4e5-46fb-87e5-d1648bd02519", "0de14c77-b9b0-4137-9360-34878a929827", "412dcf96-176d-4b3a-a1b0-4981ad66971e", "b2b55f5b-7758-4719-8d8f-88ae172e6bdb") and (si_ip ~= "(?i)^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$" or (incidr(si_ip, "144.172.64.0/24") or incidr(si_ip, "187.15.88.0/22")))
| fields _time, si_app_name, si_app_id, si_sp_name, si_ip, si_user_agent, si_resource, si_error
| sort desc _time
| limit 1000
