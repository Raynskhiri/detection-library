config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE
| filter (action_registry_key_name ~= "(?i)\\\\Control\\\\Lsa$" and action_registry_value_name in ("runasppl", "runaspplboot") and action_registry_data contains "0x00000000") or (action_registry_key_name ~= "(?i)\\\\SecurityProviders\\\\WDigest$" and action_registry_value_name = "uselogoncredential" and action_registry_data contains "0x00000001")
| fields _time, agent_hostname, actor_process_image_name, action_registry_key_name, action_registry_value_name, action_registry_data
| sort desc _time
| limit 1000
