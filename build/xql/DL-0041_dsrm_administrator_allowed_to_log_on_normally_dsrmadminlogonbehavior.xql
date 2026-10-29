config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE
| filter action_registry_key_name ~= "(?i)\\\\Control\\\\Lsa$" and action_registry_value_name = "dsrmadminlogonbehavior"
| fields _time, agent_hostname, actor_process_image_name, action_registry_key_name, action_registry_value_name, action_registry_data
| sort desc _time
| limit 1000
