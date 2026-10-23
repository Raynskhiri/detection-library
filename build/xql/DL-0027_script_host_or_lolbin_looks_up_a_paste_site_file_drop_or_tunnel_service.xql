config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK and dns_query_name != null
| filter actor_process_image_name in ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "cmd.exe", "msbuild.exe") and dns_query_name ~= "(?i)(^|\\.)(pastebin\\.com|paste\\.ee|hastebin\\.com|rentry\\.co|raw\\.githubusercontent\\.com|transfer\\.sh|file\\.io|gofile\\.io|temp\\.sh|ngrok\\.io|ngrok-free\\.app|trycloudflare\\.com|cdn\\.discordapp\\.com|api\\.telegram\\.org)\\.?$"
| fields _time, agent_hostname, actor_process_image_name, dns_query_name
| sort desc _time
| limit 1000
