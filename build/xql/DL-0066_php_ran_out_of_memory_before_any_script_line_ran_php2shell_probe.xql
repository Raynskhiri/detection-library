config case_sensitive = false
| dataset = apache_httpd_raw
| filter _raw_log != null
| filter _raw_log contains "allowed memory size of" and _raw_log contains "exhausted" and _raw_log contains "unknown on line 0"
| fields _time, _raw_log
| sort desc _time
| limit 1000
