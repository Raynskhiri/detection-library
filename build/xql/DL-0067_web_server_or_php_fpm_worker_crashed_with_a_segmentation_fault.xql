config case_sensitive = false
| dataset = apache_httpd_raw
| filter _raw_log != null
| filter _raw_log ~= "(?i)ah0005[12].*segmentation fault" or _raw_log contains "exited on signal 11"
| fields _time, _raw_log
| sort desc _time
| limit 1000
