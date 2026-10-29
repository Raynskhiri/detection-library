config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter (actor_process_image_path ~= "(?i)/(apache2|httpd|nginx|php-fpm[0-9.]*|php-cgi[0-9.]*|frankenphp|lsphp[0-9]*|litespeed|lshttpd)$" and action_process_image_path ~= "(?i)/(sh|bash|dash|zsh|ksh|busybox|nc|ncat|netcat|socat|curl|wget|python[0-9.]*|perl|ruby|id|whoami|uname|hostname|base64|chmod)$") and not ((action_process_image_command_line != null and (action_process_image_command_line contains "sendmail" or action_process_image_command_line contains "/usr/sbin/exim" or action_process_image_command_line contains "postdrop")))
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 1000
