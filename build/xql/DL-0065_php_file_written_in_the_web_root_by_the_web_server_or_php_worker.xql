config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE and event_sub_type in (ENUM.FILE_CREATE_NEW, ENUM.FILE_WRITE)
| filter actor_process_image_path ~= "(?i)/(apache2|httpd|nginx|php-fpm[0-9.]*|php-cgi[0-9.]*|frankenphp|lsphp[0-9]*|dash|sh|bash|curl|wget)$" and action_file_path ~= "(?i)^/(var/www|srv/www|srv/http|usr/share/nginx)/.+\\.(php[0-9]?|phtml|phar|pht)$"
| fields _time, agent_hostname, actor_process_image_name, action_file_path
| sort desc _time
| limit 1000
