config case_sensitive = false
| dataset = fortinet_fortigate_raw
| filter _raw_log != null
| alter fg_logid = arrayindex(regextract(_raw_log, "\\blogid=\"?([^\"\\s]*)"), 0), fg_subtype = arrayindex(regextract(_raw_log, "\\bsubtype=\"?([^\"\\s]*)"), 0), fg_action = arrayindex(regextract(_raw_log, "\\baction=\"?([^\"\\s]*)"), 0), fg_status = arrayindex(regextract(_raw_log, "\\bstatus=\"?([^\"\\s]*)"), 0), fg_user = arrayindex(regextract(_raw_log, "\\buser=\"?([^\"\\s]*)"), 0), fg_srcip = arrayindex(regextract(_raw_log, "\\bsrcip=\"?([^\"\\s]*)"), 0), fg_ui = arrayindex(regextract(_raw_log, "\\bui=\"?([^\"\\s]*)"), 0), fg_method = arrayindex(regextract(_raw_log, "\\bmethod=\"?([^\"\\s]*)"), 0), fg_devname = arrayindex(regextract(_raw_log, "\\bdevname=\"?([^\"\\s]*)"), 0), fg_logdesc = arrayindex(regextract(_raw_log, "\\blogdesc=\"([^\"]*)\""), 0), fg_msg = arrayindex(regextract(_raw_log, "\\bmsg=\"([^\"]*)\""), 0)
| filter (fg_subtype = "system" and fg_action = "login" and fg_status = "success") and ((fg_method = "sso" or fg_ui ~= "(?i)^sso") or not ((fg_srcip != null and (incidr(fg_srcip, "10.0.0.0/8") or incidr(fg_srcip, "172.16.0.0/12") or incidr(fg_srcip, "192.168.0.0/16") or incidr(fg_srcip, "127.0.0.0/8")))))
| fields _time, fg_devname, fg_logid, fg_user, fg_srcip, fg_ui, fg_logdesc, fg_msg
| sort desc _time
| limit 1000
