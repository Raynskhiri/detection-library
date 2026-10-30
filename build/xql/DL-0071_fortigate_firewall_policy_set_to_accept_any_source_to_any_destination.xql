config case_sensitive = false
| dataset = fortinet_fortigate_raw
| filter _raw_log != null
| alter fg_logid = arrayindex(regextract(_raw_log, "\\blogid=\"?([^\"\\s]*)"), 0), fg_action = arrayindex(regextract(_raw_log, "\\baction=\"?([^\"\\s]*)"), 0), fg_user = arrayindex(regextract(_raw_log, "\\buser=\"?([^\"\\s]*)"), 0), fg_srcip = arrayindex(regextract(_raw_log, "\\bsrcip=\"?([^\"\\s]*)"), 0), fg_ui = arrayindex(regextract(_raw_log, "\\bui=\"?([^\"\\s]*)"), 0), fg_cfgpath = arrayindex(regextract(_raw_log, "\\bcfgpath=\"?([^\"\\s]*)"), 0), fg_devname = arrayindex(regextract(_raw_log, "\\bdevname=\"?([^\"\\s]*)"), 0), fg_logdesc = arrayindex(regextract(_raw_log, "\\blogdesc=\"([^\"]*)\""), 0), fg_msg = arrayindex(regextract(_raw_log, "\\bmsg=\"([^\"]*)\""), 0), fg_cfgattr = arrayindex(regextract(_raw_log, "\\bcfgattr=\"([^\"]*)\""), 0)
| filter (fg_cfgpath = "firewall.policy" and fg_action in ("add", "edit")) and (fg_cfgattr ~= "(?i)srcaddr\\[([^\\]]*->)?all\\]" and fg_cfgattr ~= "(?i)dstaddr\\[([^\\]]*->)?all\\]")
| fields _time, fg_devname, fg_logid, fg_user, fg_srcip, fg_ui, fg_logdesc, fg_msg
| sort desc _time
| limit 1000
