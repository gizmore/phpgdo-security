<?php
return [
'list_security_access' => '%s Access events',
'mtitle_security_access' => 'Access history',
'mdescr_security_access' => 'Review logins for your account.',
'accacc_isp' => 'ISP',
'accacc_ua' => 'User-Agent',
    
# Settings
'link_security_access' => 'Your access history',
'sec_record_ip' => 'Record IP after login?',
'sec_uawatch' => 'Send alert on User-Agent change?',
'sec_ipwatch' => 'Send alert on IP change?',
'sec_ispwatch' => 'Send alert on ISP change?',

# Mail
'mail_subj_account_alert' => '[%s] Access Alert',
'mail_body_account_alert' => '
Hello %s,
    
There has been access to your %s account with an unusual configuration.
    
UserAgent: %s
IP Address: %s
Hostname/ISP: %s
    
You can check your access history here.
    
%s
    
You can toggle your access alerts here.
    
%s
    
Kind Regards,
The %2$s Team',
];
