<?php
return [
'list_security_access' => '%s Zugriff(e) wurden für Sie protokolliert',
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
'mail_subj_account_alert' =>'[%s] Avviso di accesso',
'mail_body_account_alert' =>  '
Salve %s,
    
Abbiamo notato un accesso con una configurazione insolita sul suo account %s.
    
	UserAgent:		%s
	Indirizzo IP:	%s
	Hostname/ISP:	%s
    
Puó verificare i suoi accessi nel link seguente:
    
	%s
    
Puó disattivare l´avviso di accesso qui:
    
	%s
    
Saluti,
Il suo %2$s Team.',
];
