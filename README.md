# Build Squid on Raspberry Pi with enabled SSL, optionally realtime SARG statistics and SquidClamAV

This is the short guide about how to recompile/enable `--enable-ssl` option in a Squid caching proxy server. The `--enable-ssl` option turned off by default, to be able to use SslBump feature we have to turn it on. To my own surprise Squid was compiled not only without `--enable-ssl` flag, but also with GnuTLS due to GPL legal reasons.

Optionally enable:
- SARG to provide detailed usage statistics, https://sourceforge.net/projects/sarg/
- SquidClamAV to scan web traffic for viruses, https://squidclamav.darold.net/

## Squid

### Prepare build environment and Squid source code

First off, uncomment the deb-src in */etc/apt/source.list* and do:
```bash
sudo apt update
```
then, open a bash shell and:

```bash
mkdir squid-build
cd squid-build
sudo apt-get install openssl devscripts build-essential fakeroot libdbi-perl libssl-dev dpkg-dev
sudo apt-get build-dep squid
apt-get source squid
cd squid-4.6/
```

### Change Squid build script

Now change build script

```bash
nano debian/rules
```

For the `DEB_CONFIGURE_EXTRA_FLAGS` flags:

- change `--with-gnutls` to `--without-gnutls` (disable GnuTLS)
- add `--with-openssl` (use OpenSSL instead of GnuTLS)
- add `--enable-ssl`
- add `--enable-ssl-crtd`
- add `--disable-ipv6` (optionally disable IPv6)

### Build Squid DEB packages

Now compile deb-packages using

```bash
debuild -us -uc
```

In case of an error on subsequent attempt

```bash
# commit non-relevant files
dpkg-source --commit
# or get rid of it
rm -f config.log
```

### Install Squid DEB packages

```bash
cd ..
# list all produced packages
ls -la *.deb
# install only two relevant
sudo dpkg -i squid_4.6-1+deb10u4_armhf.deb squid-common_4.6-1+deb10u4_all.deb
```

Check enabled flags with:

```bash
squid -v | grep ssl
```

Put updates on hold

```bash
sudo apt-mark hold squid squid-common
```

### Prepare SSL certificates

```bash
apt-get install openssl
mkdir -p /etc/squid/cert
cd /etc/squid/cert
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -sha256 -days 365 -key ca.key -out ca.pem -subj '/C=LV/ST=Latvia/O=IT/CN=Self-signed CA'
openssl x509 -in ca.pem -outform DER -out ca.der
openssl dhparam -outform PEM -out dhparam.pem 2048
chown -R proxy:proxy /etc/squid/cert
chmod 700 /etc/squid/cert
```

*The certificate generated at this step will be used to re-encrypt your HTTPS traffic, ca.pem file must be imported to your clients web-browser*

### Prepare SSL cache for Squid

```bash
/usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB
chown -R proxy:proxy /var/spool/squid/ssl_db/
```

### Tweak Squid configuration

Add the following block to the existing Squid configuration file at `/etc/squid/squid.conf`

```
acl intermediate_fetching transaction_initiator certificate-fetching
http_access allow intermediate_fetching

sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/spool/squid/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1
# sslproxy_cert_error allow all
ssl_bump stare all

http_port 3129 tcpkeepalive=60,30,3 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/cert/ca.pem key=/etc/squid/cert/ca.key cipher=HIGH:MEDIUM:!LOW:!RC4:!SEED:!IDEA:!3DES:!MD5:!EXP:!PSK:!DSS options=NO_TLSv1,NO_SSLv3 tls-dh=prime256v1:/etc/squid/cert/dhparam.pem
```

You can instruct Squid to use only particular OpenSSL ciphers to connect to external web-sites, and between itself and proxy-users

```
tls_outgoing_options cipher=HIGH:MEDIUM:!RSA:!CAMELLIA:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!SHA1:!SHA256:!SHA384:!SEED:!ADH options=NO_SSLv3 min-version=1.2

ssl_bump bump all

http_port 192.168.88.220:3129 tcpkeepalive=60,30,3 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/cert/ca.pem key=/etc/squid/cert/ca.key cipher=HIGH:MEDIUM:!RSA:!CAMELLIA:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!SHA1:!SHA256:!SHA384:!SEED:!ADH options=NO_TLSv1,NO_TLSv1_1,NO_SSLv3 tls-dh=prime256v1:/etc/squid/cert/dhparam.pem
```

<details>
  <summary>Click to see complete configuration</summary>
  
```
acl internal_icons urlpath_regex -i /squid-internal-static/icons/
http_access allow internal_icons

acl intermediate_fetching transaction_initiator certificate-fetching
http_access allow intermediate_fetching

sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/spool/squid/ssl_db -M 4MB
sslcrtd_children 8 startup=1 idle=1
# sslproxy_cert_error allow all
ssl_bump stare all

# printf "squid:$(openssl passwd -crypt 'squid')\n" | sudo tee -a /etc/squid/passwd
# auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwd
# auth_param basic realm proxy
# auth_param basic credentialsttl 8 hours
# auth_param basic utf8 on
# auth_param basic casesensitive off
# acl authenticated proxy_auth REQUIRED

acl localnet src 0.0.0.1-0.255.255.255	
acl localnet src 10.0.0.0/8		
acl localnet src 100.64.0.0/10		
acl localnet src 169.254.0.0/16
acl localnet src 172.16.0.0/12		
acl localnet src 192.168.0.0/16		

acl SSL_ports port 443
acl Safe_ports port 80		
acl Safe_ports port 21		
acl Safe_ports port 443		
acl Safe_ports port 70		
acl Safe_ports port 210		
acl Safe_ports port 1025-65535	
acl Safe_ports port 280		
acl Safe_ports port 488		
acl Safe_ports port 591		
acl Safe_ports port 777		

acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager

snmp_access deny all
icp_access deny all
htcp_access deny all

http_access deny to_localhost
http_access allow localnet
http_access allow localhost
# http_access allow authenticated
http_access deny all

http_port 3128
http_port 3129 tcpkeepalive=60,30,3 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/cert/ca.pem key=/etc/squid/cert/ca.key cipher=HIGH:MEDIUM:!LOW:!RC4:!SEED:!IDEA:!3DES:!MD5:!EXP:!PSK:!DSS options=NO_TLSv1,NO_SSLv3 tls-dh=prime256v1:/etc/squid/cert/dhparam.pem

cache deny all
# access_log none
access_log daemon:/var/log/squid/access.log squid
cache_store_log none
cache_log /dev/null
via off
forwarded_for delete
follow_x_forwarded_for deny all
logfile_rotate 0
strip_query_terms off
shutdown_lifetime 2 seconds
memory_pools off
dns_v4_first on
visible_hostname raspberrypi
```
</details>

Restart

```bash
sudo systemctl restart squid.service
```

### Client configuration

Since we're not using `intercept` mode a client configuration is needed:

- Set HTTP proxy to point to Squid server ip address and port `3129`
- Download `/etc/squid/cert/ca.pem` certificate and import it into the trust-store

In `intercept` mode few changes are needed (feel free to skip this step if you do not plan to use intercept mode):

#### Configuration file

Enable IP layer interception

```
http_port 3120 intercept
https_port 3130 intercept ssl-bump ...
```

#### Catch incoming routing

```bash
iptables -t nat -A PREROUTING -i eth0 -s 192.168.55.0/24 ! -d 192.168.55.0/24 -p tcp -m tcp --dport 80 -j REDIRECT --to-port 3120
iptables -t nat -A PREROUTING -i eth0 -s 192.168.55.0/24 ! -d 192.168.55.0/24 -p tcp -m tcp --dport 443 -j REDIRECT --to-port 3130
```

#### Prevent local traffic dead-loop

```bash
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxy --dport 80 -j REDIRECT --to-port 3120
iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner proxy --dport 443 -j REDIRECT --to-port 3130
```

#### Allow forwarding

```
tee -a /etc/sysctl.conf <<'EOF' >/dev/null
net.ipv4.ip_forward = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
sudo sysctl -p
```

## Optional: Basic auth

Prepare passwords file

```bash
sudo touch /etc/squid/passwd
sudo chmod 644 /etc/squid/passwd
sudo htpasswd -c /etc/squid/passwd squid
```

Uncomment lines

```
auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm proxy
auth_param basic credentialsttl 8 hours
auth_param basic utf8 on
auth_param basic casesensitive off
acl authenticated proxy_auth REQUIRED

http_access allow authenticated
http_access deny all
```

## Misc: SSL options

```
# ssl_bump peek all
# ssl_bump splice all
# ssl_bump bump all

# acl step1 at_step SslBump1
# acl step2 at_step SslBump2
# acl step3 at_step SslBump3

# acl ssl_exclude_domains ssl::server_name "/etc/squid/ssl_exclude_domains.conf"
# acl ssl_exclude_ips     dst              "/etc/squid/ssl_exclude_ips.conf"

# ssl_bump splice localhost
# ssl_bump peek step1 all
# ssl_bump splice ssl_exclude_domains
# ssl_bump splice ssl_exclude_ips
# ssl_bump stare step2 all
# ssl_bump bump all
```

## Optional: Install SARG

### Install SARG prerequisites

```bash
sudo apt-get install zlib1g-dev libgd-dev libbz2-dev liblzma-dev libpcre3-dev
```

### Download and build SARG 

```bash
curl -fsSLO https://kumisystems.dl.sourceforge.net/project/sarg/sarg/sarg-2.4.0/sarg-2.4.0.tar.gz
tar -zxf sarg-2.4.0.tar.gz
cd sarg-2.4.0/
./configure --prefix /opt/sarg
make
sudo make install
```

### Configure SARG

```
sudo usermod -a -G proxy www-data # allow to read squid logs
sudo cp sarg.conf /opt/sarg/etc/sarg.conf # check config file below
sudo /opt/sarg/bin/sarg -r
```

### Add crontab task to generate statistics at midnight

```
sudo crontab -e
```

Add new item

```
59 23 * * * sudo /opt/sarg/bin/sarg -f /opt/sarg/etc/sarg.conf
```

<details>
  <summary>Click to see complete configuration file /opt/sarg/etc/sarg.conf</summary>
  
```
access_log /var/log/squid/access.log
output_dir /var/www/html/sarg
resolve_ip yes
user_ip yes
topuser_sort_field BYTES reverse
user_sort_field BYTES reverse
date_format e
lastlog 7
remove_temp_files yes
index yes
index_tree file
index_fields dirsize
overwrite_report yes
records_without_userid ip
use_comma no
topsites_num 10
topsites_sort_order CONNECT D
index_sort_order D
report_type topusers topsites sites_users users_sites date_time denied auth_failures site_user_time_date downloads user_agent
long_url yes
date_time_by bytes
charset Latin1
privacy no
show_successful_message yes
show_read_statistics no
show_read_percent no
topuser_fields NUM DATE_TIME USERID CONNECT BYTES %BYTES IN-CACHE-OUT USED_TIME MILISEC %TIME TOTAL AVERAGE
user_report_fields CONNECT BYTES %BYTES IN-CACHE-OUT USED_TIME MILISEC %TIME TOTAL AVERAGE
bytes_in_sites_users_report yes
topuser_num 5
dansguardian_conf none
squidguard_conf none
show_sarg_info no
show_sarg_logo no
parsed_output_log none
displayed_values abbreviation
www_document_root /var/www/html
user_authentication no
download_suffix "zip,arj,bzip,gz,ace,doc,iso,adt,bin,cab,com,dot,drv$,lha,lzh,mdb,mso,ppt,rtf,src,shs,sys,exe,dll,mp3,avi,mpg,mpeg"
realtime_refresh_time 10
realtime_access_log_lines 100
realtime_types GET,PUT,CONNECT,POST
keep_temp_log no
```
</details>

If you do not see realtime statistics add full path to sarg binary to `/var/www/html/sarg-php/sarg-realtime.php` file

```php
<?php
system("/opt/sarg/bin/sarg -r");
?>
```

If you see incorrect urls in realtime statistics patch `realtime.c` file, then repeat compile and install steps again

<details>
  <summary>Click to see patch file</summary>
  
```
--- sarg-2.4.0-orig/realtime.c	2019-12-24 11:04:00.000000000 +0000
+++ sarg-2.4.0/realtime.c	2020-12-19 19:58:31.578238661 +0000
@@ -97,19 +97,15 @@ static void StoreLogEntry(struct Realtim
  safe_strcpy(Dest->Ip,Entry->Ip,sizeof(Dest->Ip));
  if (Entry->Url)
  {
-		int i;
-		const char *url=Entry->Url;
-
-		// skip the scheme
-		for (i=0 ; i<8 && url[i] && (isalnum(url[i]) || url[i]=='+' || url[i]=='-' || url[i]=='.') ; i++);
-		if (url[i]==':' && url[i+1]=='/' && url[i+2]=='/')
-		{
-			url+=i+3;
-			for (i=0 ; url[i] && url[i]!='/' ; i++);
-		}
-		if (i>=sizeof(Dest->Url)) i=sizeof(Dest->Url)-1;
-		strncpy(Dest->Url,url,i);
-		Dest->Url[i]='\0';
+                int i = 0;
+                const char *url=Entry->Url;
+                const char *proto=strstr(url,"://");
+                if (proto) {
+                  url = proto+3;
+                }
+                i = strlen(url) < sizeof(Dest->Url) ? strlen(url) : sizeof(Dest->Url)-1;
+                memcpy(Dest->Url,url,i);
+                Dest->Url[i]='\0';
  }
  safe_strcpy(Dest->User,Entry->User,sizeof(Dest->User));
  safe_strcpy(Dest->HttpMethod,Entry->HttpMethod,sizeof(Dest->HttpMethod));
```
</details>

SARG statistics will be available:
- `http://x.x.x.x/sarg/` - midnight or ad-hoc
- `http://x.x.x.x/sarg-php/sarg-realtime.php` - realtime

## Optional: Install SquidClamAV

Confirm squid has required flags first:

- `squid -v | grep 'enable-icap-client'`
- `squid -v | grep 'enable-ecap'`

If not, add & recompile

### Install SquidClamAV
  
Note: I do not recommend to install it if you have Raspberry Pi installed on sdcard and less than 8 GB or RAM!

```bash
sudo apt-get install clamav clamav-daemon c-icap libicapapi-dev libarchive-dev
curl -fsSLO http://downloads.sourceforge.net/project/squidclamav/squidclamav/7.1/squidclamav-7.1.tar.gz
tar -zxf squidclamav-7.1.tar.gz
./configure --with-c-icap=/usr
make
sudo make install
```

### Prepare SquidClamAV configuration
1. Allow i-cap daemon to start at boot

    <details>
      <summary>Click to see configuration of /etc/default/c-icap</summary>
      
    ```
    --- /etc/default/c-icap.orig	2020-12-20 14:44:50.513644910 +0000
    +++ /etc/default/c-icap	2020-12-20 14:45:19.003262843 +0000
    @@ -3,7 +3,7 @@
     # installed at /etc/default/c-icap by the maintainer scripts
     
     # Should c-icap daemon run automatically on startup? (default: no)
    -START=no
    +START=yes
     
     # Additional options that are passed to the Daemon.
     DAEMON_ARGS=""
    ```
    </details>

1. Import squidclamav.so module and change few parameters

    <details>
      <summary>Click to see configuration of /etc/c-icap/c-icap.conf</summary>
      
    ```
    --- /etc/c-icap/c-icap.conf.orig	2020-12-20 14:41:38.516221674 +0000
    +++ /etc/c-icap/c-icap.conf	2020-12-20 18:16:28.704142545 +0000
    @@ -55,7 +55,7 @@
     #	generates a number of threads, which serve the requests.
     # Default:
     #	StartServers 3
    -StartServers 3
    +StartServers 1
     
     # TAG: MaxServers
     # Format: MaxServers number
    @@ -100,7 +100,7 @@
     #	stability of c-icap. It can be disabled by setting its value to 0.
     # Default:
     #	MaxRequestsPerChild  0
    -MaxRequestsPerChild  0
    +MaxRequestsPerChild  100
     
     # TAG: InterProcessSharedMemScheme
     # Format: InterProcessSharedMemScheme posix | mmap | sysv
    @@ -129,7 +129,7 @@
     #	The port number that the c-icap server uses to listen to requests.
     # Default:
     #	None
    -Port 1344
    +Port 127.0.0.1:1345
     
     # TAG: TlsPort
     # Format: TlsPort [address:]port [tls-method=method] [cert=path_to_pem_cert] [key=path_to_pem_key] [client_ca=path_to_pem_file] [ciphers=ciph1:ciph2...] [tls_options=[!]Opt1|[!]Opt2|...]
    @@ -231,7 +231,7 @@
     #	server (logs, info service, etc)
     # Default:
     #	No value
    -ServerName YourServerName
    +ServerName raspberrypi
     
     # TAG: TmpDir
     # Format: TmpDir dir
    @@ -258,7 +258,7 @@
     #	The acceptable range of levels is between 0 and 10.
     # Default:
     #	DebugLevel 1
    -DebugLevel 1
    +DebugLevel 0
     
     # TAG: Pipelining
     # Format: Pipelining on|off
    @@ -515,6 +515,8 @@
     #	acl BigObjects content_length{>} 5000000
     #	acl WorkingHours time M,T,W,H,F/8:00-18:00
     #	acl FreeHour time Sunday,Saturday/8:00-23:59 M,T,W,H,F/18:01-23:59 M,T,W,H,F/0:00-7.59
    +acl localhost src 127.0.0.1/255.255.255.255
    +acl PERMIT_REQUESTS type REQMOD RESPMOD
     
     # TAG: icap_access
     # Format: icap_access allow|deny [!]acl1 ...
    @@ -529,6 +531,8 @@
     #	#Require authentication for all users from local network:
     #	icap_access allow AUTH localnet
     #	icap_access deny all
    +icap_access allow localhost PERMIT_REQUESTS
    +icap_access deny all
     
     # TAG: client_access
     # Format: client_access allow|deny acl1 [acl2] [...]
    @@ -706,7 +710,8 @@
     #	Simple test service
     # Example:
     #	Service echo srv_echo.so
    -Service echo srv_echo.so
    +#Service echo srv_echo.so
    +Service squidclamav squidclamav.so
     
     # Module: sys_logger
     # Description:
    ```
    </details>

1. Enable archive support, set redirect url, log threats (you may enable `multipart` too)

    <details>
      <summary>Click to see configuration of /etc/c-icap/squidclamav.conf</summary>
      
    ```
    --- /etc/c-icap/squidclamav.conf.default	2020-12-20 15:00:05.541393122 +0000
    +++ /etc/c-icap/squidclamav.conf	2020-12-20 17:31:16.490432907 +0000
    @@ -17,7 +17,7 @@
     
     # When a virus is found then redirect the user to this URL. If this directive
     # is disabled squidclamav will use c-icap error templates to report issues.
    -redirect http://proxy.domain.dom/cgi-bin/clwarn.cgi
    +redirect http://raspberrypi/squidclamav/clwarn.cgi
     
     # Path to the clamd socket, use clamd_local if you use Unix socket or if clamd
     # is listening on an Inet socket, comment clamd_local and set the clamd_ip and
    @@ -32,7 +32,7 @@
     
     # Force SquidClamav to log all virus detection or squiguard block redirection
     # to the c-icap log file.
    -logredir 0
    +logredir 1
     
     # Enable / disable DNS lookup of client ip address. Default is enabled '1' to
     # preserve backward compatibility but you must desactivate this feature if you
    @@ -115,7 +115,7 @@
     # file in the archives. Enabling this directive allow squidclamav to uncompress
     # archives and filter according to user-defined rules before passing them to
     # clamav. See directives bellow for more details.
    -enable_libarchive 0
    +enable_libarchive 1
     
     # Block matching archive entries (supported by libarchive).
     # eg. zip files containing threats such as ransomeware that are not yet
    ```
    </details>

1. Enable redirect page *please note: I'm using pihole and lighttpd*

    <details>
      <summary>Click to see configuration of /etc/lighttpd/conf-enabled/10-cgi.conf</summary>
      
    ```
    server.modules += (
      "mod_cgi",
      "mod_alias"
    )

    $HTTP["url"] =~ "^/squidclamav/" {
            cgi.assign = ( "" => "" )
            alias.url += ( "/squidclamav/" => "/usr/local/libexec/squidclamav/" )
    }
    ```
    </details>

1. Add missing logrotate for c-icap daemon

    <details>
      <summary>Click to see configuration of /etc/logrotate.d/c-icap</summary>
      
    ```
    /var/log/c-icap/server.log /var/log/c-icap/access.log {
        daily
        rotate 4
        missingok
        notifempty
        compress
        delaycompress
        create 0644 root root
        postrotate
            /etc/init.d/c-icap force-reload > /dev/null
        endscript
    }
    ```
    </details>

1. Set stream size to 5M, should be the same value as `maxsize` in squidclamav.conf

    <details>
      <summary>Click to see configuration of /etc/clamav/clamd.conf</summary>
      
    ```
    --- /etc/clamav/clamd.conf.orig	2020-12-21 17:34:51.683638477 +0000
    +++ /etc/clamav/clamd.conf	2020-12-20 17:29:37.461752724 +0000
    @@ -76,7 +76,7 @@
     ScanXMLDOCS true
     ScanHWP3 true
     MaxRecHWP3 16
    -StreamMaxLength 25M
    +StreamMaxLength 5M
     LogFile /var/log/clamav/clamav.log
     LogTime true
     LogFileUnlock false
    ```
    </details>

1. Set explicit cpu-quota to clamav services

    <details>
      <summary>Click to see configuration of /etc/systemd/system/clamav-daemon.service.d/override.conf</summary>
      
    ```
    [Service]
    CPUQuota=50%
    ```
    </details>

    <details>
      <summary>Click to see configuration of /etc/systemd/system/clamav-freshclam.service.d/override.conf</summary>
      
    ```
    [Service]
    CPUQuota=50%
    ```
    </details>

1. Complete Squid configuration with icap settings, malware blocklist, headers allowlist

    <details>
      <summary>Click to see configuration of /etc/squid/squid.conf</summary>
      
    ```
    acl internal_icons urlpath_regex -i /squid-internal-static/icons/
    http_access allow internal_icons

    acl intermediate_fetching transaction_initiator certificate-fetching
    http_access allow intermediate_fetching

    sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/spool/squid/ssl_db -M 4MB
    sslcrtd_children 8 startup=1 idle=1
    # sslproxy_cert_error allow all
    ssl_bump stare all

    # auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/passwd
    # auth_param basic realm proxy
    # acl authenticated proxy_auth REQUIRED

    # acl malware_block_list url_regex -i "/etc/squid/malware_block_list"

    acl localnet src 0.0.0.1-0.255.255.255	
    acl localnet src 10.0.0.0/8		
    acl localnet src 100.64.0.0/10		
    acl localnet src 169.254.0.0/16
    acl localnet src 172.16.0.0/12		
    acl localnet src 192.168.0.0/16		

    acl SSL_ports port 443
    acl Safe_ports port 80		
    acl Safe_ports port 21		
    acl Safe_ports port 443		
    acl Safe_ports port 70		
    acl Safe_ports port 210		
    acl Safe_ports port 1025-65535	
    acl Safe_ports port 280		
    acl Safe_ports port 488		
    acl Safe_ports port 591		
    acl Safe_ports port 777		

    acl CONNECT method CONNECT

    http_access deny !Safe_ports
    http_access deny CONNECT !SSL_ports
    http_access allow localhost manager
    http_access deny manager

    snmp_access deny all
    icp_access deny all
    htcp_access deny all

    http_access deny to_localhost
    # http_access deny malware_block_list
    http_access allow localnet
    http_access allow localhost
    # http_access allow authenticated
    http_access deny all

    http_port 3128
    http_port 3129 tcpkeepalive=60,30,3 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert=/etc/squid/cert/ca.pem key=/etc/squid/cert/ca.key cipher=HIGH:MEDIUM:!LOW:!RC4:!SEED:!IDEA:!3DES:!MD5:!EXP:!PSK:!DSS options=NO_TLSv1,NO_SSLv3 tls-dh=prime256v1:/etc/squid/cert/dhparam.pem

    cache deny all
    # access_log none
    access_log daemon:/var/log/squid/access.log squid
    cache_store_log none
    cache_log /dev/null
    via off
    forwarded_for delete
    follow_x_forwarded_for deny all
    logfile_rotate 0
    strip_query_terms off
    shutdown_lifetime 2 seconds
    memory_pools off
    dns_v4_first on
    visible_hostname raspberrypi

    # icap
    icap_enable on
    adaptation_send_client_ip on
    adaptation_send_username on
    icap_persistent_connections on
    icap_client_username_encode off
    icap_client_username_header X-Authenticated-User
    icap_preview_enable on
    icap_preview_size 1024
    icap_service_failure_limit -1

    acl icap_skip_localnet dst 192.168.0.0/16

    icap_service service_req reqmod_precache bypass=0 icap://127.0.0.1:1345/squidclamav
    icap_service service_resp respmod_precache bypass=0 icap://127.0.0.1:1345/squidclamav

    adaptation_access service_req deny icap_skip_localnet
    adaptation_access service_resp deny icap_skip_localnet
    adaptation_access service_req allow all
    adaptation_access service_resp allow all

    # limit headers
    request_header_access Allow allow all
    request_header_access Authorization allow all
    request_header_access WWW-Authenticate allow all
    request_header_access Proxy-Authorization allow all
    request_header_access Proxy-Authenticate allow all
    request_header_access Content-Encoding allow all
    request_header_access Content-Length allow all
    request_header_access Content-Type allow all
    request_header_access Date allow all
    request_header_access Expires allow all
    request_header_access Host allow all
    request_header_access If-Modified-Since allow all
    request_header_access Last-Modified allow all
    request_header_access Location allow all
    request_header_access Pragma allow all
    request_header_access Accept allow all
    request_header_access Accept-Charset allow all
    request_header_access Accept-Encoding allow all
    request_header_access Accept-Language allow all
    request_header_access Content-Language allow all
    request_header_access Mime-Version allow all
    request_header_access Retry-After allow all
    request_header_access Title allow all
    request_header_access Connection allow all
    request_header_access Proxy-Connection allow all
    request_header_access User-Agent allow all
    request_header_access Cookie allow all
    request_header_access Referer deny all
    request_header_access X-Forwarded-For deny all
    request_header_access Via deny all
    request_header_access All deny all
    request_header_access Cache-Control deny all
    httpd_suppress_version_string on
    ```
    </details>

### Post actions

Tweak permissions if required

```bash
sudo chmod 644 /etc/logrotate.d/c-icap
sudo chown root:root /etc/logrotate.d/c-icap
```

Restart services

```bash
sudo systemctl restart clamav-daemon.service
sudo systemctl restart clamav-freshclam.service
sudo systemctl restart c-icap.service
sudo systemctl restart squid.service
```

You may reload icap configuration without complete restart

```bash
sudo sh -c 'echo -n "squidclamav:cfgreload" > /var/run/c-icap/c-icap.ctl'
sudo sh -c 'echo -n "reconfigure" > /var/run/c-icap/c-icap.ctl'
```

Few recommendations:
- install `clamav-unofficial-sigs` script to update ClamAV databases
- use safebrowsing only if really needed

### ClamAV high memory and CPU consumption

Run

```bash
sudo systemctl edit clamav-daemon.service
```

Set configuration and save

```
[Service]
CPUQuota=50%
CPUSchedulingPolicy=rr
CPUSchedulingPriority=25
Nice=10
```

Reload service

```bash
sudo systemctl daemon-reload
sudo systemctl restart clamav-daemon.service
```

### Very slow scans

By default all content will be scanned by ClamAV, it is possible to change this behavior by changing `/etc/c-icap/squidclamav.conf` file

```
enable_libarchive 1
scan_mode ScanNothingExcept
scan ^.*\.(pdf|doc|docx|xls|xlsx|xlsm|ppt|pptx)$
scan ^.*\.(zip|rar)$
scan ^.*\.(exe|com|vbs|js|json)$
scancontent ^application\/.*$
```

Or keep default mode, and drop content like images, audio, video, fonts, etc.

```
enable_libarchive 1
scan_mode ScanAllExcept
abort ^.*\.(ico|gif|png|jpg|jpeg|svg)$
abort ^.*\.(woff|ttf|otf)$
abortcontent ^image\/.*$
abortcontent ^audio\/.*$
abortcontent ^video\/.*$
abortcontent ^application\/font\-.*$
```


### MalwarePatrol script

You may want to download MalwarePatrol Squid ACL lists to be able to use `malware_block_list` option. Save the script below as `malware_list_update.sh`, change two variables `RECEIPT_ID` and `PRODUCT_ID`, set executable flag like `chmod +x malware_list_update.sh`, and import it as a new crontab task.

```bash
#!/usr/bin/env bash

exists()
{
  command -v "$1" >/dev/null 2>&1
}

if ! exists curl ; then
  echo 'Error: curl is not installed'
  exit 1
fi

if ! exists squid ; then
  echo 'Error: squid is not installed'
  exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo 'Error: run as root'
  exit 1
fi

RECEIPT_ID="" # change me
PRODUCT_ID="" # change me

curl -fsSL "https://lists.malwarepatrol.net/cgi/getfile?receipt=${RECEIPT_ID}&product=${PRODUCT_ID}&list=squid" -o /etc/squid/malware_block_list
curl -fsSL "https://lists.malwarepatrol.net/cgi/getfile?receipt=${RECEIPT_ID}&product=${PRODUCT_ID}&list=squid&hash=1" -o /etc/squid/malware_block_list.md5

integrity_check=0

if [ $(wc -l /etc/squid/malware_block_list.md5 | cut -d' ' -f 1) -gt 2 ]; then
  echo 'Warning: skipping integrity check due to license limitation'
else
  md5a="$(md5sum /etc/squid/malware_block_list | awk '{print $1}')"
  md5b="$(cat /etc/squid/malware_block_list.md5)"
  if [[ "$md5a" == "$md5b" ]]; then
    echo 'Info: integrity check succeeded'
    integrity_check=1
  else
    echo 'Error: integrity check failed'
    integrity_check=0
  fi
fi

if [ $integrity_check -eq 1 ]; then
  echo 'Info: reloading squid'
  sed -i 's#\^https\?\\:\\/\\/#\^\(http\|https\)\\:\\/\\/#g' /etc/squid/malware_block_list
  chmod 0644 /etc/squid/malware_block_list
  chmod 0644 /etc/squid/malware_block_list.md5
  systemctl reload squid.service
else
  echo 'Warning: squid reload skipped'
fi
```

Make sure blocklist files downloaded successfully, then uncomment two `malware_block_list` lines in Squid configuration file

### BlackWeb script

Alternative free version

```bash
#!/usr/bin/env bash

exists()
{
  command -v "$1" >/dev/null 2>&1
}

if ! exists curl ; then
  echo 'Error: curl is not installed'
  exit 1
fi

if ! exists squid ; then
  echo 'Error: squid is not installed'
  exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo 'Error: run as root'
  exit 1
fi

curl -fsSL "https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.tar.gz" -o /tmp/blackweb.tar.gz
curl -fsSL "https://raw.githubusercontent.com/maravento/blackweb/master/checksum.md5" -o /etc/squid/blackweb_block_list.md5

tar -xzf /tmp/blackweb.tar.gz -C /etc/squid/ blackweb.txt
mv /etc/squid/blackweb.txt /etc/squid/blackweb_block_list

integrity_check=0

if [ $(wc -l /etc/squid/blackweb_block_list.md5 | cut -d' ' -f 1) -gt 2 ]; then
  echo 'Warning: skipping integrity check due to license limitation'
else
  md5a="$(md5sum /etc/squid/blackweb_block_list | awk '{print $1;}')"
  md5b="$(cat /etc/squid/blackweb_block_list.md5 | awk '{print $1;}')"
  if [[ "$md5a" == "$md5b" ]]; then
    echo 'Info: integrity check succeeded'
    integrity_check=1
  else
    echo 'Error: integrity check failed'
    integrity_check=0
  fi
fi

if [ $integrity_check -eq 1 ]; then
  echo 'Info: reloading squid'
  chmod 0644 /etc/squid/blackweb_block_list
  chmod 0644 /etc/squid/blackweb_block_list.md5
  systemctl reload squid.service
else
  echo 'Warning: squid reload skipped'
fi
```

Add it to `squid.conf` file

```
acl blackweb dstdomain "/etc/squid/blackweb_block_list"
http_access deny blackweb
```

## References

https://wiki.squid-cache.org/Features/SslPeekAndSplice

https://support.kaspersky.com/KWTS/6.1/en-US/181866.htm

https://github.com/extremeshok/clamav-unofficial-sigs

https://squidclamav.darold.net/documentation.html

https://docs.diladele.com/administrator_guide_stable/install/debian10/index.html

