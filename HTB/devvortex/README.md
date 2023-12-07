# Target : 10.10.11.242 aka devvortex.htb

# Reconnaissance (aka intelligence)

## 1. Scan ports

```
└─$ nmap -sV -A -p 80,22 10.10.11.242
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-03 05:11 EST
Nmap scan report for 10.10.11.242
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.33 seconds


```

## 2. Check 80 port in browser

![plot](./1.png)

## 3. Enumerate directories and files

```
└─$ gobuster dir -u http://devvortex.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://devvortex.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 178] [--> http://devvortex.htb/css/]
/images               (Status: 301) [Size: 178] [--> http://devvortex.htb/images/]
/index.html           (Status: 200) [Size: 18048]
/js                   (Status: 301) [Size: 178] [--> http://devvortex.htb/js/]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================

```

Nothing interesting. Well, let's try to sort out the virtual hosts

## 4. Enumerate vhosts

Run gobuster with parameter **vhost** parameter **--apend-domain** and wordlist **subdomains-top1million-5000.txt**
```
└─$ gobuster vhost -u devvortex.htb -r -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20 --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://devvortex.htb
[+] Method:          GET
[+] Threads:         20
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb Status: 200 [Size: 23221]
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
```

And we find virtual host dev.devvortex.htb

**change /etc/hosts for access this domain**

## 5. Go to this vhost with browser

![plot](./2.png)

We see the some web-app

Try to enumerating this site

![plot](./3.png)

Find **/administrator** url. This is Joomla administrator panel.

You can find out the version of Joomla and look for public exploits.

```
We also find robots.txt

# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

Later we make sure that all the URLs that we found coincide with the **robots.txt** file

```
└─$ dirb http://dev.devvortex.htb

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Dec  7 15:03:24 2023
URL_BASE: http://dev.devvortex.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://dev.devvortex.htb/ ----
==> DIRECTORY: http://dev.devvortex.htb/administrator/                                                                                                            
==> DIRECTORY: http://dev.devvortex.htb/api/                                                                                                                      
==> DIRECTORY: http://dev.devvortex.htb/cache/                                                                                                                    
==> DIRECTORY: http://dev.devvortex.htb/components/                                                                                                               
+ http://dev.devvortex.htb/home (CODE:200|SIZE:23221)                                                                                                             
==> DIRECTORY: http://dev.devvortex.htb/images/                                                                                                                   
==> DIRECTORY: http://dev.devvortex.htb/includes/                                                                                                                 
+ http://dev.devvortex.htb/index.php (CODE:200|SIZE:23221)                                                                                                        
==> DIRECTORY: http://dev.devvortex.htb/language/                                                                                                                 
==> DIRECTORY: http://dev.devvortex.htb/layouts/                                                                                                                  
==> DIRECTORY: http://dev.devvortex.htb/libraries/                                                                                                                
==> DIRECTORY: http://dev.devvortex.htb/media/                                                                                                                    
==> DIRECTORY: http://dev.devvortex.htb/modules/                                                                                                                  
==> DIRECTORY: http://dev.devvortex.htb/plugins/                                                                                                                  
+ http://dev.devvortex.htb/robots.txt (CODE:200|SIZE:764)                                                                                                         
==> DIRECTORY: http://dev.devvortex.htb/templates/                                                                                                                
==> DIRECTORY: http://dev.devvortex.htb/tmp/  
```

Further we find script in metasploit for getting Joomla version

```
sudo msfdb start
sudo msfconsole

msf6 > search joomla

msf6 > use auxiliary/scanner/http/joomla_version

msf6 auxiliary(scanner/http/joomla_version) > show options

Module options (auxiliary/scanner/http/joomla_version):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the Joomla application
   THREADS    1                yes       The number of concurrent threads (max one per host)
   VHOST                       no        HTTP server virtual host

msf6 auxiliary(scanner/http/joomla_version) > set RHOSTS 10.10.11.242
RHOSTS => 10.10.11.242
msf6 auxiliary(scanner/http/joomla_version) > set VHOST dev.devvortex.htb
VHOST => dev.devvortex.htb
msf6 auxiliary(scanner/http/joomla_version) > run

[*] Server: nginx/1.18.0 (Ubuntu)
[+] Joomla version: 4.2.6
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

Find version Joomla CMS 4.2.6

Looking for public exploits for this version Joomla in google and find fresh vulnerability CVE-2023-23752. 
We are also looking for an exploit and find this PoC https://github.com/adhikara13/CVE-2023-23752


# Initial access and exploitation 

