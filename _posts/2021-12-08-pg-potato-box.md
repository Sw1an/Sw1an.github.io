---
title: Potato Easy box on Offensive Security Proving Grounds - OSCP Preparation.
tags: [oscp easy box, PG easy box, enumeration, strcmp, privilege escalation, sudo, linux]
categories: [OSCP, Proving Grounds]
comments: true
date: 2021-12-08 11:33:00
---

Hello,

We are going to exploit one of [OffSec Proving Grounds](https://portal.offensive-security.com/proving-grounds/play) easy machines which called `Potato` and this post is not a fully detailed walkthrough, I will just go through the important points during the exploit process.


## Enumeration:
- Nmap:
![nmap](../../assets/img/sample/pg-potato/nmap.png)

- FTP Anon Login:
![ftp-anon](../../assets/img/sample/pg-potato/ftp-anon.png)

- Content of `index.php.bak` file:

```php
<html>
<head></head>
<body>
<?php
$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>
  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>
```

- Authentication Bypass:

So if you get a close look at the source code above you will notice that the application uses [strcmp](https://www.doyler.net/security-not-included/bypassing-php-strcmp-abctf2016) on line `8` to check for the username and password and that can be bypassed with `username[]=""&password[]=""` like shown bellow.

![strcmp-bypass](../../assets/img/sample/pg-potato/strcmp.png)

- Exploit Local File Inclusion (LFI):

As you can see in the picture bellow there's a password for the user `webadmin` in `/etc/passwd`: 
![strcmp-bypass](../../assets/img/sample/pg-potato/lfi.png)


- Crack the password for `webadmin` user using `john`:
![crack-passwd](../../assets/img/sample/pg-potato/crack.png)

## Privilege Escalation:

- sudo -l:
![sudo-l](../../assets/img/sample/pg-potato/sudo-l.png)

- Getting root:

![root](../../assets/img/sample/pg-potato/root.png)


Happy Hacking!