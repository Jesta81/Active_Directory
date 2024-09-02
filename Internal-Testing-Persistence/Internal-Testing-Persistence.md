## Internal Testing Persistence

### Valid credentials

> - Username: srvadm
> - Password: ILFreightnixadm!

Now that we have a stable connection via SSH, we can start enumerating further.


### Local Privilege Escalation

> - We could upload an enumeration script to the system such as [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), but I always try two simple commands after gaining access: **id** to see if the compromised account is in any privileged local groups, and **sudo -l** to see if the account has any type of **sudo** privileges to run commands as another user or as root. By now, we have practiced many privilege escalation techniques in both Academy modules and perhaps some boxes on the HTB main platform. It's great to have these techniques in our back pocket, especially if we land on a very hardened system. However, we are dealing with human administrators, and humans make mistakes and also go for convenience. More often than not, my path to escalating privileges on a Linux box during a pentest was not some wildcard attack leveraging tar and a cron job, but rather something simple such as **sudo su** without a password to gain root privileges or not having to escalate privileges because the service I exploited was running in the context of the root account. It's still necessary to understand and practice as many techniques as possible because, as said a few times now, every environment is different, and we want to have the most comprehensive toolkit possible at our disposal.

![Privilege Escalation](/Internal-Testing-Persistence/images/priv-check.png) 

> - Running **sudo -l**, we see that we can run the **/usr/bin/openssl** command as root without requiring a password. As suspected, there is a [GTFOBin](https://gtfobins.github.io/gtfobins/openssl/) for the OpenSSL binary. The entry shows various ways this can be leveraged: to upload and download files, gain a reverse shell, and read and write files. Let's try this to see if we can grab the SSH private key for the root user. This is ideal over just attempting to read the **/etc/shadow** file or obtain a reverse shell as the **ida_rsa** private key file will grant us SSH back into the environment as the root user, which is perfect for setting up our pivots.

> - The entry states that we can use the binary for privileged file reads as follows:

![Privilege Escalation](/Internal-Testing-Persistence/images/priv-esc.png) 


## Establishing Persistence 

> - Success! We can now save the private key to our local system, modify the privileges, and use it to SSH as root and confirm root privileges.

![Persistence](/Internal-Testing-Persistence/images/persistence-1.png) 

![Persistence Cont.](/Internal-Testing-Persistence/images/persistence-2.png)


> - It worked, and we're in and now have a "save point" to get back into the internal environment quickly and can use this SSH access to set up port forwards and pivot internally.
