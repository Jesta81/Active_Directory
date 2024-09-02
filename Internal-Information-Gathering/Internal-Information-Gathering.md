## Internal Information Gathering

We've covered a ton of ground so far:


> - Performed external information gathering
> - Performed external port and service scanning
> - Enumerated multiple services for misconfigurations and known vulnerabilities
> - Enumerated and attacked 12 different web applications, with some resulting in no access, others granting file read or sensitive data access, and a few resulting in remote code execution on the underlying web server
> - Obtained a hard-fought foothold in the internal network
> - Performed pillaging and lateral movement to gain access as a more privileged user
> - Escalated privileges to root on the web server
> - Established persistence through the use of both a user/password pair and the root account's private key for fast SSH access back into the environment

### Setting Up Pivoting - SSH

#### Dynamic Port Forwarding

> - With a copy of the root **id_rsa** (private key) file, we can use SSH port forwarding along with [ProxyChains](https://github.com/haad/proxychains) to start getting a picture of the internal network. To review this technique, check out the [Dynamic Port Forwarding with SSH and SOCKS Tunneling](https://academy.hackthebox.com/module/158/section/1426) section of the **Pivoting, Tunneling, and Port Forwarding** module.

> - We can use the following command to set up our SSH pivot using dynamic port forwarding: **ssh -D 8081 -i dmz01_key root@10.129.x.x**. This means we can proxy traffic from our attack host through port 8081 on the target to reach hosts inside the 172.16.8.0/23 subnet directly from our attack host.

> - In our first terminal, let's set up the SSH dynamic port forwarding command first:

![Dynamic SSH Tunneling](/Internal-Information-Gathering/images/Dynamic-SSH.png) 

We can confirm that the dynamic port forward is set up using Netstat or running an Nmap scan against our localhost address.

![Netstat](/Internal-Information-Gathering/images/netstat.png) 

Next, we need to modify the **/etc/proxychains.conf** to use the port we specified with our dynamic port forwarding command (8081 here).

![Proxychains Conf](/Internal-Information-Gathering/images/proxychaing-conf.png) 

Next, we can use Nmap with Proxychains to scan the dmz01 host on its' second NIC, with the IP address **172.16.8.120** to ensure everything is set up correctly.

![Proxy-nmap](/Internal-Information-Gathering/images/proxy-nmap.png) 



### Setting Up Pivoting - Metasploit

Alternatively, we can set up our pivoting using Metasploit, as covered in the [Meterpreter Tunneling & Port Forwarding](https://academy.hackthebox.com/module/158/section/1428) section of the Pivoting module. To achieve this, we can do the following:

1. > - First, generate a reverse shell in Elf format using **msfvenom**.

![msfvenom payload](/Internal-Information-Gathering/images/msfvenom.png) 

2. > - Next, transfer the host to the target. Since we have SSH, we can upload it to the target using SCP.

![Copy payload](/Internal-Information-Gathering/images/scp.png) 

	$ scp -i root.key evil.elf root@10.129.229.147

3. > - Now, we'll set up the **Metasploit exploit/multi/handler**. 

![Multi-Handler](/Internal-Information-Gathering/images/metasploit.png) 

4. > - Execute the **shell.elf** file on the target system:

![Pwn](/Internal-Information-Gathering/images/pwn.png) 

5. > - If all goes as planned, we'll catch the Meterpreter shell using the multi/handler, and then we can set up routes.

![meterpreter](/Internal-Information-Gathering/images/meterpreter.png) 

6. > - Next, we can set up routing using the **post/multi/manage/autoroute** module.

![Metasploit Post autoroute](/Internal-Information-Gathering/images/autoroute.png) 

![Set Routes](/Internal-Information-Gathering/images/route-config.png) 


For a refresher, consult the [Crafting Payloads with MSFvenom](https://academy.hackthebox.com/module/115/section/1205) section of the **Shells & Payloads** module and the [Introduction to MSFVEnom](https://academy.hackthebox.com/module/39/section/418) section of the **Using the Metasploit Framework** module.


### Host Discovery - 172.16.8.0/23 Subnet - Metasploit

Once both options are set up, we can begin hunting for live hosts. Using our Meterpreter session, we can use the **multi/gather/ping_sweep** module to perform a ping sweep of the **172.16.8.0/23 subnet**.

![Ping Sweep](/Internal-Information-Gathering/images/ping-sweep-config.png) 


![Ping Environment](/Internal-Information-Gathering/images/ping-sweep-run.png) 


### Host Discovery - 172.16.8.0/23 Subnet - SSH Tunnel

Alternatively, we could do a ping sweep or use a [static Nmap binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) from the dmz01 host.

We get quick results with this Bash one-liner ping sweep:

![Bash Ping](/Internal-Information-Gathering/images/bash-ping-sweep.png) 

![Bash run sweep](/Internal-Information-Gathering/images/bash-ping-run.png) 

We could also use Nmap through Proxychains to enumerate hosts in the 172.16.8.0/23 subnet, but it will be very slow and take ages to finish.

Our host discovery yields three additional hosts:

> - 172.16.8.3
> - 172.16.8.20
> - 172.16.8.50
> - 172.16.8.120

We can now dig deeper into each of these hosts and see what we turn up.


### Host Enumeration

Let's continue our enumeration using a static Nmap binary from the dmz01 host. Try uploading the binary using one of the techniques taught in the [File Transfers](https://academy.hackthebox.com/module/24/section/159) module. 


#### Nmap scan on internal 172.16.x.x hosts

> - 172.16.8.3

![Nmap 1](/Internal-Information-Gathering/images/nmap-1.png) 


> - 172.16.8.20 & 172.16.8.50

![Nmap 2](/Internal-Information-Gathering/images/nmap-2.png) 


> - 172.16.8.120

![Nmap 3](/Internal-Information-Gathering/images/nmap-3.png) 


From the Nmap output, we can gather the following:


> - 172.16.8.3 is a Domain Controller because we see open ports such as Kerberos and LDAP. We can likely leave this to the side for now as its unlikely to be directly exploitable (though we can come back to that)
> - 172.16.8.20 is a Windows host, and the ports 80/HTTP and 2049/NFS are particularly interesting
> - 172.16.8.50 is a Windows host as well, and port 8080 sticks out as non-standard and interesting

We could run a full TCP port scan in the background while digging into some of these hosts.


### Active Directory Quick Hits - SMB NULL SESSION

We can quickly check against the Domain Controller for SMB NULL sessions. If we can dump the password policy and a user list, we could try a measured password spraying attack. If we know the password policy, we can time our attacks appropriately to avoid account lockout. If we can't find anything else, we could come back and use **Kerbrute** to enumerate valid usernames from various user lists and after enumerating (during a real pentest) potential usernames from the company's LinkedIn page. With this list in hand, we could try 1-2 spraying attacks and hope for a hit. If that still does not work, depending on the client and assessment type, we could ask them for the password policy to avoid locking out accounts. We could also try an ASREPRoasting attack if we have valid usernames, as discussed in the **Active Directory Enumeration & Attacks** module.


### 172.16.8.50 - Tomcat

Our earlier Nmap scan showed port 8080 open on this host. Browsing to **http://172.16.8.50:8080** shows the latest version of Tomcat 10 installed. Though there are no public exploits for it, we can try to brute-force the Tomcat Manager login as shown in the [Attacking Tomcat](https://academy.hackthebox.com/module/113/section/1211) section of the **Attacking Common Applications** module. We can start another instance of Metasploit using Proxychains by typing **proxychains msfconsole** to be able to pivot through the compromised dmz01 host if we don't have routing set up via a Meterpreter session. We can then use the **auxiliary/scanner/http/tomcat_mgr_login** module to attempt to brute-force the login.


![Metasploit Tomcat login](/Internal-Information-Gathering/images/metasploit-tomcat-login.png) 

We do not get a successful login, so this appears to be a dead-end and not worth exploring further. If we came across a Tomcat Manager login page exposed to the internet, we'd probably want to record it as a finding since an attacker could potentially brute-force it and use it to obtain a foothold. During an internal, we would only want to report it if we could get in via weak credentials and upload a JSP web shell. Otherwise, seeing on an internal network is normal if it is well locked down.


### Enumerating 172.16.8.20 - DotNetNuke (DNN)

From the Nmap scan, we saw ports **80 and 2049 open**. Let's dig into each of these. We can check out what's on port 80 using **cURL** from our attack host using the command **proxychains curl http://172.16.8.20**. From the HTTP response, it looks like [DotNetNuke (DNN)](https://www.dnnsoftware.com/) is running on the target. This is a CMS written in .NET, basically the WordPress of .NET. It has suffered from a few critical flaws over the years and also has some built-in functionality that we may be able to take advantage of. We can confirm this by browsing directly to the target from our attack host, passing the traffic through the SOCKS proxy.

We can set this up in Firefox as follows:

![Firefox SOCKS proxy](/Internal-Information-Gathering/images/firefox-proxy.png) 

> - Click on settings and type Proxy into the search bar.
> - Click "Manual proxy configuration" 
> - In "SOCKS Host" field input "127.0.0.1"
> - In Port field insert 8081
> - Select SOCKS v5 and hit OK.

Browsing to the page confirms our suspicions.

![DotNetNuke](/Internal-Information-Gathering/images/dnn.png) 

Browsing to **http://172.16.8.20/Login?returnurl=%2fadmin** shows us the admin login page. There is also a page to register a user. We attempt to register an account but receive the message:

> - An email with your details has been sent to the Site Administrator for verification. You will be notified by email when your registration has been approved. In the meantime you can continue to browse this site.

In my experience, it is highly unlikely that any type of site administrator will approve a strange registration, though it's worth trying to cover all of our bases.

Putting DNN aside, for now, we go back to our port scan results. Port 2049, NFS, is always interesting to see. If the NFS server is misconfigured (which they often are internally), we can browse NFS shares and potentially uncover some sensitive data. As this is a development server (due to the in-process DNN installation and the **DEV01** hostname) so it's worth digging into. We can use [showmount](https://linux.die.net/man/8/showmount) to list exports, which we may be able to mount and browse similar to any other file share. We find one export, **DEV01**, that is accessible to everyone (anonymous access). Let's see what it holds.


![showmount](/Internal-Information-Gathering/images/showmount.png) 


We can't mount the NFS share through Proxychains, but luckily we have root access to the dmz01 host to try. We see a few files related to DNN and a **DNN** subdirectory.

![mount DEV01](/Internal-Information-Gathering/images/mount.png) 

The **DNN** subdirectory is very interesting as it contains a **web.config file***. From our discussions on pillaging throughout the **Penetration Tester Path**, we know that config files can often contain credentials, making them a key target during any assessment.

Checking the contents of the web.config file, we find what appears to be the administrator password for the DNN instance.

![DNN Web creds](/Internal-Information-Gathering/images/dnn-web-creds.png) 

#### Creds

> - Username: Administrator
> - Password: D0tn31Nuk3R0ck$$@123


Before we move on, since we have root access on **dmz01** via SSH, we can run **tcpdump** as it's on the system. It can never hurt to "listen on the wire" whenever possible during a pentest and see if we can grab any cleartext credentials or generally uncover any additional information that may be useful for us. We'll typically do this during an Internal Penetration Test when we have our own physical laptop or a VM that we control inside the client's network. Some testers will run a packet capture the entire time (rarely, clients will even request this), while others will run it periodically during the first day or so to see if they can capture anything.


We could now transfer this down to our host and open it in **Wireshark** to see if we were able to capture anything. This is covered briefly in the [Interacting with Users](https://academy.hackthebox.com/module/67/section/630) section of the **Windows Privilege Escalation** module. For a more in-depth study, consult the Intro to [Network Traffic Analysis](https://academy.hackthebox.com/module/details/81) module.

![Wireshark](/Internal-Information-Gathering/images/wireshark.png) 

After transferring the file down to our host, we open it in Wireshark but see that nothing was captured. If we were on a user VLAN or other "busy" area of the network, we might have considerable data to dig through, so it's always worth a shot.


### Moving On

At this point, we have dug into the other "live" hosts we can reach and attempted to sniff network traffic. We could run a full port scan of these hosts as well, but we have plenty to move forward with for now. Let's see what we can do with the DNN credentials we obtained from the **web.config** file pillaged from the open NFS share.  
