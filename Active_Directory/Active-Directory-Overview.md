# Active Directory Overview

> Active Directory (AD) is a directory service for Windows network environments. It is a distributed, hierarchical structure that allows for centralized management of an organization’s resources, including users, computers, groups, network devices and file shares, group policies, servers and workstations, and trusts. AD provides authentication and authorization functions within a Windows domain environment. It was first shipped with Windows Server 2000; it has come under increasing attack in recent years. Designed to be backward-compatible, and many features are arguably not “secure by default,” and it can be easily misconfigured.

> This can be leveraged to move laterally and vertically within a network and gain unauthorized access. AD is essentially a large database accessible to all users within the domain, regardless of their privilege level. A basic AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to: 
>
> 1. Domain Computers
> 2. Domain Users
> 3. Domain Group Information
> 4. Default Domain Policy
> 5. Domain Functional Levels
> 6. Password Policy
> 7. Group Policy Objects (GPOs)
> 8. Kerberos Delegation
> 9. Domain Trusts
> 10. Access Control Lists (ACLs)

> This data will paint a clear picture of the overall security posture of an Active Directory environment. It can be used to quickly identify misconfigurations, overly permissive policies, and other ways of escalating privileges within an AD environment. Many attacks exist that merely leverage AD misconfigurations, bad practices, or poor administration, such as: 
>
> 1. Kerberoasting / ASREPRoasting
> 2. NTLM Relaying
> 3. Network traffic poisoning
> 4. Password spraying
> 5. Kerberos delegation abuse
> 6. Domain trust abuse
> 7. Credential theft
> 8. Object control

> Hardening Active Directory, along with a strong patching and configuration management policy, and proper network segmentation should be prioritized. If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels. Proper controls will help slow down an attacker and potentially force them to become noisier and risk detection.  

## Active Directory Structure

> Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains, which can themselves contain nested subdomains. A forest is the **security boundary** within which all objects are under administrative control. A forest may contain multiple domains, and a domain may contain further child or sub-domains. A domain is a structure within which contained objects (users, computers, and groups) are accessible. Objects are the most basic unit of data in AD.

> It contains many built-in **Organizational Units (OUs)**, such as “Domain Controllers,” “Users,” and “Computers,” and new OUs can be created as required. OUs may contain objects and sub-OUs, allowing for assignment of different group policies.

![AD Forests](/Active_Directory/images/AD-Forests.png) 

> We can see this structure graphically by opening **Active Directory Users and Computers** on a Domain Controller. In our lab domain **INLANEFREIGHT.LOCAL**, we see various OUs such as **Admin, Employees, Servers, Workstations, etc**. Many of these OUs have OUs nested within them, such as the **Mail Room OU** under **Employees**. This helps maintain a clear and coherent structure within Active Directory, which is especially important as we add Group Policy Objects (GPOs) to enforce settings throughout the domain. 

![AD Users and Computers](/Active_Directory/images/AD-Users-and-Computers.png) 

> Understanding the structure of Active Directory is paramount to perform proper enumeration and uncover the flaws and misconfigurations that sometimes have gone missed in an environment for many years. 


## Why Enumerate AD?

> As penetration testers, **enumeration** is one of, if not the most important, skills we must master. When starting an assessment in a new network gaining a comprehensive inventory of the environment is extremely important. The information gathered during this phase will inform our later attacks and even post-exploitation. Given the prevalence of AD in corporate networks, we will likely find ourselves in AD environments regularly, and therefore, it is important to hone our enumeration process. There are many tools and techniques to help with AD enumeration, which we will cover in-depth in this module and subsequent modules; however, before using these tools, it is important to understand the reason for performing detailed AD enumeration. 

> Whether we perform a penetration test or targeted AD assessment, we can always go above and beyond and provide our clients with extra value by giving them a detailed picture of their AD strengths and weaknesses. Corporate environments go through many changes over the years, adding and removing employees and hosts, installing software and applications that require changes in AD, or corporate policies that require GPO changes. These changes can introduce security flaws through misconfiguration, and it is our job as assessors to find these flaws, exploit them, and help our clients fix them. 


### Getting Started

> Once we have a foothold in an AD environment, we should start by gathering several key pieces of information, including but not limited to:
>
> 1. The domain functional level
> 2. The domain password policy
> 3. A full inventory of AD users
> 4. A full inventory of AD computers
> 5. A full inventory of AD groups and memberships
> 6. Domain trust relationships
> 7. Object ACLs
> 8. Group Policy Objects (GPO) information
> 9. Remote access rights

> With this information in hand, we can look for any "quick wins" such as our current user or the entire Domain Users group having RDP and/or local administrator access to one or more hosts. This is common in large environments for many reasons, one being the improper use of jump hosts and another being Citrix server Remote Desktop Services (RDS) misconfigurations. We should also check what rights our current user has in the domain. Are they a member of any privileged groups? Do they have any special rights delegated? Do they have any control over another domain object such as a user, computer, or GPO?

> The enumeration process is iterative. As we move through the AD environment, compromising hosts and users, we will need to perform additional enumeration to see if we have gained any further access to help us reach our goal.


## Rights and Privileges in AD 

> AD contains many groups that grant their members powerful rights and privileges. Many of these can be abused to escalate privileges within a domain and ultimately gain Domain Admin or SYSTEM privileges on a Domain Controller (DC). Some of these groups are listed below. 

### 1. Default Administrators
> - Domain Admins and Enterprise Admins "super" groups.

### 2. Server Operators
> - Members can modify services, access SMB shares, and backup files. 

### 3. Backup Operators
> - Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.

### 4. Print Operators
> - Members are allowed to logon to DCs locally and "trick" Windows into loading a malicious driver.

### 5. Hyper-V Administrators
> - If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins. 

### 6. Account Operators
> - Members can modify non-protected accounts and groups in the domain.

### 7. Remote Desktop Users
> - Members are not given any useful permissions by default but are often granted additional rights such as **Allow Login Through Remote Desktop Services** and can move laterally using the RDP protocol.

### 8. Remote Management Users
> - Members are allowed to logon to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).

### 9. Group Policy Creator Owners
> - Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.

### 10. Schema Admins
> - Members can modify the Active Directory schema structure and can backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL. 

### 11. DNS Admins
> - Members have the ability to load a DLL on a DC but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://cube0x0.github.io/Pocing-Beyond-DA/).


### Members of "Schema Admins"

	PS C:\> Get-ADGroup -Identity "Schema Admins" -Properties *


	adminCount                      : 1
	CanonicalName                   : INLANEFREIGHT.LOCAL/Users/Schema Admins
	CN                              : Schema Admins
	Created                         : 7/26/2020 1:14:37 PM
	createTimeStamp                 : 7/26/2020 1:14:37 PM
	Deleted                         :
	Description                     : Designated administrators of the schema
	DisplayName                     :
	DistinguishedName               : CN=Schema Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
	dSCorePropagationData           : {7/29/2020 8:52:30 PM, 7/29/2020 8:09:16 PM, 7/27/2020 6:45:00 PM, 7/27/2020 6:34:13
		                             PM...}
	GroupCategory                   : Security
	GroupScope                      : Universal
	groupType                       : -2147483640
	HomePage                        :
	instanceType                    : 4
	isCriticalSystemObject          : True
	isDeleted                       :
	LastKnownParent                 :
	ManagedBy                       :
	member                          : {CN=Jenna Smith,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL,
		                             CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}
	MemberOf                        : {CN=Denied RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}
	Members                         : {CN=Jenna Smith,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL,
		                             CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL}
	Modified                        : 9/25/2020 4:53:15 PM
	modifyTimeStamp                 : 9/25/2020 4:53:15 PM
	Name                            : Schema Admins
	nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
	ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
	ObjectClass                     : group
	ObjectGUID                      : 36eef5cb-92b1-47d2-a25d-b9d73783ed1e
	objectSid                       : S-1-5-21-2974783224-3764228556-2640795941-518
	ProtectedFromAccidentalDeletion : False
	SamAccountName                  : Schema Admins
	sAMAccountType                  : 268435456
	sDRightsEffective               : 0
	SID                             : S-1-5-21-2974783224-3764228556-2640795941-518
	SIDHistory                      : {}
	uSNChanged                      : 233800
	uSNCreated                      : 12336
	whenChanged                     : 9/25/2020 4:53:15 PM
	whenCreated                     : 7/26/2020 1:14:37 PM


## User Rights Assignment

> Depending on group membership, and other factors such as privileges assigned via Group Policy, users can have various rights assigned to their account. This Microsoft article on [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) provides a detailed explanation of each of the user rights that can be set in Windows.

> Typing the command **whoami /priv** will give you a listing of all user rights assigned to your current user. Some rights are only available to administrative users and can only be listed/leveraged when running an elevated cmd or PowerShell session. These concepts of elevated rights and User [Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) are security features introduced with Windows Vista to default to restricting applications from running with full permissions unless absolutely necessary. If we compare and contrast the rights available to us as an admin in a non-elevated console vs. an elevated console, we will see that they differ drastically. Let's try this out as the **htb-student** user on the lab machine. 

> Below are the rights available to a Domain Admin user.

### User Rights Non-Elevated

	PS C:\> whoami /priv

	PRIVILEGES INFORMATION
	----------------------

	Privilege Name                Description                          State
	============================= ==================================== ========
	SeShutdownPrivilege           Shut down the system                 Disabled
	SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
	SeUndockPrivilege             Remove computer from docking station Disabled
	SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
	SeTimeZonePrivilege           Change the time zone                 Disabled


### User Rights Elevated
> - If we run an elevated command (our htb-student user has local admin rights via nested group membership; the Domain Users group is in the local Administrators group), we can see the complete listing of rights available to us:

	PS C:\> whoami /priv

	PRIVILEGES INFORMATION
	----------------------

	Privilege Name                            Description                                                        State
	========================================= ================================================================== ========
	SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
	SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
	SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
	SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
	SeSystemProfilePrivilege                  Profile system performance                                         Disabled
	SeSystemtimePrivilege                     Change the system time                                             Disabled
	SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
	SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
	SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
	SeBackupPrivilege                         Back up files and directories                                      Disabled
	SeRestorePrivilege                        Restore files and directories                                      Disabled
	SeShutdownPrivilege                       Shut down the system                                               Disabled
	SeDebugPrivilege                          Debug programs                                                     Enabled
	SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
	SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
	SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
	SeUndockPrivilege                         Remove computer from docking station                               Disabled
	SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
	SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
	SeCreateGlobalPrivilege                   Create global objects                                              Enabled
	SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
	SeTimeZonePrivilege                       Change the time zone                                               Disabled
	SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
	SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
	
> - A standard domain user, in contrast, has drastically fewer rights.

### Domain User Rights

	PS C:\htb> whoami /priv

	PRIVILEGES INFORMATION
	----------------------

	Privilege Name                Description                    State
	============================= ============================== ========
	SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
	SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

> - User rights increase based on the groups they are placed in and/or their assigned privileges. Below is an example of the rights granted to users in the **Backup Operators group**. Users in this group do have other rights that are currently restricted by UAC. Still, we can see from this command that they have the **SeShutdownPrivilege**, which means that they can shut down a domain controller that could cause a massive service interruption should they log onto a domain controller locally (not via RDP or WinRM).


### Backup Operator Rights

	PS C:\htb> whoami /priv

	PRIVILEGES INFORMATION
	----------------------

	Privilege Name                Description                    State
	============================= ============================== ========
	SeShutdownPrivilege           Shut down the system           Disabled
	SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
	SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


### DNSAdmins Group

	PS C:\> Get-ADGroup -Identity "DNSAdmins" -Properties *


	CanonicalName                   : INLANEFREIGHT.LOCAL/Users/DnsAdmins
	CN                              : DnsAdmins
	Created                         : 7/26/2020 1:15:17 PM
	createTimeStamp                 : 7/26/2020 1:15:17 PM
	Deleted                         :
	Description                     : DNS Administrators Group
	DisplayName                     :
	DistinguishedName               : CN=DnsAdmins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
	dSCorePropagationData           : {7/29/2020 8:09:16 PM, 7/27/2020 6:45:00 PM, 7/27/2020 6:34:13 PM, 1/1/1601 10:16:33
		                             AM}
	GroupCategory                   : Security
	GroupScope                      : DomainLocal
	groupType                       : -2147483644
	HomePage                        :
	instanceType                    : 4
	isDeleted                       :
	LastKnownParent                 :
	ManagedBy                       :
	member                          : {CN=Hazel Lamb,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
	MemberOf                        : {}
	Members                         : {CN=Hazel Lamb,OU=Server Team,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL}
	Modified                        : 9/9/2020 9:42:29 PM
	modifyTimeStamp                 : 9/9/2020 9:42:29 PM
	Name                            : DnsAdmins
	nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
	ObjectCategory                  : CN=Group,CN=Schema,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
	ObjectClass                     : group
	ObjectGUID                      : 9ca8ad30-2c5d-4c5f-b624-ca1769d16d63
	objectSid                       : S-1-5-21-2974783224-3764228556-2640795941-1101
	ProtectedFromAccidentalDeletion : False
	SamAccountName                  : DnsAdmins
	sAMAccountType                  : 536870912
	sDRightsEffective               : 0
	SID                             : S-1-5-21-2974783224-3764228556-2640795941-1101
	SIDHistory                      : {}
	uSNChanged                      : 176510
	uSNCreated                      : 12483
	whenChanged                     : 9/9/2020 9:42:29 PM
	whenCreated                     : 7/26/2020 1:15:17 PM

