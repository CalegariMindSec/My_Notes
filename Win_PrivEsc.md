## Windows PrivEsc CheatSheet

My Windows PrivEsc CheatSheet with example machines.

**REFS:** https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

**REFS:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

**REFS:** https://lolbas-project.github.io/#pd

### <-- Kernel Exploits -->

1 - Windows Exploit Suggester

    https://github.com/AonCyberLabs/Windows-Exploit-Suggester

**Refs:** https://github.com/SecWiki/windows-kernel-exploits

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/blob/main/windows_boxes/devel/writeup.md

### <-- Password Reuse and ICALCS -->

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/blob/main/windows_boxes/chatterbox/README.md

### <-- Impersonation -->

Comandos:

    whoami /priv

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/tree/main/windows_boxes/jeeves#privilege-escalation

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- keePass Storage Key -->

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/tree/main/windows_boxes/jeeves#privilege-escalation

### <-- Runas -->

Comandos:

    cmdkey /list - (Listar Save Credentials)
    runas /savecred

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---runas

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/blob/main/windows_boxes/access/README.md

    Exemplo: runas.exe /netonly /user:<domain>\<username> cmd.exe

### <-- Dump Proccess -->

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/blob/main/windows_boxes/heist/writeup.md

### <-- AlwaysInstallElevated -->

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---alwaysinstallelevated

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/blob/main/windows_boxes/love/README.md

**THM WriteUp:** https://tryhackme.com/room/windowsprivesc20

### <-- DPAPI -->

**HTB WriteUp:** https://github.com/CalegariMindSec/HTB_Writeups/blob/main/windows_boxes/access/README.md

### <-- Unattended Windows Installations -->

Files:

    C:\Unattend.xml
    C:\Windows\Panther\Unattend.xml
    C:\Windows\Panther\Unattend\Unattend.xml
    C:\Windows\system32\sysprep.inf
    C:\Windows\system32\sysprep\sysprep.xml

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#passwords-in-unattendxml

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- Powershell History -->

Commands:

    type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

**Refs**: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#powershell-history

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- Powershell Transcript -->

**Refs**: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#powershell-transcript

### <-- IIS Config File -->

Comando

    Get-Childitem –Path C:\PATH\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#iis-web-config

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- Scheduled Tasks -->

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---processes-enumeration-and-tasks

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- Insecure Permissions on Service Executable -->

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---incorrect-permissions-in-services

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- Unquoted Service Paths -->

**Refs:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---unquoted-service-paths

**THM Room:** https://tryhackme.com/room/windowsprivesc20

### <-- Unpatched Software -->

Comandos:

    wmic product get name,version,vendor

**THM Room:** https://tryhackme.com/room/windowsprivesc20
