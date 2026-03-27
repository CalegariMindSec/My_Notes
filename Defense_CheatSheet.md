# Defense CheatSheet

Summary:

- [Detection Engineering](#detection-engineering)

# Detection Engineering

Summary:

- [Threat Hunting](#threat-hunting)

## Threat Hunting

Summary:

- [Get-WinEvent - cmdlet (CheatSheet)](#get-winevent---cmdlet-cheatsheet)

### Get-WinEvent - cmdlet (CheatSheet)

Summary: 

- [Command - Retrieve Properties list](#command---retrieve-properties-list)
- [Command - Retrieve EventId event (Message)](#command---retrieve-eventid-event-message)
- [Command - Retrieve EventId event (Full)](#command---retrieve-eventid-event-full)
- [Command - Table-Like Output](#command---retrieve-matching-results)

#### Command - Retrieve Properties list

**Description:**

> Extracts the parameters (EventData fields) of a single specified Event ID from `.evtx` logs and maps each field to its corresponding index in the `Properties` array.

**Command:**

```powershell
$event = Get-WinEvent -Path "C:\PATH\LOG\*.evtx" |
Where-Object { $_.Id -eq [EventID] } |
Select-Object -First 1

[xml]$xml = $event.ToXml()

for ($i=0; $i -lt $xml.Event.EventData.Data.Count; $i++) {
    "$i - $($xml.Event.EventData.Data[$i].Name)"
```

**Example:**

```powershell
PS C:\Users\Administrator> $event = Get-WinEvent -Path "C:\Logs\StrangePPID\*.evtx" |
>> Where-Object { $_.Id -eq 8 } |
>> Select-Object -First 1
>>
>> [xml]$xml = $event.ToXml()
>>
>> for ($i=0; $i -lt $xml.Event.EventData.Data.Count; $i++) {
>>     "$i - $($xml.Event.EventData.Data[$i].Name)"
>> }
0 - RuleName
1 - UtcTime
2 - SourceProcessGuid
3 - SourceProcessId
4 - SourceImage
5 - TargetProcessGuid
6 - TargetProcessId
7 - TargetImage
8 - NewThreadId
9 - StartAddress
10 - StartModule
11 - StartFunction
12 - SourceUser
13 - TargetUser
PS C:\Users\Administrator>
```

#### Command - Retrieve EventId event (Message)

**Description:**

> Retrieves and displays the full details of the message of a single event with a specified Event ID from `.evtx` log files, including all available fields and values.

**Command:**

```powershell
$event = Get-WinEvent -Path "C:\PATH\LOG\*.evtx" |
Where-Object { $_.Id -eq [EventID] } |
Select-Object -First 1

[xml]$xml = $event.ToXml()

$xml.Event.EventData.Data | ForEach-Object {
    "$($_.Name) : $($_.'#text')"
}
```

**Example:**

```powershell
PS C:\Users\Administrator> $event = Get-WinEvent -Path "C:\Logs\StrangePPID\*.evtx" |
>> Where-Object { $_.Id -eq 1 } |
>> Select-Object -First 1
>>
>> [xml]$xml = $event.ToXml()
>>
>> $xml.Event.EventData.Data | ForEach-Object {
>>     "$($_.Name) : $($_.'#text')"
>> }
RuleName : -
UtcTime : 2022-04-28 02:18:06.800
ProcessGuid : {67e39d39-f95e-6269-8503-000000000300}
ProcessId : 8424
Image : C:\Windows\System32\whoami.exe
FileVersion : 10.0.19041.1 (WinBuild.160101.0800)
Description : whoami - displays logged on user information
Product : Microsoft® Windows® Operating System
Company : Microsoft Corporation
OriginalFileName : whoami.exe
CommandLine : whoami
CurrentDirectory : C:\ProgramData\
User : DESKTOP-R4PEEIF\waldo
LogonGuid : {67e39d39-ed25-6269-7000-170000000000}
LogonId : 0x170070
TerminalSessionId : 1
IntegrityLevel : Medium
Hashes : SHA1=1915FBFDB73FDD200C47880247ACDDE5442431A9,MD5=A4A6924F3EAF97981323703D38FD99C4,SHA256=1D4902A04D99E8CCBFE7085E63155955FEE397449D386453F6C452AE407B8743,IMPHASH=7FF0758B766F747CE57DFAC70743FB88
ParentProcessGuid : {67e39d39-f95e-6269-8303-000000000300}
ParentProcessId : 472
ParentImage : C:\Windows\System32\cmd.exe
ParentCommandLine : cmd.exe /c whoami
ParentUser : DESKTOP-R4PEEIF\waldo
PS C:\Users\Administrator>
```

#### Command - Retrieve EventId event (Full)

**Description:**

> Retrieves and displays the full details of a single event with a specified Event ID from `.evtx` log files, including all available fields and values.

**Command:**

```powershell
Get-WinEvent -Path "C:\PATH\LOG\*.evtx" |
Where-Object { $_.Id -eq [EventID] } |
Select-Object -First 1 |
Format-list *
```

**Example:**

```powershell
PS C:\Users\Administrator> Get-WinEvent -Path "C:\Logs\StrangePPID\*.evtx" |
>> Where-Object { $_.Id -eq 1 } |
>> Select-Object -First 1 |
>> Format-list *


Message              : Process Create:
                       RuleName: -
                       UtcTime: 2022-04-28 02:18:06.800
                       ProcessGuid: {67e39d39-f95e-6269-8503-000000000300}
                       ProcessId: 8424
                       Image: C:\Windows\System32\whoami.exe
                       FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
                       Description: whoami - displays logged on user information
                       Product: Microsoft® Windows® Operating System
                       Company: Microsoft Corporation
                       OriginalFileName: whoami.exe
                       CommandLine: whoami
                       CurrentDirectory: C:\ProgramData\
                       User: DESKTOP-R4PEEIF\waldo
                       LogonGuid: {67e39d39-ed25-6269-7000-170000000000}
                       LogonId: 0x170070
                       TerminalSessionId: 1
                       IntegrityLevel: Medium
                       Hashes: SHA1=1915FBFDB73FDD200C47880247ACDDE5442431A9,MD5=A4A6924F3EAF97981323703D38FD99C4,SHA256=1D4902A04D99E8CCBFE7085E63155955FEE397449D386453F6C452AE407B8743,IMPHASH=7FF0758B766F747CE57DFAC70743FB88
                       ParentProcessGuid: {67e39d39-f95e-6269-8303-000000000300}
                       ParentProcessId: 472
                       ParentImage: C:\Windows\System32\cmd.exe
                       ParentCommandLine: cmd.exe /c whoami
                       ParentUser: DESKTOP-R4PEEIF\waldo
Id                   : 1
Version              : 5
Qualifiers           :
Level                : 4
Task                 : 1
Opcode               : 0
Keywords             : -9223372036854775808
RecordId             : 1536142
ProviderName         : Microsoft-Windows-Sysmon
ProviderId           : 5770385f-c22a-43e0-bf4c-06f5698ffbd9
LogName              : Microsoft-Windows-Sysmon/Operational
ProcessId            : 2940
ThreadId             : 3748
MachineName          : DESKTOP-R4PEEIF
UserId               : S-1-5-18
TimeCreated          : 4/27/2022 7:18:06 PM
ActivityId           :
RelatedActivityId    :
ContainerLog         : c:\logs\strangeppid\strangeppid.evtx
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Process Create (rule: ProcessCreate)
KeywordsDisplayNames : {}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty, System.Diagnostics.Eventing.Reader.EventProperty...}
PS C:\Users\Administrator>
```

#### Command - Retrieve Matching Results

**Description:**

> Filters events based on specified conditions and extracts the value of a specific field from the matching results.

**Command:**

```powershell
Get-WinEvent -Path "C:\PATH\LOG\*.evtx" |
Where-Object {
    $_.Id -eq [EventID] -and
    $_.Properties[Property_Array_Value].Value -eq "[Filter]"
} |
Select-Object @{
    Name="[Field_Name]"; Expression = { $_.Properties[Property_Array_Value].Value }
}
```

**Example:**

```powershell
PS C:\Users\Administrator> Get-WinEvent -Path "C:\Logs\Dump\LsassDump.evtx" |
>> Where-Object {
>>     $_.Id -eq 10 -and
>>     $_.Properties[8].Value -eq "C:\Windows\System32\lsass.exe"
>> } |
>> Select-Object @{
>>     Name="Injector"; Expression = { $_.Properties[5].Value }
>> }
Injector
--------
C:\Windows\system32\svchost.exe
```

#### Command - Table-Like Output

**Description:**

> Formats the output to display selected fields side by side in a table-like structure.

**Command:**

```powershell
Get-WinEvent -Path "C:\PATH\LOG\*.evtx" |
Where-Object { $_.Id -eq [EventID] } |
Select-Object @{
    Name="[Field_Name]"; Expression = { $_.Properties[Property_Array_Value].Value }
}, @{
    Name="[Field_Name]"; Expression = { $_.Properties[Property_Array_Value].Value }
}
```

**Example:**

```powershell
PS C:\Users\Administrator> Get-WinEvent -Path "C:\Logs\StrangePPID\*.evtx" |
>> Where-Object { $_.Id -eq 1 } |
>> Select-Object @{
>>     Name="Process"; Expression = { $_.Properties[4].Value }
>> }, @{
>>     Name="ParentProcess"; Expression = { $_.Properties[20].Value }
>> }

Process                          ParentProcess
-------                          -------------
C:\Windows\System32\whoami.exe   C:\Windows\System32\cmd.exe
C:\Windows\System32\conhost.exe  C:\Windows\System32\cmd.exe
C:\Windows\System32\cmd.exe      C:\Windows\System32\WerFault.exe
C:\Windows\System32\WerFault.exe C:\Windows\explorer.exe
```

#### 













