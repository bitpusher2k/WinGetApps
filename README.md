           Bitpusher
            \`._,'/
            (_- -_)
              \o/
          The Digital
              Fox
          @VinceVulpes
    https://theTechRelay.com
 https://github.com/bitpusher2k

# WinGetApps

## Script to install/update applications with WinGet suitable for scheduled or remote use

## By Bitpusher/The Digital Fox

## v2.4 last updated 2024-03-07

Script to to use WinGet to check if specified apps are installed and optionally install if not/upgrade if they are.
Capable of being run remotely in the background on an endpoint from system context (PS Remoting/RMM use).
Will attempt to install WinGet and its dependencies if it is not found. Will attempt to also run updates in
user space if a user is logged in when run.

Caution: WinGet will terminate programs it is attempting to update. Beware of updating apps on systems while they are in use.

Usage:
powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -AppIdList "7zip.7zip","Mozilla.Thunderbird","Google.Chrome","Mozilla.Firefox" -Install 1 -Upgrade 1

Using email reporting:
powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -AppIdList "7zip.7zip","Mozilla.Thunderbird","Google.Chrome","Mozilla.Firefox" -Install 1 -Upgrade 1 -RandMax 100  -emailServer "smtpo.yourmailserver.com" -emailUsername "username@yourmailserver.com" -emailPassword "XXXXXXXX" -emailFrom "username@yourmailserver.com" -emailTo "reports+winget@yourmailserver.com"

Test what installs/updates are possible:
powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -AppIdList "7zip.7zip","Mozilla.Thunderbird","Google.Chrome","Mozilla.Firefox" -Install 0 -Upgrade 0

Upgrade all apps possible for WinGet to manage:
powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -UpgradeAll 1


List apps to be installed using their WinGet ID, comma-separated.
If run with no arguments script will attempt to install/upgrade 7zip, Firefox, Chrome, Notepad++, and Putty

Commonly used WingGet package IDs:
'7zip.7zip'
'Adobe.Acrobat.Reader.64-bit'
'Cisco.CiscoWebexMeetings'
'Foxit.FoxitReader'
'Google.Chrome'
'IDRIX.VeraCrypt'
'Insecure.Nmap'
'JanDeDobbeleer.OhMyPosh'
'Microsoft.PowerShell'
'Microsoft.PowerToys'
'Mozilla.Firefox'
'Mozilla.Thunderbird'
'Notepad++.Notepad++'
'OBSProject.OBSStudio'
'PortSwigger.BurpSuite.Community'
'PuTTY.PuTTY'
'Python.Python.3.11'
'Sandboxie.Plus'
'SumatraPDF.SumatraPDF'
'VideoLAN.VLC'
'voidtools.Everything'
'WinMerge.WinMerge'
'WiresharkFoundation.Wireshark'

Run with admin privileges


email log to yourself by including the emailServer, emailFrom, emailTo
emailUsername, and emailPassword parameters.

when creating a scheduled task to run such scripts, use the following structure example:
powershell.exe -NoProfile -ExecutionPolicy Bypass -Scope Process -File "C:\Utility\WinGet-Apps.ps1"

To run as a scheduled task start PowerShell:
C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe
With arguments something like this:
-Command "& 'C:\Utility\WinGet-Apps.ps1' -Param1 XXX1,XXX2,XXX3 -Param2 15"

To run remotely on a list of endpoints with PS remoting already enabled (Enable-PSRemoting):
Invoke-Command -FilePath "C:\Utility\WinGet-Apps.ps1" -ComputerName endpoint1,endpoint2,endpoint3
or
Invoke-command -ComputerName (get-content c:\Utility\EndpointList.txt) -filepath c:\Utility\WinGet-Apps.ps1
or using PsExec:
psexec -s \\endpoint1 Powershell -ExecutionPolicy Bypass -File \\dc\netlogon\scripts\WinGet-Apps.ps1
