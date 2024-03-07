#           Bitpusher
#            \`._,'/
#            (_- -_)
#              \o/
#          The Digital
#              Fox
#          @VinceVulpes
#    https://theTechRelay.com
# https://github.com/bitpusher2k
#
# WinGet-Apps.ps1 - By Bitpusher/The Digital Fox
# v2.4 last updated 2024-03-07
# Script to to use WinGet to check if specified apps are installed and optionally install if not/upgrade if they are.
# Capable of being run remotely in the background on an endpoint from system context (PS Remoting/RMM use).
# Will attempt to install WinGet and its dependencies if it is not found. Will attempt to also run updates in
# user space if a user is logged in when run.
#
# Caution: WinGet will terminate programs it is attempting to update. Beware of updating apps on systems while they are in use.
#
# Usage:
# powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -AppIdList "7zip.7zip","Mozilla.Thunderbird","Google.Chrome","Mozilla.Firefox" -Install 1 -Upgrade 1
#
# Using email reporting:
# powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -AppIdList "7zip.7zip","Mozilla.Thunderbird","Google.Chrome","Mozilla.Firefox" -Install 1 -Upgrade 1 -RandMax 100  -emailServer "smtpo.yourmailserver.com" -emailUsername "username@yourmailserver.com" -emailPassword "XXXXXXXX" -emailFrom "username@yourmailserver.com" -emailTo "reports+winget@yourmailserver.com"
#
# Test what installs/updates are possible:
# powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -AppIdList "7zip.7zip","Mozilla.Thunderbird","Google.Chrome","Mozilla.Firefox" -Install 0 -Upgrade 0
#
# Upgrade all apps possible for WinGet to manage:
# powershell -executionpolicy bypass -f .\WinGet-Apps.ps1 -UpgradeAll 1
#
#
# List apps to be installed using their WinGet ID, comma-separated.
# If run with no arguments script will attempt to install/upgrade 7zip, Firefox, Chrome, Notepad++, and Putty
#
# Commonly used WingGet package IDs:
# '7zip.7zip'
# 'Adobe.Acrobat.Reader.64-bit'
# 'Cisco.CiscoWebexMeetings'
# 'Foxit.FoxitReader'
# 'Google.Chrome'
# 'IDRIX.VeraCrypt'
# 'Insecure.Nmap'
# 'JanDeDobbeleer.OhMyPosh'
# 'Microsoft.PowerShell'
# 'Microsoft.PowerToys'
# 'Mozilla.Firefox'
# 'Mozilla.Thunderbird'
# 'Notepad++.Notepad++'
# 'OBSProject.OBSStudio'
# 'PortSwigger.BurpSuite.Community'
# 'PuTTY.PuTTY'
# 'Python.Python.3.11'
# 'Sandboxie.Plus'
# 'SumatraPDF.SumatraPDF'
# 'VideoLAN.VLC'
# 'voidtools.Everything'
# 'WinMerge.WinMerge'
# 'WiresharkFoundation.Wireshark'
#
# Run with admin privileges
#
#
# email log to yourself by including the emailServer, emailFrom, emailTo
# emailUsername, and emailPassword parameters.
#
# when creating a scheduled task to run such scripts, use the following structure example:
# powershell.exe -NoProfile -ExecutionPolicy Bypass -Scope Process -File "C:\Utility\WinGet-Apps.ps1"
#
# To run as a scheduled task start PowerShell:
# C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe
# With arguments something like this:
# -Command "& 'C:\Utility\WinGet-Apps.ps1' -Param1 XXX1,XXX2,XXX3 -Param2 15"
#
# To run remotely on a list of endpoints with PS remoting already enabled (Enable-PSRemoting):
# Invoke-Command -FilePath "C:\Utility\WinGet-Apps.ps1" -ComputerName endpoint1,endpoint2,endpoint3
# or
# Invoke-command -ComputerName (get-content c:\Utility\EndpointList.txt) -filepath c:\Utility\WinGet-Apps.ps1
# or using PsExec:
# psexec -s \\endpoint1 Powershell -ExecutionPolicy Bypass -File \\dc\netlogon\scripts\WinGet-Apps.ps1
#
#comp #powershell #script #winget #install #update #upgrade

#Requires -Version 5.1

param(
    [array]$AppIdList = @('7zip.7zip','Notepad++.Notepad++','Google.Chrome','PuTTY.PuTTY','Mozilla.Firefox'),
    [string]$Install = '1',
    [string]$Upgrade = '1',
    [string]$UpgradeAll = '0',
    [string]$InstallWinget = '1',
    [string]$TempFolder = 'C:\temp',
    [string]$scriptName = "WinGet-Apps",
    [string]$Priority = "Normal",
    [int]$RandMax = "500",
    [string]$DebugPreference = "SilentlyContinue",
    [string]$VerbosePreference = "SilentlyContinue",
    [string]$InformationPreference = "Continue",
    [string]$logFileFolderPath = "C:\temp\log",
    [string]$ComputerName = $env:computername,
    [string]$ScriptUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
    [string]$emailServer = "",
    [string]$emailFrom = "",
    [string]$emailTo = "",
    [string]$emailUsername = "",
    [string]$emailPassword = "",
    [string]$shareLocation = "",
    [string]$shareUsername = "",
    [string]$sharePassword = "",
    [string]$logFilePrefix = "$scriptName" + "_" + "$ComputerName" + "_",
    [string]$logFileDateFormat = "yyyyMMdd_HHmmss",
    [int]$logFileRetentionDays = 30,
    [string]$Encoding = "utf8bom" # "ascii","ansi","bigendianunicode","unicode","utf8","utf8","utf8NoBOM","utf32"
)
#@('Adobe.Acrobat.Reader.64-bit','7zip.7zip','voidtools.Everything','Foxit.FoxitReader','Mozilla.Thunderbird','Notepad++.Notepad++','OBSProject.OBSStudio','JanDeDobbeleer.OhMyPosh','Sandboxie.Plus','SumatraPDF.SumatraPDF','IDRIX.VeraCrypt','Python.Python.3.11','Google.Chrome','PuTTY.PuTTY','Microsoft.PowerShell','Cisco.CiscoWebexMeetings','VideoLAN.VLC','WiresharkFoundation.Wireshark','Insecure.Nmap','PortSwigger.BurpSuite.Community','Mozilla.Firefox')


process {
    #region initialization
    if ($PSVersionTable.PSVersion.Major -eq 5 -and ($Encoding -eq "utf8bom" -or $Encoding -eq "utf8nobom")) { $Encoding = "utf8" }

    function Get-TimeStamp {
        param(
            [switch]$NoWrap,
            [switch]$Utc
        )
        $dt = Get-Date
        if ($Utc -eq $true) {
            $dt = $dt.ToUniversalTime()
        }
        $str = "{0:MM/dd/yy} {0:HH:mm:ss}" -f $dt

        if ($NoWrap -ne $true) {
            $str = "[$str]"
        }
        return $str
    }

    function Test-FileLock {
        param(
            [Parameter(Mandatory = $true)] [string]$Path
        )

        $oFile = New-Object System.IO.FileInfo $Path

        if ((Test-Path -Path $Path) -eq $false) {
            return $false
        }

        try {
            $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

            if ($oStream) {
                $oStream.Close()
            }
            return $false
        } catch {
            # file is locked by a process.
            return $true
        }
    }

    if ($logFileFolderPath -ne "") {
        if (!(Test-Path -PathType Container -Path $logFileFolderPath)) {
            Write-Output "$(Get-TimeStamp) Creating directory $logFileFolderPath" | Out-Null
            New-Item -ItemType Directory -Force -Path $logFileFolderPath | Out-Null
        } else {
            $DatetoDelete = $(Get-Date).AddDays(- $logFileRetentionDays)
            Get-ChildItem $logFileFolderPath | Where-Object { $_.Name -like "*$logFilePrefix*" -and $_.LastWriteTime -lt $DatetoDelete } | Remove-Item | Out-Null
        }
        $logFilePath = $logFileFolderPath + "\$logFilePrefix" + (Get-Date -Format $logFileDateFormat) + ".LOG"
        #OR: $logFilePath = $logFileFolderPath + "\$logFilePrefix" + (Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z') + ".LOG"
        # attempt to start the transcript log, but don't fail the script if unsuccessful:
        try {
            Start-Transcript -Path $logFilePath -Append
        } catch [Exception] {
            Write-Warning "$(Get-TimeStamp) Unable to start Transcript: $($_.Exception.Message)"
            $logFileFolderPath = ""
        }
    }

    # Set script priority
    # Possible values: Idle, BelowNormal, Normal, AboveNormal, High, RealTime
    $process = Get-Process -Id $pid
    Write-Output "Setting process priority to `"$Priority`""
    #Write-Output "Script priority before:"
    #Write-Output $process.PriorityClass
    $process.PriorityClass = $Priority
    #Write-Output "Script priority After:"
    #Write-Output $process.PriorityClass
    #endregion initialization

    #region main
    # debug tracing - set to "2" for testing, set to "0" for production use
    Set-PSDebug -Trace 0
    [int]$MyExitStatus = 1
    $StartTime = $(Get-Date)
    Write-Output "Script $scriptName started at $(Get-TimeStamp)"
    Write-Output "ISO8601:$(Get-Date (Get-Date).ToUniversalTime() -UFormat '+%Y%m%dT%H%M%S.000Z')`n"
    $RandSeconds = Get-Random -Minimum 1 -Maximum $RandMax
    Write-Output "Waiting $RandSeconds seconds (between 1 and $RandMax) to stagger execution across devices`n"
    Start-Sleep -Seconds $RandSeconds


    if (!(Test-Path $TempFolder)) {
        New-Item -Path $TempFolder -ItemType Directory -Force -Confirm:$false
    }

    Write-Output "Locating WinGet..."
    $WingetPath = ""
    $TestWinget = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "Microsoft.DesktopAppInstaller" }
    $TestWinget

    if ([Version]$TestWinGet.Version -gt "2022.506.16.0") {
        Write-Output "WinGet already installed. Finding executable path..."
        $ResolveWingetPath = (Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Sort-Object -Property Path | Select-Object -Last 1)
        if ($null -eq $ResolveWingetPath) {
            Write-Output "ERROR: WinGet path was not found."
            $MyExitStatus = 20
        }
        $WingetPath = $ResolveWingetPath[-1].Path
    } elseif ($InstallWinget -eq '1') {
        Write-Output "WinGet not found. Attempting to install..."
        # If Visual C++ Redistributable 2022 not present, download and install. (WinGet Dependency)
        if (Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Visual C++ 2022%'") {
            Write-Output "Dependency VC++ Redistributable 2022 already installed"
        } else {
            Write-Output "Dependency Visual C++ Redistributable not found - Installing..."
            #Permalink for latest supported x64 version
            Invoke-Webrequest -uri https://aka.ms/vs/17/release/vc_redist.x64.exe -Outfile $TempFolder\vc_redist.x64.exe
            Start-Process "$TempFolder\vc_redist.x64.exe" -Wait -ArgumentList "/q /norestart"
        }
        # Download WinGet MSIXBundle
        Write-Output "Downloading WinGet..." 
        Invoke-Webrequest -uri https://aka.ms/getwinget -Outfile $TempFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
        
        # Install WinGet MSIXBundle 
        Try {
            Write-Output "Installing MSIXBundle for App Installer..." 
            Add-AppxProvisionedPackage -Online -PackagePath "$TempFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -SkipLicense 
            Write-Output "Installed MSIXBundle for App Installer (WinGet)"
            Start-Sleep -Seconds 5
            $ResolveWingetPath = (Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" | Sort-Object -Property Path | Select-Object -Last 1)
            if ($null -eq $ResolveWingetPath) {
                Write-Output "ERROR: WinGet path was not found."
                $MyExitStatus = 20
            }
            $WingetPath = $ResolveWingetPath[-1].Path
        } Catch {
            Write-Output "Failed to install MSIXBundle for App Installer..."
        }
        # Cleanup
        if (Test-Path "$TempFolder\vc_redist.x64.exe") {
            Remove-Item -Path "$TempFolder\vc_redist.x64.exe" -Force -ErrorAction Continue
        }
        if (Test-Path "$TempFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle") {
            Remove-Item -Path "$TempFolder\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force -ErrorAction Continue
        }
    }

    if ($UpgradeAll -eq '1') {
        $Install = '0'
        $Upgrade = '0'
        $AppIdList = 'PlaceholderForUpgradAll'
    }

    if ($WingetPath) {
        Write-Output "WinGet directory found: $WingetPath"
        $MyExitStatus = 0

        foreach ($AppId in $AppIdList) {
            if ($AppId -eq 'PlaceholderForUpgradAll') {
                $AppSearch = 'N/A'
            } else {
                Write-Output "`n`nSearching WinGet for $AppId"
                $AppSearch = (& $WingetPath\winget.exe list --id "$AppId" --accept-source-agreements)
            }

            if ($AppSearch -like '*No installed package found*') {
                Write-Output ""
                Write-Output "$AppId not installed."
                if ($Install -eq '1') {
                    $Show = (& $WingetPath\winget.exe show --id "$AppId" --accept-source-agreements)
                    # $AppInfo = ($Show | Select-String -Pattern '(?m)^(\s*Installer|\s*Version).*$' -AllMatches).Matches.Value
                    $AppInfo = ($Show | Select-String -Pattern '(?m)^(Version).*$' -AllMatches).Matches.Value
                    $VersionAvailable = ($AppInfo -split " ")[-1]
                    Write-Output "Available: $VersionAvailable"
                    Write-Output "Installing application..."
                    Write-Output "& $WingetPath\winget.exe install --id `"$AppId`" --silent --accept-package-agreements --accept-source-agreements --log $TempFolder\winget.log"
                    $AppInstall = (& $WingetPath\winget.exe install --id "$AppId" --silent --accept-package-agreements --accept-source-agreements --log $TempFolder\winget.log)
                    if ($AppInstall -like '*Successfully installed*') {
                        Write-Output "$AppId installed."
                        Write-Output "Continuing..."
                    } else {
                        Write-Output "Error installing $AppId."
                        $MyExitStatus += 1
                        $AppInstall
                        Write-Output "Continuing..."
                    }
                } else {
                    Write-Output "Enable install flag to attempt app installation. Continuing..."
                }
            } elseif ($AppSearch -match '\bVersion\s+Available\b') {
                Write-Output ""
                Write-Output "$AppId already installed. Update available."
                $VersionInstalled, $VersionAvailable = (-split $AppSearch[-1])[-3,-2]
                Write-Output "Installed: $VersionInstalled"
                Write-Output "Available: $VersionAvailable"
                if ($Upgrade -eq '1') {
                    Write-Output "Installing updates..."
                    $Show = (& $WingetPath\winget.exe show --id "$AppId" --accept-source-agreements)
                    $AppInfo = ($Show | Select-String -Pattern '(?m)^(\s*Installer|\s*Version).*$' -AllMatches).Matches.Value
                    $AppInfo
                    Write-Output "& $WingetPath\winget.exe upgrade --id `"$AppId`" --silent --accept-package-agreements --accept-source-agreements --log $TempFolder\winget.log"
                    $AppUpgrade = (& $WingetPath\winget.exe upgrade --id "$AppId" --silent --accept-package-agreements --accept-source-agreements --log $TempFolder\winget.log)
                    if ($AppUpgrade -like '*Successfully installed*') {
                        Write-Output "$AppId updated."
                        Write-Output "Continuing..."
                    } else {
                        Write-Output "Error updating $AppId."
                        $MyExitStatus += 1
                        $AppUpgrade
                        Write-Output "Continuing..."
                    }
                } else {
                    Write-Output "Enable upgrade flag to attempt app updates. Continuing..."
                }
            } elseif ($AppSearch -match '\bVersion\s+Source\b') {
                Write-Output ""
                Write-Output "$AppId already installed, and no update is currently available."
                $VersionInstalled = (-split $AppSearch[-1])[-2]
                Write-Output "Installed: $VersionInstalled"
                Write-Output "Continuing..."
            }
            
            if ($UpgradeAll -eq '1') {
                Write-Output ""
                Write-Output "UpgradeAll flag set - Will now attempt to upgrade all apps that WinGet can manage..."
                Write-Output "& $WingetPath\winget.exe upgrade --all --silent --accept-source-agreements --accept-source-agreements --log $TempFolder\winget.log"
                $AppUpgradeAll = (& $WingetPath\winget.exe upgrade --all --silent --accept-source-agreements --accept-source-agreements --log $TempFolder\winget.log)
                $AppUpgradeAll
            }


            # Check if another user is logged in. If so, rerun upgrade commands within this user's session so apps in the user space are also updated.
            # Probably not all that useful in current context, but was a bit of a challenge to get working.
            $LoggedInUser = Get-Process -IncludeUserName -Name explorer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserName -Unique
            $CurrentUser = whoami
            if ($LoggedInUser -ne $CurrentUser) {
                "`n`n$LoggedInUser is logged in. Running WinGet update for $AppId under this user's session to be sure user space apps are updated."

                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $PackageProviderList = "NuGet"
                foreach ($PackageProvider in $PackageProviderList) {
                    if (Get-PackageProvider -ListAvailable -Name $PackageProvider -ErrorAction SilentlyContinue) {
                        Write-Output "$PackageProvider module already exists."
                    } else {
                        Write-Output "$PackageProvider does not exist. Installing..."
                        Install-PackageProvider -Name $PackageProvider -Force
                    }
                }
                # Check for dependent modules and install if not present (RunAsUser)
                $ModuleList = "RunAsUser"
                foreach ($Module in $ModuleList) {
                    if (Get-Module -ListAvailable -Name $Module) {
                        Write-Output "$Module module already exists."
                    } else {
                        Write-Output "$Module does not exist. Installing..."
                        Install-Module -Name $Module -Force -AllowClobber
                    }
                }

                if ($AppId -eq 'PlaceholderForUpgradAll') {
                    $AppSearchUserResult = 'N/A'
                } else {
                    # Write the command & output to a file so that we can pick it up as USER & SYSTEM respectively
                    "& `"$WinGetPath\winget.exe`" list --id `"$AppId`" --accept-source-agreements | Out-File `"$TempFolder\wingetAsUser.txt`"" | Out-File "$TempFolder\command.txt"
                    $AppSearchUser = ([scriptblock]::Create((Get-Content "$TempFolder\command.txt")))
                    Write-Output "$AppSearchUser"
                    invoke-ascurrentuser -scriptblock $AppSearchUser
                    $AppSearchUserResult = Get-Content "$TempFolder\wingetAsUser.txt"
                    remove-item "$TempFolder\command.txt" -Force
                    remove-item "$TempFolder\wingetAsUser.txt" -Force
                }

                if ($AppSearchUserResult -like '*No installed package found*') {
                    Write-Output ""
                    Write-Output "$AppId not installed in user space. Continuing..."
                } elseif ($AppSearchUserResult -match '\bVersion\s+Available\b') {
                    Write-Output ""
                    Write-Output "$AppId already installed in user space. Update available."
                    $VersionInstalled, $VersionAvailable = (-split $AppSearchUserResult[-1])[-3,-2]
                    Write-Output "Installed: $VersionInstalled"
                    Write-Output "Available: $VersionAvailable"
                    if ($Upgrade -eq '1') {
                        Write-Output "Installing updates in user space..."
                        $Show = (& $WingetPath\winget.exe show --id "$AppId" --accept-source-agreements)
                        $AppInfo = ($Show | Select-String -Pattern '(?m)^(\s*Installer|\s*Version).*$' -AllMatches).Matches.Value
                        $AppInfo

                        # Write the command & output to a file so that we can pick it up as USER & SYSTEM respectively
                        "& `"$WinGetPath\winget.exe`" upgrade --id `"$AppId`" --silent --accept-package-agreements --accept-source-agreements | Out-File `"$TempFolder\wingetAsUser.txt`"" | Out-File "$TempFolder\command.txt"
                        $AppUpdateUser = ([scriptblock]::Create((Get-Content "$TempFolder\command.txt")))
                        Write-Output "$AppUpdateUser"
                        invoke-ascurrentuser -scriptblock $AppUpdateUser
                        $AppUpdateUserResult = Get-Content "$TempFolder\wingetAsUser.txt"
                        remove-item "$TempFolder\command.txt" -Force
                        remove-item "$TempFolder\wingetAsUser.txt" -Force
                        if ($AppUpdateUserResult -like '*Successfully installed*') {
                            Write-Output "$AppId updated."
                            Write-Output "Continuing..."
                        } else {
                            Write-Output "Error updating $AppId."
                            $MyExitStatus += 1
                            $AppUpdateUserResult
                            Write-Output "Continuing..."
                        }
                    } else {
                        Write-Output "Enable upgrade flag to attempt app updates. Continuing..."
                    }
                } elseif ($AppSearchUserResult -match '\bVersion\s+Source\b') {
                    Write-Output ""
                    Write-Output "$AppId already installed, and no update is currently available."
                    $VersionInstalled = (-split $AppSearchUserResult[-1])[-2]
                    Write-Output "Installed: $VersionInstalled"
                    Write-Output "Continuing..."
                }

                if ($UpgradeAll -eq '1') {
                    Write-Output ""
                    Write-Output "UpgradeAll flag set - Will now attempt to upgrade all apps that WinGet can manage from user space as $LoggedInUser..."
                    # Write the command & output to a file so that we can pick it up as USER & SYSTEM respectively
                    "& `"$WinGetPath\winget.exe`" upgrade --all --silent --accept-source-agreements | Out-File `"$TempFolder\wingetAsUser.txt`"" | Out-File "$TempFolder\command.txt"
                    $UpdateAllApps = ([scriptblock]::Create((Get-Content "$TempFolder\command.txt")))
                    Write-Output "$UpdateAllApps"
                    invoke-ascurrentuser -scriptblock $UpdateAllApps
                    $AppUpdateUserResult = Get-Content "$TempFolder\wingetAsUser.txt"
                    $AppUpdateUserResult
                    remove-item "$TempFolder\command.txt" -Force
                    remove-item "$TempFolder\wingetAsUser.txt" -Force
                }
            } else {
                "No one is logged in. Additional upgrade attempt not needed. Continuing..."
            }
        }
    } else {
        Write-Output "Unable to locate WinGet on system. Ending."
        $MyExitStatus = 20
    }

    #endregion main

    #region finalization
    if ($logFileFolderPath -ne "") {
        Write-Output "`nScript $scriptName ended at $(Get-TimeStamp)"
        $elapsedTime = $(Get-Date) - $StartTime
        Write-Output "Elapsed time (seconds): $($elapsedTime.TotalSeconds)"
        Stop-Transcript
        if (($emailServer -ne "") -and ($emailUsername -ne "") -and ($emailPassword -ne "") -and ($emailFrom -ne "") -and ($emailTo -ne "")) {
            Send-MailMessage -SmtpServer "$emailServer" -Port 587 -From "$emailFrom" -To "$emailTo" -Subject "$scriptName - $ComputerName - $MyExitStatus - Log File" -Body "$logFilePath" -UseSsl -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$emailUsername", (ConvertTo-SecureString -String "$emailPassword" -AsPlainText -Force)) -Attachments $logFilePath
        }
        if (($shareLocation -ne "") -and ($shareUsername -ne "") -and ($sharePassword -ne "")) {
            [securestring]$secStringPassword = ConvertTo-SecureString $sharePassword -AsPlainText -Force
            [pscredential]$shareCred = New-Object System.Management.Automation.PSCredential ($shareUsername, $secStringPassword)
            New-PSDrive -Name LogStore -PSProvider FileSystem -Root "$shareLocation" -Description "Log Store" -Credential $shareCred
            $destFolder = "LogStore:\"
            Copy-Item -LiteralPath "$logFilePath" -Destination "$destFolder" -Force -ErrorAction Continue -ErrorVariable ErrorOutput
            Remove-PSDrive -Name LogStore
        }
    }
    Set-PSDebug -Trace 0
    #Get-Content $logFilePath
    exit $MyExitStatus
    #endregion finalization
}
