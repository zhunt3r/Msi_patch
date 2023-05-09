:: https://winget.run/
:: https://winstall.app/

:: Know that :: are considered a comment, so the command wont run with it, unless you get the command by itself and run, or remove it from before the command, then you can run the file, for whatever line you might want to be used. But only do so for commands, and not explaining text, otherwise that will break the script.

:: Install Winget through this or use https://github.com/microsoft/winget-cli/releases with .msixbundle file
powershell "Install-Module WingetTools"

:: You can update them all by running
:: winget upgrade --all

:: You can find apps options by using
:: winget search whatyouwant

:: You can make it run automatically in every windows startup by running this command once
:: powershell -c "$action = New-ScheduledTaskAction -Execute \"powershell\" -Argument \"-WindowStyle hidden -Command winget upgrade --all\"; $trigger = New-ScheduledTaskTrigger -AtLogOn; $principal = New-ScheduledTaskPrincipal -UserID $env:USERNAME -RunLevel Highest; Register-ScheduledTask -TaskName \"AutoUpdateWingetApps\" -Action $action -Trigger $trigger -Principal $principal;"

:: You can install Windows Store apps by using their id
:: https://apps.microsoft.com/store/detail/netflix/9WZDNCRFJ3TJ
:: winget install -e --id 9WZDNCRFJ3TJ

winget install -e --id Microsoft.DirectX

:: Replace native Windows Menu
:: winget install -e --id Open-Shell.Open-Shell-Menu

:: Replace every other browser
winget install -e --id Brave.Brave --accept-package-agreements

:: Replace 7Zip
winget install -e --id M2Team.NanaZip

:: Replace Notepad
winget install -e --id Notepad++.Notepad++
:: winget install -e --id VSCodium.VSCodium
:: winget install -e --id Microsoft.VisualStudioCode

:: Replace Paint
winget install -e --id dotPDNLLC.paintdotnet

:: Replace Calculator, or if you want it back.
:: winget install -e --id Qalculate.Qalculate
:: winget install Calculator --accept-package-agreements

:: Screenshot and more
:: winget install -e --id ShareX.ShareX

:: GPU OC + OSD
:: winget install -e --id Guru3D.Afterburner

:: Voice + Chat
:: winget install -e --id Discord.Discord

:: Replace any other Media Player
:: winget install -e --id clsid2.mpc-hc
:: winget install -e --id Nevcairiel.LAVFilters
:: winget install -e --id VideoLAN.VLC

:: Torrent
:: winget install -e --id qBittorrent.qBittorrent

:: Gaming
:: winget install -e --id Valve.Steam
:: winget install -e --id EpicGames.EpicGamesLauncher
:: winget install -e --id OBSProject.OBSStudio

:: Check drivers latency
:: winget install -e --id Resplendence.LatencyMon

:: Make the system more responsive
:: winget install -e --id BitSum.ProcessLasso

:: New Powershell
:: winget install -e --id Microsoft.PowerShell

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Security :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: DO NOT download executables you dont know to be safe or decently safe. Check them before. You can use https://www.virustotal.com/ if online. Or scan with an good antimalware. You can also isolate it from your enviromnent by using a Sandbox environment like Sandboxie.

:: https://www.privacytools.io/
:: https://www.kaspersky.com.br/downloads/free-virus-removal-tool

:: Replace Windows Firewall - I recommend at least simplewall as alternative, you have much more control and better visibility than Windows option, and more security.
:: winget install -e --id Henry++.simplewall
:: winget install -e --id Safing.Portmaster
:: winget install -e --id BiniSoft.WindowsFirewallControl

:: Protection against many types of malware and more
:: winget install -e --id Bitdefender.Bitdefender
:: winget install -e --id Malwarebytes.Malwarebytes

:: Sandbox environment
:: winget install -e --id Sandboxie.Plus

:: Browser Extensions
:: https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm
:: https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp
:: https://chrome.google.com/webstore/detail/decentraleyes/ldpochfccmkkmhdbclfhpagapcfdljkj

:: ----------------------------------------------------------------------------------------------------------------
:: ----------------------------------------------------------------------------------------------------------------

:: Alternatively you can use the most popular one. Chocolatey. Install with the following command, using powershell.

:: Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

:: https://community.chocolatey.org/packages

:: Replace File Explorer
:: choco install files -y
