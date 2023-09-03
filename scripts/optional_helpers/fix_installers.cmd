:: Run this script, in case some installers are not working through click or winget, e.g., .msixbundle, .appinstaller, .appx, .appxbundle, some packages from winget.

:: WIP - Remove this line and everything below the divider, once a solution is found and built.

:: ------------------------------------------------------------------------

:: WIP Notes

:: I could use the VM to test what script exactly has what is causing it to stop working.
:: From what make sense, it could be tweaks/usability, debloat/packages, debloat/services. But could be also something else, still those are the main possible reasons.

:: I dont know all the things in all the tweaks+debloat that would cause this to break, If someone wants to find out, in the simplest and cleanest way and make a PR. Try to get it working with the minimum needed.

:: Try to build a sort of toggle in this, so each time you run the script, it will enable or disable everything that it end up going through here.

:: sc config wuauserv start= demand
:: sc config BITS start= auto
:: sc config DoSvc start= delayed-auto
:: sc config uhssvc start= delayed-auto
:: sc config UsoSvc start= auto
:: sc config WaaSMedicSVC start= demand

:: net start wuauserv :: Default Manual
:: net start BITS :: Default Auto
:: net start DoSvc :: Default Delayed Auto
:: net start uhssvc :: Default Disabled or Delayed Auto
:: net start UsoSvc :: Default Auto
:: net start msiserver :: Default Auto
:: net start WaaSMedicSVC :: Didnt want to initialize - Default Manual
:: net start AppXSvc
:: net start wlidsvc
:: net start WSService :: Maybe it was removed too, it was invalid when I tried

:: wcifs, FileInfo, FileCrypt

:: net start InstallService :: Was kept default manual - needs to be running to install msixbundle
:: net start PushToInstall :: Was kept default manual 
:: net start DcomLaunch :: Was kept default auto, to not break other dependent parts.
:: net start TrustedInstaller :: Was kept default manual.

:: Get-Service wuauserv, BITS, DoSvc, uhssvc, UsoSvc, WaaSMedicSVC, msiserver, AppXSvc, wlidsvc, WSService, InstallService, PushToInstall, DcomLaunch, TrustedInstaller, cryptsvc, appidsvc, LicenseManager, mpssvc, RpcLocator, BFE | Select -Property Name, Status, StartType, DisplayName

:: Automatic, AutomaticDelayedStart, Disabled, Manual
:: Set-Service BITS -StartupType Manual 

:: Start-Service -Name "eventlog"

:: Startup Types: 0 = Boot, 1 = System, 2 = Automatic, 3 = Manual, 4 = Disabled
:: DelayedAutoStart 0 or 1, same level as Start key
:: REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 4 /f

:: REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 0 /f
:: REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 0 /f
:: REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 0 /f
:: REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 1 /f

:: ---------------------------------------------------------------------------

:: Packages to test and make work
:: winget install Calculator --accept-package-agreements
:: winget install -e --id 9MSMLRH6LZF3 --accept-package-agreements

:: VP9
:: winget install -e --id 9N4D0MSMP0PT --accept-package-agreements

:: MSStore
:: https://apps.microsoft.com/store/detail/microsoft-store/9WZDNCRFJBMP

:: It could be that Nvidia Control Panel are not longer being installed with the driver is that, when finishing up the installation, it requires connection with the internet, maybe what it does is, download the panel from the MS Store, but since the services are disabled, is not working. So, no nvidia control panel. Or it already includes the installation but since some of the above is not working, same issue.
:: Through ms store, it would be installable by using
:: winget install -e --id 9NF8H0H7WMLT --accept-package-agreements
:: Clearly it's another reason to fix this.

:: Commands like these do not work to restore what is already removed, because it seems to use windows update to restore, if it's already disabled/removed, then is why does not work.
:: sfc/scannow
:: DISM /Online /Cleanup-Image /RestoreHealth
:: If you have Windows in a disk/usb, you can point to it instead. Change G: to where windows installation is in.
:: DISM /Online /Cleanup-Image /RestoreHealth /Source:G:\Sources\install.wim /LimitAccess
:: I have tried both of these options, it did not work.

:: App installation failed with error message: error 0x800706D9: While processing the request, the syste, failed to register the windows.firewall extension due to the following error: There are no more endpoints available from the endpoint mapper.