<#
	WIP (not done)

	Currently, it's fully working on Win10 22H2 to disable and enable.

	But not on Win11, there is no taskbar, right click does not work anywhere, but openshell does work if you use windows key. An sort of small window glitch also appear and stay in the screen and if you open a folder with shortcut, the top part of it stays entirely black. Folders you can open, some apps you can open, not others, but it will be still broken.

	Anyone that want to try find the Win11 solution can do with this script, all you would have to do is add / remove rules and/or items. Everything else should be automated.

	I add a new way to support different OS and builds, a Rule variable, pattern is below in how it works. Anyone are able to test and contribute in different builds. Beware, if DWM are not disabled in any of the builds, it might need additional checks at Is-DWM-Enabled

	-------------------------

	Automated script to disable or enable DWM, a toggle.

	Script goal is to keep the disabling persisted through a restart while everything still being functional.
	Why? Because some dwm scripts are built to be disabled, and enabled before you restart/shutdown your computer, otherwise it breaks your system.

	This script is made to be working within the whole gaming_os_tweaker folder, as it depends on one of it's tools. You can still run this script through cmd, powershell or UI if you prefer, as long as it is in the folder that it belongs.

	-------------------------

	It will only be supported in the versions that were tested. All checks will be based on the Rules, to prevent incompatibility with untested builds/versions.

	You are responsible for any damage it may cause, there will be checks and testing, but we never know if there is an unknown variable in your system could cause other problems. I wont be providing any support other than possibly fixing general confirmed bugs.

	-------------------------

	In case you get problems running the script in Win11, you can run the command to allow, and after, another to set back to a safer or undefined policy. But if you have set to be run at every startup, you might want to keep the bypass without changing it back.

	You can check the current policy settings
	Get-ExecutionPolicy -List

	Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Confirm:$false -Force
	Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser -Confirm:$false -Force
#>

# Start as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

# -----------------------------------------------------------------------------------------------------------------

$OpenShellFilePath = "$PSScriptRoot\OpenShell-Latest.exe"
$DLLPath = "$env:SystemRoot\System32"

# Follow this pattern to add rules (OSs-:Edition-FromBuild.FromPatch-ToBuild.ToPatch) e.g., "Win7-Win10:20H1-Build.Patch-Build.Patch;Win7:19H1-Build.Patch-Build.Patch;Win10:21H2-Build.Patch-Build.Patch", alternatively you can add -All if that windows edition (e.g., 22H2) are supported from the first to the last build and patch. Beware, there are 4 different possible separators (- : ; .)

$DLLs = @(
	[PsObject]@{Name = 'UIRibbon'; Rules = 'Win10:22H2-All'},
	[PsObject]@{Name = 'UIRibbonRes'; Rules = 'Win10:22H2-All'},
	[PsObject]@{Name = 'Windows.UI.Logon'; Rules = 'Win10:22H2-All'},
	[PsObject]@{Name = 'DWMInit'; Rules = 'Win10:22H2-All'},
	[PsObject]@{Name = 'WSClient'; Rules = 'Win10:22H2-All'},
	[PsObject]@{Name = 'Windows.immersiveshell.serviceprovider'; Rules = 'Win10:22H2-All'}
)

$Executables = @(
	[PsObject]@{Path = "$env:SystemRoot\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\System32\RuntimeBroker.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\System32\dwm.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\MiniSearchHost.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\System32\ApplicationFrameHost.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\System32\taskhostw.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe"; Rules = 'Win10:22H2-All'},
	[PsObject]@{Path = "$env:SystemRoot\System32\sihost.exe"; Rules = ''},
	[PsObject]@{Path = "$env:SystemRoot\Resources\Themes\aero\aero.msstyles"; Rules = ''}
)

$Services = @(
	[PsObject]@{Name = 'UxSms'; DefaultValue = 2; Rules = ''},
	[PsObject]@{Name = 'Themes'; DefaultValue = 2; Rules = ''}
)

# -----------------------------------------------------------------------------------------------------------------

function Get-OS-Build-Version {
	$Versions = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	$BuildNumber = [int]$Versions.CurrentBuildNumber
	$PatchNumber = [int]$Versions.UBR
	$DisplayVersion = [string]$Versions.DisplayVersion
	$ProductName = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption
	return @{ PatchNumber = $PatchNumber; BuildNumber = $BuildNumber; DisplayVersion = $DisplayVersion; ProductName = $ProductName }
}

function Get-Filename-From-Path {
	param ([string] $value)
	$valueSplit = $value.Split('\')
	return $valueSplit[$valueSplit.Length - 1]
}

function Is-OS-Version-Supported {
	$Versions = Get-OS-Build-Version
	$CombinedData = $DLLs + $Executables + $Services
	$ItemsSupportedCount = 0
	foreach ($item in $CombinedData) {
		$IsValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if ($IsValueUsed) {
			$ItemsSupportedCount++
		}
	}
	return $ItemsSupportedCount -gt 0
}

function Get-OS-Number {
	param ([string] $value)
	$ValueSplit = $value.Split(' ')
	$OSNumber = 0
	foreach ($item in $ValueSplit) {
		$itemAsInt = $item -as [int]
		if (![string]::IsNullOrWhiteSpace($itemAsInt) -and $itemAsInt.GetType().Name -eq 'Int32') {
			$OSNumber = $itemAsInt
			break
		}
	}
	return $OSNumber
}

function Get-Rules-Data {
	param ([string] $value)
	$RulesData = @()
	if (!$value) {
		return $RulesData
	}
	if ($value.Trim().Length -eq 0) {
		return $RulesData
	}
	$Rules = $value.Split(';')
	foreach ($rule in $Rules) {
		$OSs = $rule.Split(':')[0]
		$OSsSplit = $OSs.Split('-')
		$OSsBuild = $rule.Split(':')[1]
		$BuildVersions = $OSsBuild.Split('-')
		$DisplayVersion = $BuildVersions[0]
		$FromBuild = 0
		$FromPatch = 0
		$ToBuild = 0
		$ToPatch = 0
		if ($BuildVersions.Length -gt 2 -and $BuildVersions[1] -ne 'All') {
			$FromVer = $BuildVersions[1].Split('.')
			$FromBuild = $FromVer[0]
			$FromPatch = $FromVer[1]
			$ToVer = $BuildVersions[2].Split('.')
			$ToBuild = $ToVer[0]
			$ToPatch = $ToVer[1]
		}
		foreach ($OS in $OSsSplit) {
			$OSNumber = [int]$OS.replace('Win', '')
			$RulesData += [PsObject]@{OS = $OSNumber; DisplayVersion = $DisplayVersion; FromBuild = $FromBuild; FromPatch = $FromPatch; ToBuild = $ToBuild; ToPatch = $ToPatch}
		}
	}
	return $RulesData
}

function Is-Value-Used-In-OS {
	param ([string] $value)
	$SupportCount = 0
	$Rules = Get-Rules-Data -value $value
	$CurrentVersions = Get-OS-Build-Version
	$CurrentOSNumber = Get-OS-Number -value $CurrentVersions.ProductName
	foreach ($rule in $Rules) {
		if (
			$rule.OS -eq $CurrentOSNumber -and
			$rule.DisplayVersion -eq $CurrentVersions.DisplayVersion -and
			$CurrentVersions.BuildNumber -ge $rule.FromBuild -and
			$CurrentVersions.BuildNumber -le $rule.ToBuild -and
			$CurrentVersions.PatchNumber -ge $rule.FromPatch -and
			$CurrentVersions.PatchNumber -le $rule.ToPatch
		) {
			$SupportCount++
		}
	}
	return $SupportCount -gt 0
}

function Show-Message {
	param ([string] $value)
	Write-Host "$value"
	[Environment]::NewLine
}

function Download-And-Install-Latest-OpenShell {
	if (Is-OpenShell-Installed) {
		Show-Message -value "OpenShell is already installed, ignore and continue."
		return
	}
	$releasesJson = "https://api.github.com/repos/Open-Shell/Open-Shell-Menu/releases"
	$assets = (Invoke-WebRequest $releasesJson -UseBasicParsing | ConvertFrom-Json)[0].assets
	$downloadUrl = ""
	foreach ($item in $assets) {
		if ($item.browser_download_url.Contains('.exe')) {
			$downloadUrl = $item.browser_download_url
		}
	}
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Show-Message -value "No download url found"
		return
	}
	Show-Message -value "Downloading OpenShell - $downloadUrl"
	Invoke-WebRequest -URI $downloadUrl -OutFile $OpenShellFilePath -UseBasicParsing
	Show-Message -value "Installing OpenShell"
	& "$OpenShellFilePath" /qn ADDLOCAL=StartMenu
}

function Get-OpenShell-Install-Id {
	return Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Open*" -and $_.Name -like "*Shell*" } | Select-Object -ExpandProperty IdentifyingNumber
}

function Is-OpenShell-Installed {
	$OpenShellId = Get-OpenShell-Install-Id
	if ([string]::IsNullOrWhiteSpace($OpenShellId)) { return $false } else { return $true }
}

function Uninstall-OpenShell {
	Show-Message -value "Uninstalling OpenShell"
	$OpenShellId = Get-OpenShell-Install-Id
	MsiExec.exe /x $OpenShellId /qn
	Run-Command-With-Elevated-Permission -value "Remove-Item -Path $OpenShellFilePath -Force"
}

function Run-Command-With-Elevated-Permission {
	param ([string] $value)
	& "$PSScriptRoot\run_minsudo" "powershell -ExecutionPolicy Bypass -Command $value" | Out-Null
}

function Alter-REGs {
	Show-Message -value "Altering REGs"
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name ConsoleMode -Value 1 -Force -Type Dword -ErrorAction Ignore
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name XamlCredUIAvailable -Value 0 -Force -Type Dword -ErrorAction Ignore
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\DWM" -Name CompositionPolicy -Value 0 -Force -Type Dword -ErrorAction Ignore
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" -Name Debugger -Value "$env:SystemRoot\System32\rundll32.exe" -Force -Type String -ErrorAction Ignore
}

function Undo-REG-Changes {
	Show-Message -value "Undoing REG Changes"
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name XamlCredUIAvailable -Value 1 -Force -Type Dword -ErrorAction Ignore
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name ConsoleMode -Force -ErrorAction Ignore
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" -Name Debugger -Force -ErrorAction Ignore
}

function Disable-Executables {
	Show-Message -value "Disabling Executables"
	foreach ($item in $Executables) {
		$isValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if (!$isValueUsed) {
			continue
		}
		$Path = $item.Path
		$Filename = Get-Filename-From-Path -value $Path
		Stop-Process -Name $Filename -Force -ErrorAction Ignore
		if (Test-Path -Path $Path) {
			Run-Command-With-Elevated-Permission -value "Move-Item -Path $Path -Destination $Path.backup -Force -ErrorAction Ignore"
		}
		if ($Filename -eq 'dwm.exe') {
			$FromFile = "$env:SystemRoot\System32\rundll32.exe"
			$ToFile = "$env:SystemRoot\System32\dwm.exe"
			Run-Command-With-Elevated-Permission -value "Copy-Item -Path $FromFile -Destination $ToFile -Force -ErrorAction Ignore"
		}
	}
}

function Enable-Executables {
	Show-Message -value "Enabling Executables"
	foreach ($item in $Executables) {
		$isValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if (!$isValueUsed) {
			continue
		}
		$Path = $item.Path
		$Filename = Get-Filename-From-Path -value $Path
		$FilePathBackup = "$Path.backup"
		if (Test-Path -Path $FilePathBackup) {
			if ($Filename -eq 'dwm.exe') {
				Stop-Process -Name 'winlogon.exe' -Force -ErrorAction Ignore
				Stop-Process -Name $Filename -Force -ErrorAction Ignore
				$RemoveTempFile = "$env:SystemRoot\System32\$Filename"
				Run-Command-With-Elevated-Permission -value "Remove-Item -Path $RemoveTempFile -Force"
			}
			Run-Command-With-Elevated-Permission -value "Move-Item -Path $FilePathBackup -Destination $item -Force -ErrorAction Ignore"
		}
	}
}

function Disable-DLLs {
	Show-Message -value "Disabling DLLs"
	foreach ($item in $DLLs) {
		$isValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if (!$isValueUsed) {
			continue
		}
		$DLL = $item.Name
		$FilePath = "$DLLPath\$DLL.dll"
		if (Test-Path -Path $FilePath) {
			Run-Command-With-Elevated-Permission -value "Move-Item -Path $FilePath -Destination $FilePath.backup -Force -ErrorAction Ignore"
		}
	}
}

function Enable-DLLs {
	Show-Message -value "Enabling DLLs"
	foreach ($item in $DLLs) {
		$isValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if (!$isValueUsed) {
			continue
		}
		$DLL = $item.Name
		$FilePath = "$DLLPath\$DLL.dll"
		$FilePathBackup = "$FilePath.backup"
		if (Test-Path -Path $FilePathBackup) {
			Run-Command-With-Elevated-Permission -value "Move-Item -Path $FilePathBackup -Destination $FilePath -Force -ErrorAction Ignore"
		}
	}
}

function Disable-Services {
	Show-Message -value "Disabling Services"
	foreach ($item in $Services) {
		$isValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if (!$isValueUsed) {
			continue
		}
		$Service = $item.Name
		Run-Command-With-Elevated-Permission -value "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\$Service' -Name Start -Value 4 -Force -Type Dword -ErrorAction Ignore"
	}
}

function Enable-Services {
	Show-Message -value "Enabling Services"
	foreach ($item in $Services) {
		$isValueUsed = Is-Value-Used-In-OS -value $item.Rules
		if (!$isValueUsed) {
			continue
		}
		$Service = $item.Name
		Run-Command-With-Elevated-Permission -value "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\services\$Service' -Name Start -Value $($item.DefaultValue) -Force -Type Dword -ErrorAction Ignore"
	}
}

function Show-OS-Info {
	$Versions = Get-OS-Build-Version
	Show-Message -value "You are on $($Versions.ProductName) $($Versions.DisplayVersion) - Build $($Versions.BuildNumber) - Patch $($Versions.PatchNumber)"
}

function Restart-Machine {
	Show-Message -value "Process finished, this script will restart your PC in 15 seconds from now..."
	Start-Sleep -Seconds 15
	Restart-Computer
}

function Is-DWM-Enabled {
	$DWMProcess = Get-Process -Name dwm -ErrorAction SilentlyContinue
	if ([string]::IsNullOrWhiteSpace($DWMProcess)) { return $false } else { return $true }
}

# -----------------------------------------------------------------------------------------------------------------

Show-OS-Info

if (!(Is-OS-Version-Supported)) {
	Show-Message -value "Your OS version are not currently supported by this script!"
	exit
}

if (Is-DWM-Enabled) {
	Show-Message -value "Starting process to disable DWM!"
	Download-And-Install-Latest-OpenShell
	Alter-REGs
	Disable-Executables
	Disable-DLLs
	Disable-Services
} else {
	Show-Message -value "Starting process to enable DWM!"
	Uninstall-OpenShell
	Undo-REG-Changes
	Enable-Executables
	Enable-DLLs
	Enable-Services
}

Restart-Machine
