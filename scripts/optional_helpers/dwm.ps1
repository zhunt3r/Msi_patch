<#
	WIP (not done)

	Automated script to disable or enable DWM, a toggle.

	Script goal is to keep the disabling persisted through a restart while everything still being functional.
	Why? Because some dwm scripts are built to be disabled, and enabled before you restart/shutdown your computer, otherwise it breaks your system.

	This script is made to be working within the whole gaming_os_tweaker folder, as it depends on one of it's tools. You can still run this script through cmd, powershell or UI if you prefer, as long as it is in the folder that it belongs.

	-------------------------

	It will only be supported in the versions that were tested, and for now, 22H2 for both Win10 and 11, but not to builds before.
	There are additional checks, only up to a build that were tested and confirmed working. To prevent incompability with untested builds/versions.

	You are responsible for any damage it may cause, there will be checks and testing, but we never know if there is an unknown variable in your system could cause other problems.

	You are free to remove the checks and test yourself in different builds, but again it's your responsability for any damage it may cause. I wont be providing any support other than possibly fixing general confirmed bugs.

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

$SUPPORT_WIN11_UP_TO_BUILD = 0
$SUPPORT_WIN11_UP_TO_REV = 0
$SUPPORTED_VERSION = "22H2"

$DLLPath = "%SystemRoot%\System32"

$DLLs = @('UIRibbon', 'UIRibbonRes', 'Windows.UI.Logon', 'DWMInit', 'WSClient')

$Executables = @(
	'%SystemRoot%\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe',
	'%SystemRoot%\System32\RuntimeBroker.exe'
)

$Services = @(
	# [PsObject]@{Name = 'UxSms'; DefaultValue = 2}
)

# -----------------------------------------------------------------------------------------------------------------

function Get-OS-Build-Version {
	$Versions = [System.Environment]::OSVersion.Version
	$RevNumber = $Versions.Revision
	$BuildNumber = $Versions.Build
	return @{ RevNumber = $RevNumber; BuildNumber = $BuildNumber }
}

function Get-Display-Version {
	return Get-ComputerInfo | Select-Object -ExpandProperty OSDisplayVersion
}

function Get-Filename-From-Path {
	param ([string] $value)
	$valueSplit = $value.Split('\')
	return $valueSplit[$valueSplit.Length - 1]
}

function Is-Win11 {
	$Versions = Get-OS-Build-Version
	return $Versions.BuildNumber -ge 22000
}

function Is-Win10 {
	$Versions = Get-OS-Build-Version
	return $Versions.BuildNumber -gt 10000 -and $Versions.BuildNumber -lt 22000
}

function Is-OS-Version-Supported {
	$Versions = Get-OS-Build-Version
	$DisplayVersion = Get-Display-Version
	if (Is-Win10 -and $DisplayVersion -eq $SUPPORTED_VERSION) {
		return $true
	}
	return Is-Win11 -and $DisplayVersion -eq $SUPPORTED_VERSION -and $Versions.BuildNumber -le $SUPPORT_WIN11_UP_TO_BUILD -and $Versions.RevNumber -le $SUPPORT_WIN11_UP_TO_REV
}

function Show-Message {
	param ([string] $value)
	Write-Host "$value"
	[Environment]::NewLine
}

function Download-And-Install-Latest-OpenShell {
	if (Is-OpenShell-Installed) {
		Show-Message -value "OpenShell is already installed, ignore and continue."
		exit 0
	}
	$releasesJson = "https://api.github.com/repos/Open-Shell/Open-Shell-Menu/releases"
	$assets = (Invoke-WebRequest $releasesJson | ConvertFrom-Json)[0].assets
	$downloadUrl = ""
	foreach ($item in $assets) {
		if ($item.browser_download_url.Contains('.exe')) {
			$downloadUrl = $item.browser_download_url
		}
	}
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Show-Message -value "No download url found"
		exit 0
	}
	$FilePathName = "$PSScriptRoot\OpenShell-Latest.exe"
	Show-Message -value "Started downloading OpenShell - $downloadUrl"
	Invoke-WebRequest -URI $downloadUrl -OutFile $FilePathName
	Show-Message -value "Started installing OpenShell"
	& "$FilePathName" /qn ADDLOCAL=StartMenu
	Show-Message -value "Finished installing OpenShell"
	Remove-Item -Path $FilePathName -Force
}

function Get-OpenShell-Install-Id {
	return Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Open*" -and $_.Name -like "*Shell*" } | Select-Object -ExpandProperty IdentifyingNumber
}

function Is-OpenShell-Installed {
	$OpenShellId = Get-OpenShell-Install-Id
	if ([string]::IsNullOrWhiteSpace($OpenShellId)) { return $false } else { return $true }
}

function Uninstall-OpenShell {
	Show-Message -value "Started uninstalling OpenShell"
	$OpenShellId = Get-OpenShell-Install-Id
	MsiExec.exe /x $OpenShellId /qn
	Show-Message -value "Finished uninstalling OpenShell"
}

function Run-Command-With-Elevated-Permission {
	param ([string] $value)
	& "$PSScriptRoot\run_minsudo" "powershell -NoProfile -ExecutionPolicy Bypass -Command $value"
}

function Alter-REGs {
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "ConsoleMode" -Value 1 -Force -Type Dword -ErrorAction Ignore
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "XamlCredUIAvailable" -Value 0 -Force -Type Dword -ErrorAction Ignore
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\DWM" -Name "CompositionPolicy" -Value 0 -Force -Type Dword -ErrorAction Ignore
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" -Name "Debugger" -Value "%SystemRoot%\System32\rundll32.exe" -Force -Type String -ErrorAction Ignore
}

function Undo-REG-Changes {
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "XamlCredUIAvailable" -Value 1 -Force -Type Dword -ErrorAction Ignore
	Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\TestHooks" -Name "ConsoleMode" -Force -ErrorAction Ignore
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" -Name "Debugger" -Force -ErrorAction Ignore
}

function Disable-Executables {
	foreach ($item in $Executables) {
		$Filename = Get-Filename-From-Path -value $item
		Stop-Process -Name $Filename -Force -ErrorAction Ignore
		Run-Command-With-Elevated-Permission -value "Move-Item -Path $item -Destination "$item.backup" -Force -ErrorAction Ignore"
	}
}

function Enable-Executables {
	foreach ($item in $Executables) {
		Run-Command-With-Elevated-Permission -value "Move-Item -Path "$item.backup" -Destination $item -Force -ErrorAction Ignore"
	}
}

function Disable-DLLs {
	foreach ($dll in $DLLs) {
		$FilePath = "$DLLPath\$dll.dll"
		if (Test-Path -Path $FilePath -PathType Leaf) {
			Run-Command-With-Elevated-Permission -value "Move-Item -Path $FilePath -Destination "$FilePath.backup" -Force -ErrorAction Ignore"
		}
	}
}

function Enable-DLLs {
	foreach ($dll in $DLLs) {
		$FilePath = "$DLLPath\$dll.dll"
		$FilePathBackup = "$FilePath.backup"
		if (Test-Path -Path $FilePathBackup -PathType Leaf) {
			Run-Command-With-Elevated-Permission -value "Move-Item -Path $FilePathBackup -Destination $FilePath -Force -ErrorAction Ignore"
		}
	}
}

function Disable-Services {
	foreach ($item in $Services) {
		Run-Command-With-Elevated-Permission -value "Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\$($item.Name)" -Name "Start" -Value 4 -Force -Type Dword -ErrorAction Ignore"
	}
}

function Enable-Services {
	foreach ($item in $Services) {
		Run-Command-With-Elevated-Permission -value "Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\$($item.Name)" -Name "Start" -Value $($item.DefaultValue) -Force -Type Dword -ErrorAction Ignore"
	}
}

function Is-DWM-Enabled {
	if (Get-Process -Name dwm -ErrorAction SilentlyContinue) { return $true } else { $false }
}

function Restart-Machine {
	Show-Message -value "Process finished, this script will restart your machine in 10 seconds from now..."
	Start-Sleep -Seconds 10
	Restart-Computer
}

# -----------------------------------------------------------------------------------------------------------------

if (!(Is-OS-Version-Supported)) {
	Show-Message -value "Your OS version are not currently supported by this script!"
	exit
}

if (Is-DWM-Enabled) {
	Show-Message -value "Started process to disable DWM!"
	# Download-And-Install-Latest-OpenShell # Uncomment once done
	Alter-REGs
	Disable-Executables
	Disable-DLLs
	Disable-Services
} else {
	Show-Message -value "Started process to enable DWM!"
	Uninstall-OpenShell
	Undo-REG-Changes
	Enable-Executables
	Enable-DLLs
	Enable-Services
}

cmd /c pause # Remove once done

# Restart-Machine # Uncomment once the script are done and working
