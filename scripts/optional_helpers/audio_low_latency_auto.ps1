# Start as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

$ToolsLAT = "$(Split-Path -Path $PSScriptRoot -Parent)\tools\low_audio_latency_no_console.exe"
$LocalLAT = "$PSScriptRoot\low_audio_latency_no_console.exe"

function Show-Message {
	param ([string] $value)
	Write-Host "$value"
	[Environment]::NewLine
}

function LAT-Exists {
	$ToolsLATExists = Test-Path -Path $ToolsLAT -PathType Leaf
	$LocalLATExists = Test-Path -Path $LocalLAT -PathType Leaf
	return @{LocalLATExists = $LocalLATExists; ToolsLATExists = $ToolsLATExists}
}

function Download-LAT {
	$LATExists = LAT-Exists
	if ($LATExists.ToolsLATExists -or $LATExists.LocalLATExists) {
		return
	}
	$releasesJson = "https://api.github.com/repos/spddl/LowAudioLatency/releases"
	$assets = (Invoke-WebRequest $releasesJson -UseBasicParsing | ConvertFrom-Json)[0].assets
	$downloadUrl = ""
	foreach ($item in $assets) {
		if ($item.browser_download_url.Contains('low_audio_latency_no_console.exe')) {
			$downloadUrl = $item.browser_download_url
		}
	}
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Show-Message -value "No download url found"
		return
	}
	Show-Message -value "Downloading latest version - Low Audio Latency - $downloadUrl"
	Invoke-WebRequest -URI $downloadUrl -OutFile $LocalLAT -UseBasicParsing
}

function Get-LAT {
	$LATExists = LAT-Exists
	if ($LATExists.ToolsLATExists) { return $ToolsLAT } else { return $LocalLAT }
}

function Get-Task-Info {
	$taskName = "AudioLowLatencyAuto"
	$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
	return @{TaskExists = $taskExists; TaskName = $taskName}
}

function Apply-Startup-Script {
	$TaskInfo = Get-Task-Info
	if (!$TaskInfo.TaskExists) {
		$action = New-ScheduledTaskAction -Execute "$(Get-LAT)"
		$delay = New-TimeSpan -Seconds 10
		$trigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay $delay
		$UserName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
		$principal = New-ScheduledTaskPrincipal -UserID $UserName -RunLevel Highest -LogonType Interactive
		Register-ScheduledTask -TaskName $($TaskInfo.TaskName) -Action $action -Trigger $trigger -Principal $principal
		[Environment]::NewLine

		# In case you have to remove the script from startup, but are not able to do from the UI, run:
		# Unregister-ScheduledTask -TaskName "AudioLowLatencyAuto"
	}
}

function Startup-Ask {
	$TaskInfo = Get-Task-Info
	if ($TaskInfo.TaskExists) {
		Write-Host "You already set this script up to be run automatically at every startup."
		[Environment]::NewLine
		return
	}
	$startup = Read-Host "Do you wish set this script to be automatically run at every windows start-up? [Y] or [N]"
	[Environment]::NewLine
	if ($startup -eq "Y") {
		Write-Host "Setting up this script to be run at every windows startup automatically. Be sure to keep the downloaded file where you executed this script from, but only if you didnt get the whole gaming_os_tweaker folder, otherwise it should be in tools folder."
		[Environment]::NewLine
		Apply-Startup-Script
	}
}

function Execute-LAT {
	& "$(Get-LAT)"
}

# --------------------------------------------------------------------------------------------

Show-Message -value "If you set this to be started automatically at every windows start, you only need to execute this script once."

Download-LAT

Startup-Ask

Execute-LAT

cmd /c pause