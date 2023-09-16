<#
	In case you decide to keep Windows Defender enabled, you can whitelist folders and files to prevent them to be scanned. That should help performance wise.
#>

# Start as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

Add-MpPreference -ExclusionPath "$(Split-Path -Path $PSScriptRoot -Parent)"
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp\NVIDIA Corporation\NV_Cache"
Add-MpPreference -ExclusionPath "$env:PROGRAMDATA\NVIDIA Corporation\NV_Cache"
Add-MpPreference -ExclusionPath "$env:windir\SoftwareDistribution\Datastore\Datastore.edb"
Add-MpPreference -ExclusionPath "$env:windir\SoftwareDistribution\Datastore\Logs\Edb*.jrs"
Add-MpPreference -ExclusionPath "$env:windir\SoftwareDistribution\Datastore\Logs\Edb.chk"
Add-MpPreference -ExclusionPath "$env:windir\SoftwareDistribution\Datastore\Logs\Tmp.edb"
Add-MpPreference -ExclusionPath "$env:windir\SoftwareDistribution\Datastore\Logs\*.log"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.edb"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.sdb"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.log"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.chk"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.jrs"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.xml"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.csv"
Add-MpPreference -ExclusionPath "$env:windir\Security\Database\*.cmtx"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.pol"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.tmp"
Add-MpPreference -ExclusionPath "$env:userprofile\NTUser.dat"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\sru\*.log"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\sru\*.dat"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\sru\*.chk"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\Configuration\MetaConfig.mof"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\winevt\Logs\*.evtx"
Add-MpPreference -ExclusionPath "$env:windir\apppatch\sysmain.sdb"
Add-MpPreference -ExclusionPath "$env:windir\EventLog\Data\lastalive?.dat"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\Configuration\DSCStatusHistory.mof"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\Configuration\DSCEngineCache.mof"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\Configuration\DSCResourceStateCache.mof"
Add-MpPreference -ExclusionPath "$env:SystemRoot\System32\Configuration\ConfigurationStatus"
Add-MpPreference -ExclusionPath "${env:ProgramFiles(x86)}\Steam\"
Add-MpPreference -ExclusionPath "${env:ProgramFiles(x86)}\Epic Games\"
Add-MpPreference -ExclusionPath "${env:ProgramFiles(x86)}\EA Games\"

Add-MpPreference -ExclusionProcess "${env:ProgramFiles(x86)}\Windows Kits\10\Windows Performance Toolkit\WPRUI.exe"
Add-MpPreference -ExclusionProcess "${env:ProgramFiles(x86)}\Windows Kits\10\Windows Performance Toolkit\wpa.exe"
Add-MpPreference -ExclusionProcess "${env:ProgramFiles(x86)}\Common Files\Steam\SteamService.exe"