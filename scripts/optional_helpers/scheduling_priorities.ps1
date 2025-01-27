<#
  WIP (not done)

  It's done in a way, it works in normal processes, but in system processes like csrss.exe, it doesnt go beyond the normal basepriority value of 13. So, unless that can be resolved, it's not done.

  -------------------------

	https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities

	idle/low: 64, below normal: 16384, normal: 32, above normal: 32768, high: 128, realtime: 256

  -------------------------

  In case you get problems running the script in Win11 manually, you can run the command to bypass restriction, and after, another to set back to a safe or undefined policy.

  You can check the current policy settings:
  Get-ExecutionPolicy -List

  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Confirm:$false -Force
  Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser -Confirm:$false -Force
#>

# Start as administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

# Must include the extension, add other executables in here.
$RealtimeProcesses = @("csrss.exe", "wininit.exe")
$LowProcesses = @('dwm.exe')

# Set priority to every process in list
foreach ($item in $RealtimeProcesses) {
    $Process = Get-WmiObject -Class Win32_Process -Filter "name='$item'"; $Process.SetPriority(256);
}

foreach ($item in $LowProcesses) {
    $Process = Get-WmiObject -Class Win32_Process -Filter "name='$item'"; $Process.SetPriority(64);
}

# List changed processes priority
$Processes = ($RealtimeProcesses + $LowProcesses) | ForEach-Object { $_.split(".")[0] }
Get-Process $Processes | Format-List Name, PriorityClass, BasePriority

# Setup this script to be re-executed in every boot
$taskName = "SchedulingPriorities"
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
if (!$taskExists) {
    $action = New-ScheduledTaskAction -Execute "powershell" -Argument "-WindowStyle hidden -ExecutionPolicy Bypass -File $PSScriptRoot\scheduling_priorities.ps1"
    $delay = New-TimeSpan -Seconds 10
    $trigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay $delay
    $principal = New-ScheduledTaskPrincipal -UserID "LOCALSERVICE" -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal
}
