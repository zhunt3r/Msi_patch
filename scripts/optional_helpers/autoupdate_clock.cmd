powershell -c "$action = New-ScheduledTaskAction -Execute \"cmd.exe\" -Argument \"/c net start w32time; w32tm /resync; net stop w32time;\"; $trigger = New-ScheduledTaskTrigger -AtLogOn; $principal = New-ScheduledTaskPrincipal -UserID $env:USERNAME -RunLevel Highest; Register-ScheduledTask -TaskName \"AutoUpdateClock\" -Action $action -Trigger $trigger -Principal $principal;"
