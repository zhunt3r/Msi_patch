<#
	Automated script to disable Interrupt Moderation (XHCI) or Interrupt Threshold Control (EHCI) in all USB controllers.

	-------------------------

	https://www.overclock.net/threads/usb-polling-precision.1550666/page-61
	https://github.com/djdallmann/GamingPCSetup/tree/master/CONTENT/RESEARCH/PERIPHERALS#universal-serial-bus-usb
	https://github.com/BoringBoredom/PC-Optimization-Hub/blob/main/content/xhci%20imod/xhci%20imod.md
	https://linustechtips.com/topic/1477802-what-does-changing-driver-interrupt-affinity-cause-the-driver-to-do/
	https://www.overclock.net/threads/usb-polling-precision.1550666/page-61#post-28580928
	https://github.com/djdallmann/GamingPCSetup/issues/12
	https://www.overclock.net/threads/usb-polling-precision.1550666/page-61#post-28582024
	http://rweverything.com/ - RwDrv driver
	https://github.com/Faintsnow/HE - HwRwDrv driver
	https://github.com/Faintsnow/HE/issues/5#issuecomment-1172197067 - KX Utility

	Note: It will download the tool used, automatically, if that is not available. You dont need the whole folder anymore, just this script will be enough.

	Credits to @BoringBoredom, @amitxv and @djdallmann for helping in different ways.

	Additional Note: It's recommended that if you are on Win11, to have updated at least up to 07-2023 Cumulative Update KB5028185, because it contains a mouse pooling improvement.

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

$ToolsKX = "$(Split-Path -Path $PSScriptRoot -Parent)\tools\KX.exe"
$LocalKX = "$PSScriptRoot\KX.exe"

function KX-Exists {
	$ToolsKXExists = Test-Path -Path $ToolsKX -PathType Leaf
	$LocalKXExists = Test-Path -Path $LocalKX -PathType Leaf
	return @{LocalKXExists = $LocalKXExists; ToolsKXExists = $ToolsKXExists}
}

function Download-KX {
	$KXExists = KX-Exists
	if ($KXExists.ToolsKXExists -or $KXExists.LocalKXExists) {
		return
	}
	$downloadUrl = "https://github.com/dougg0k/gaming_os_tweaker/raw/main/scripts/tools/KX.exe"
	Write-Host "KX Utility not found, started downloading - $downloadUrl"
	[Environment]::NewLine
	Invoke-WebRequest -URI $downloadUrl -OutFile $LocalKX -UseBasicParsing
}

function Get-KX {
	$KXExists = KX-Exists
	if ($KXExists.ToolsKXExists) { return $ToolsKX } else { return $LocalKX }
}

function Get-Task-Info {
	$taskName = "InterruptModerationUsb"
	$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
	return @{TaskExists = $taskExists; TaskName = $taskName}
}

function Apply-Startup-Script {
	$TaskInfo = Get-Task-Info
	if (!$TaskInfo.TaskExists) {
		$action = New-ScheduledTaskAction -Execute "powershell" -Argument "-WindowStyle hidden -ExecutionPolicy Bypass -File $PSScriptRoot\interrupt_moderation_usb.ps1"
		$delay = New-TimeSpan -Seconds 10
		$trigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay $delay
		$principal = New-ScheduledTaskPrincipal -UserID "LOCALSERVICE" -RunLevel Highest
		$STSet = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
		Register-ScheduledTask -TaskName $($TaskInfo.TaskName) -Action $action -Trigger $trigger -Principal $principal -Settings $STSet
		[Environment]::NewLine

		# In case you have to remove the script from startup, but are not able to do from the UI, run:
		# Unregister-ScheduledTask -TaskName "InterruptModerationUsb"
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
		Write-Host "Setting up this script to be run at every windows startup automatically. Be sure to keep this file where you executed it from, otherwise there will be nothing to run."
		[Environment]::NewLine
		Apply-Startup-Script
	}
}

function Get-All-USB-Controllers {
	[PsObject[]]$USBControllers= @()

	$allUSBControllers = Get-CimInstance -ClassName Win32_USBController | Select-Object -Property Name, DeviceID
	foreach ($usbController in $allUSBControllers) {
		$allocatedResource = Get-CimInstance -ClassName Win32_PNPAllocatedResource | Where-Object { $_.Dependent.DeviceID -like "*$($usbController.DeviceID)*" } | Select @{N="StartingAddress";E={$_.Antecedent.StartingAddress}}
		$deviceMemory = Get-CimInstance -ClassName Win32_DeviceMemoryAddress | Where-Object { $_.StartingAddress -eq "$($allocatedResource.StartingAddress)" }

		$deviceProperties = Get-PnpDeviceProperty -InstanceId $usbController.DeviceID
		$locationInfo = $deviceProperties | Where KeyName -eq 'DEVPKEY_Device_LocationInfo' | Select -ExpandProperty Data
		$PDOName = $deviceProperties | Where KeyName -eq 'DEVPKEY_Device_PDOName' | Select -ExpandProperty Data

		$moreControllerData = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.DeviceID -eq "$($usbController.DeviceID)" } | Select-Object Service
		$Type = Get-Type-From-Service -value $moreControllerData.Service

		if ([string]::IsNullOrWhiteSpace($deviceMemory.Name)) {
			continue
		}

		$USBControllers += [PsObject]@{
			Name = $usbController.Name
			DeviceId = $usbController.DeviceID
			MemoryRange = $deviceMemory.Name
			LocationInfo = $locationInfo
			PDOName = $PDOName
			Type = $Type
		}
	}
	return $USBControllers
}

function Get-Type-From-Service {
	param ([string] $value)
	if ($value -ieq 'USBXHCI') {
		return 'XHCI'
	}
	if ($value -ieq 'USBEHCI') {
		return 'EHCI'
	}
	return 'Unknown'
}

function Convert-Decimal-To-Hex {
	param ([int64] $value)
	if ([string]::IsNullOrWhiteSpace($value)) { $value = "0" }
	return '0x' + [System.Convert]::ToString($value, 16).ToUpper()
}

function Convert-Hex-To-Decimal {
	param ([string] $value)
	if ([string]::IsNullOrWhiteSpace($value)) { $value = "0x0" }
	return [convert]::ToInt64($value, 16)
}

function Convert-Hex-To-Binary {
	param ([string] $value)
	$ConvertedValue = [Convert]::ToString($value, 2)
	return $ConvertedValue.PadLeft(32, '0')
}

function Convert-Binary-To-Hex {
	param ([string] $value)
	$convertedValue = [Convert]::ToInt64($value, 2)
	return Convert-Decimal-To-Hex -value $convertedValue
}

function Get-Hex-Value-From-Tool-Result {
	param ([string] $value)
	return $value.Split(" ")[19].Trim()
}

function Get-R32-Hex-From-Address {
	param ([string] $address)
	$Value = & "$(Get-KX)" /RdMem32 $address
	while ([string]::IsNullOrWhiteSpace($Value)) { Start-Sleep -Seconds 1 }
	return Get-Hex-Value-From-Tool-Result -value $Value
}

function Get-Reg-Value {
	param ([string] $path, [string] $name)
	return Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name -ErrorAction SilentlyContinue
}

function Get-Left-Side-From-MemoryRange {
	param ([string] $memoryRange)
	return $memoryRange.Split("-")[0]
}

function Get-BitRange-From-Binary {
	param ([string] $binaryValue, [int] $from, [int] $to)
	$backwardsFrom = $to
	$backwardsTo = $from
	return $binaryValue.SubString($binaryValue.Length - $backwardsFrom, $backwardsFrom - $backwardsTo)
}

function Find-First-Interrupter-Data {
	param ([string] $memoryRange)
	$LeftSideMemoryRange = Get-Left-Side-From-MemoryRange -memoryRange $memoryRange
	$CapabilityBaseAddressInDecimal = Convert-Hex-To-Decimal -value $LeftSideMemoryRange
	$RuntimeRegisterSpaceOffsetInDecimal = Convert-Hex-To-Decimal -value "0x18"
	$SumCapabilityPlusRuntime = Convert-Decimal-To-Hex -value ($CapabilityBaseAddressInDecimal + $RuntimeRegisterSpaceOffsetInDecimal)
	$Value = Get-R32-Hex-From-Address -address $SumCapabilityPlusRuntime
	$ValueInDecimal = Convert-Hex-To-Decimal -value $Value
	$TwentyFourInDecimal = Convert-Hex-To-Decimal -value "0x24"
	$Interrupter0PreAddressInDecimal = $CapabilityBaseAddressInDecimal + $ValueInDecimal + $TwentyFourInDecimal

	$FourInDecimal = Convert-Hex-To-Decimal -value "0x4"
	$HCSPARAMS1InHex = Convert-Decimal-To-Hex -value ($CapabilityBaseAddressInDecimal + $FourInDecimal)

	return @{ Interrupter0PreAddressInDecimal = $Interrupter0PreAddressInDecimal; HCSPARAMS1 = $HCSPARAMS1InHex }
}

function Build-Interrupt-Threshold-Control-Data {
	param ([string] $memoryRange)
	$LeftSideMemoryRange = Get-Left-Side-From-MemoryRange -memoryRange $memoryRange
	$LeftSideMemoryRangeInDecimal = Convert-Hex-To-Decimal -value $LeftSideMemoryRange
	$TwentyInDecimal = Convert-Hex-To-Decimal -value "0x20"
	$MemoryBase = Convert-Decimal-To-Hex -value ($LeftSideMemoryRangeInDecimal + $TwentyInDecimal)
	$MemoryBaseValue = Get-R32-Hex-From-Address -address $MemoryBase
	$ValueInBinary = Convert-Hex-To-Binary -value $MemoryBaseValue
	$ReplaceValue = '00000000'
	$BackwardsFrom = 16
	$BackwardsTo = 23
	$ValueInBinaryLeftSide = $ValueInBinary.Substring(0, $ValueInBinary.Length - $BackwardsTo)
	$ValueInBinaryRightSide = $ValueInBinary.Substring($ValueInBinary.Length - $BackwardsTo + $ReplaceValue.Length, ($ValueInBinary.Length - 1) - $BackwardsFrom)
	$ValueAddress = Convert-Binary-To-Hex -value ($ValueInBinaryLeftSide + $ReplaceValue + $ValueInBinaryRightSide)
	return [PsObject]@{ValueAddress = $ValueAddress; InterruptAddress = $MemoryBase}
}

function Find-Interrupters-Amount {
	param ([string] $hcsParams1)
	$Value = Get-R32-Hex-From-Address -address $hcsParams1
	$ValueInBinary = Convert-Hex-To-Binary -value $Value
	$MaxIntrsInBinary = Get-BitRange-From-Binary -binaryValue $ValueInBinary -from 8 -to 18
	$InterruptersAmount = Convert-Hex-To-Decimal -value (Convert-Binary-To-Hex -value $MaxIntrsInBinary)
	return $InterruptersAmount
}

function Disable-IMOD {
	param ([string] $address, [string] $value)
	$ValueData = "0x00000000"
	if (![string]::IsNullOrWhiteSpace($value)) { $ValueData = $value }
	$Value = & "$(Get-KX)" /WrMem32 $address $valueData
	while ([string]::IsNullOrWhiteSpace($Value)) { Start-Sleep -Seconds 1 }
}

function Get-All-Interrupters {
	param ([int64] $preAddressInDecimal, [int32] $interruptersAmount)
	[PsObject[]]$Data = @()
	if ($interruptersAmount -lt 1 -or $interruptersAmount -gt 1024) {
		Write-Host "Device interrupters amount is different than specified MIN (1) and MAX (1024) - FOUND $interruptersAmount - No address from this device will be IMOD disabled"
		return $Data
	}
	for ($i=0; $i -lt $interruptersAmount; $i++) {
		$AddressInDecimal = $preAddressInDecimal + (32 * $i)
		$InterrupterAddress = Convert-Decimal-To-Hex -value $AddressInDecimal
		$Address = Get-R32-Hex-From-Address -address $InterrupterAddress
		$Data += [PsObject]@{ValueAddress = $Address; InterrupterAddress = $InterrupterAddress; Interrupter = $i}
	}
	return $Data
}

function Execute-IMOD-Process {
	Write-Host "Started disabling Interrupt Moderation (XHCI) or Interrupt Threshold Control (EHCI) in all USB controllers"
	[Environment]::NewLine

	$USBControllers = Get-All-USB-Controllers

	if ($USBControllers.Length -eq 0) {
		Write-Host "Script didnt found any valid USB controllers to be disabled, try opening an issue at the same place you got this script from, take screenshot(s) from all your usb controllers at device manager or some place else you might know how to get, and use as feedback."
	} else {
		Write-Host "------------------------------------------------------------------"
	}
	[Environment]::NewLine

	foreach ($item in $USBControllers) {
		$InterruptersAmount = 'None'
		if ($item.Type -eq 'XHCI') {
			$FirstInterrupterData = Find-First-Interrupter-Data -memoryRange $item.MemoryRange
			$InterruptersAmount = Find-Interrupters-Amount -hcsParams1 $FirstInterrupterData.HCSPARAMS1
			$AllInterrupters = Get-All-Interrupters -preAddressInDecimal $FirstInterrupterData.Interrupter0PreAddressInDecimal -interruptersAmount $InterruptersAmount

			foreach ($interrupterItem in $AllInterrupters) {
				Disable-IMOD -address $interrupterItem.ValueAddress
				Write-Host "Disabled IMOD - Interrupter $($interrupterItem.Interrupter) - Interrupter Address $($interrupterItem.InterrupterAddress) - Value Address $($interrupterItem.ValueAddress)"
			}
		}
		if ($item.Type -eq 'EHCI') {
			$InterruptData = Build-Interrupt-Threshold-Control-Data -memoryRange $item.MemoryRange
			Disable-IMOD -address $InterruptData.InterruptAddress -value $InterruptData.ValueAddress
			Write-Host "Disabled Interrupt Threshold Control - Interrupt Address $($InterruptData.InterruptAddress) - Value Address $($InterruptData.ValueAddress)"
		}

		[Environment]::NewLine
		Write-Host "Device: $($item.Name)"
		Write-Host "Device ID: $($item.DeviceId)"
		Write-Host "Location Info: $($item.LocationInfo)"
		Write-Host "PDO Name: $($item.PDOName)"
		Write-Host "Device Type: $($item.Type)"
		Write-Host "Memory Range: $($item.MemoryRange)"
		Write-Host "Interrupters Count: $InterruptersAmount"
		[Environment]::NewLine
		Write-Host "------------------------------------------------------------------"
		[Environment]::NewLine
	}

}

# --------------------------------------------------------------------------------------------

Download-KX

Execute-IMOD-Process

Startup-Ask

cmd /c pause
