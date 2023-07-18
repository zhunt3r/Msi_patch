
# WIP (not done)

# -----------------------------------------------------------------------------

# Windows Update through powershell

if (!(Get-Module -Name PSWindowsUpdate)) {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module PSWindowsUpdate
    Add-WUServiceManager -MicrosoftUpdate
}

# Get detailed documentations of a module / command. E.g.,
# Get-Help Get-WindowsUpdate -detailed

# If you are getting errors using commands, you need to set a exec policy before, to allow. After you can restrict again.
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# -----------------------------------------------------------------------------

# Check available updates
# Get-WindowsUpdate

# Check Service Ids available
# Get-WUServiceManager

# Enable newest service option
# Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -AddServiceFlag 7

# Install all updates
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -Verbose

# Exclude specific updates from installing
# Hide-WindowsUpdate -KBArticleID KB5028185

# Install specific update - Like the one with Mouse Pooling fixes KB5028185
# Install-WindowsUpdate -KBArticleID KB5028185

# Remove specific update
# Remove-WindowsUpdate -KBArticleID KB5028185

# Check if update require reboot
# Get-WURebootStatus

# Check update history
# Get-WUHistory

# -------------------------------------------------------------------------------

Set-ExecutionPolicy Undefined -Scope CurrentUser -Force
