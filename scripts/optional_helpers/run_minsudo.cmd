pushd "%~dp0"
pushd ..\tools

.\MinSudo --NoLogo --Verbose --System --TrustedInstaller --Privileged cmd /c %1
