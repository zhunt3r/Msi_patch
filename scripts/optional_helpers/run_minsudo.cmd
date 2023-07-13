pushd "%~dp0"
pushd ..\tools

.\MinSudo --NoLogo --System --TrustedInstaller --Privileged cmd /c %1
