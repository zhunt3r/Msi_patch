# Tools Source

> If you dont trust the stored files from this folder, you can download them yourself directly from the place where it was downloaded from. I just recommend that if you are going to use scripts, keep/overwrite the .exe you download at this folder, the way it is, otherwise some scripts will not work.

- Device Cleanup CMD - <https://www.majorgeeks.com/files/details/device_cleanup_cmd>

- Nvidia Profile Inspector - <https://github.com/Orbmu2k/nvidiaProfileInspector/releases>

- NanaRun (MinSudo) - <https://github.com/M2Team/NanaRun/releases> - It's the alternative recommendation and from the same team as the now archived NSudo - <https://github.com/M2TeamArchived/NSudo>

- KX Utility - <https://github.com/Faintsnow/HE/issues/5#issuecomment-1172197067>

- Nvidia Control Panel - It's here if someone are unable to install from the driver into their system, not an actual helper tool.
  - If `nvcplui.exe` get a block message, it means you might have a ownership problem, you can try one or more from the following commands, first you go to the unziped folder in powershell. (PS: You might NOT need all of them)
  - `Get-Acl .\nvcplui.exe` to check current ownership information in a file
  - `icacls * /t /q /c /reset` to reset ownership
  - `icacls * /grant administrators:F /T` to assign administrator to every file in the folder
  - `takeown /f * /r /d y` to take ownership

- Low Audio Latency - <https://github.com/spddl/LowAudioLatency/releases>
