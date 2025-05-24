@echo off
title GSecurity && color 0b
rem Author: Gorstak

:: Clear Policy
rd /s /q "%windir%\System32\Group Policy"
rd /s /q "%windir%\System32\Group Policy Users"
rd /s /q "%windir%\SysWOW64\Group Policy"
rd /s /q "%windir%\SysWOW64\Group Policy Users"
Reg.exe delete "HKLM\SOFTWARE\Policies" /f
Reg.exe delete "HKCU\Software\Policies" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Editor" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects" /f

:: Enable Data Execution Prevention (DEP)
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'NoDataExecutionPrevention' /t 'REG_DWORD' /d "^""$data"^"" /f"
PowerShell -ExecutionPolicy Unrestricted -Command "$registryPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; $data =  '0'; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'DisableHHDEP' /t 'REG_DWORD' /d "^""$data"^"" /f"

:: Reset Windows Firewall to default (optional, comment out if not desired)
netsh advfirewall reset

:: Set default policies: block all inbound, allow specified outbound
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

:: === SYSTEM Rules ===
:: NetBIOS Datagrams (UDP 137-138)
netsh advfirewall firewall add rule name="NetBIOS Datagrams Inbound" dir=in action=block protocol=UDP localport=137-138 remoteport=137-138 profile=any

:: Microsoft DS (TCP 445)
netsh advfirewall firewall add rule name="Microsoft DS Client Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=445 profile=any
netsh advfirewall firewall add rule name="Microsoft DS Server Inbound" dir=in action=block protocol=TCP localport=445 remoteport=1024-65535 profile=any

:: NetBIOS Sessions (TCP 139)
netsh advfirewall firewall add rule name="NetBIOS Sessions Client Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=139 profile=any
netsh advfirewall firewall add rule name="NetBIOS Sessions Server Inbound" dir=in action=block protocol=TCP localport=139 remoteport=1024-65535 profile=any

:: ICMP Incoming (specific types)
netsh advfirewall firewall add rule name="ICMP Incoming" dir=in action=block protocol=ICMPv4 type=8 profile=any
netsh advfirewall firewall add rule name="ICMP Outgoing" dir=out action=block protocol=ICMPv4 type=8 profile=any

:: ICMPv6 Error and Info Messages
netsh advfirewall firewall add rule name="ICMPv6 Error Messages" dir=in action=block protocol=ICMPv6 type=1,2,3,4 profile=any
netsh advfirewall firewall add rule name="ICMPv6 Info Messages" dir=in action=block protocol=ICMPv6 type=128,129,133,134,135,136,137 profile=any

:: 6to4 Tunnel (Protocol 41)
netme advfirewall firewall add rule name="6to4 Tunnel IPv6" dir=in action=block protocol=41 profile=any

:: Teredo Tunnel (UDP 3544-3545)
netsh advfirewall firewall add rule name="Teredo Tunnel Outbound" dir=out action=block protocol=UDP localport=0-65535 remoteport=3544-3545 profile=any

:: RDP (TCP 3389)
netsh advfirewall firewall add rule name="RDP Inbound" dir=in action=block protocol=TCP localport=3389 remoteport=1024-65535 profile=any

:: PPTP (TCP 1723, GRE)
netsh advfirewall firewall add rule name="PPTP Call Control Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=1723 profile=any
netsh advfirewall firewall add rule name="PPTP GRE" dir=in action=block protocol=47 profile=any

:: UPnP (UDP 1900)
netsh advfirewall firewall add rule name="UPnP Inbound" dir=in action=block protocol=UDP localport=1900 remoteport=1-65535 profile=any
netsh advfirewall firewall add rule name="UPnP Outbound" dir=out action=block protocol=UDP localport=1-65535 remoteport=1900 profile=any

:: IGMP (Protocol 2)
netsh advfirewall firewall add rule name="IGMP" dir=in action=block protocol=2 profile=any

:: === Application-Specific Rules ===

:: iexplore.exe
netsh advfirewall firewall add rule name="iexplore HTTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=80-88 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore Alt HTTP1 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8000-8008 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore Alt HTTP2 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8080-8088 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore HTTPS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=443 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore Proxy Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=3128 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any
netsh advfirewall firewall add rule name="iexplore FTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=21 program="C:\Program Files\Internet Explorer\iexplore.exe" profile=any

:: SystemSettings.exe
netsh advfirewall firewall add rule name="SystemSettings HTTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=80 program="C:\Windows\ImmersiveControlPanel\SystemSettings.exe" profile=any
netsh advfirewall firewall add rule name="SystemSettings HTTPS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=443 program="C:\Windows\ImmersiveControlPanel\SystemSettings.exe" profile=any

:: explorer.exe
netsh advfirewall firewall add rule name="explorer HTTP Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=80-88 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer Alt HTTP1 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8000-8008 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer Alt HTTP2 Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=8080-8088 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer HTTPS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=443 program="C:\Windows\explorer.exe" profile=any
netsh advfirewall firewall add rule name="explorer Proxy Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=3128 program="C:\Windows\explorer.exe" profile=any

:: ftp.exe
netsh advfirewall firewall add rule name="ftp Command Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=21 program="C:\Windows\system32\ftp.exe" profile=any

:: lsass.exe
netsh advfirewall firewall add rule name="lsass DNS Outbound" dir=out action=block protocol=TCP localport=1024-65535 remoteport=53 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos UDP Out" dir=out action=block protocol=UDP localport=1024-65535 remoteport=88 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos UDP In" dir=in action=block protocol=UDP localport=88 remoteport=1024-65535 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos TCP Out" dir=out action=block protocol=TCP localport=1024-65535 remoteport=88 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Kerberos TCP In" dir=in action=block protocol=TCP localport=88 remoteport=1024-65535 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Location Service TCP Out" dir=out action=block protocol=TCP localport=1024-65535 remoteport=135 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Location Service UDP Out" dir=out action=block protocol=UDP localport=1024-65535 remoteport=135 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass Dynamic RPC Out" dir=out action=block protocol=TCP localport=1024-65535 remoteport=1026 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass LDAP UDP Out" dir=out action=block protocol=UDP localport=1024-65535 remoteport=389 program="C:\Windows\System32\lsass.exe" profile=any
netsh advfirewall firewall add rule name="lsass LDAP UDP In" dir=in action=block protocol=UDP localport=389 remoteport=1024-65535 program="C:\Windows\System32\lsass.exe" profile=any

:: takeown of group policy client service
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn setowner -ownr n:Administrators
SetACL.exe -on "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc" -ot reg -actn ace -ace "n:Administrators;p:full"

:: Services stop and disable
sc stop gpsvc
sc stop SSDPSRV
sc stop upnphost
sc stop NetBT
sc stop BTHMODEM
sc stop LanmanWorkstation
sc stop LanmanServer
sc stop seclogon
sc stop Messenger
sc config SSDPSRV start= disabled
sc config upnphost start= disabled
sc config NetBT start= disabled
sc config BTHMODEM start= disabled
sc config gpsvc start= disabled
sc config LanmanWorkstation start= disabled
sc config LanmanServer start= disabled
sc config seclogon start= disabled
sc config Messenger start= disabled

:: Consent
takeown /f %windir%\system32\consent.exe /A
icacls %windir%\system32\consent.exe /inheritance:r
icacls %windir%\system32\consent.exe /grant:r "CONSOLE LOGON":RX
icacls %windir%\system32\consent.exe /remove "ALL APPLICATION PACKAGES"
icacls %windir%\system32\consent.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
icacls %windir%\system32\consent.exe /remove "System"
icacls %windir%\system32\consent.exe /remove "Users"
icacls %windir%\system32\consent.exe /remove "Authenticated Users"
icacls %windir%\system32\consent.exe /remove "Administrators"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f

:: Perms
for /d %%d in (A B C D E F G H I J K L M N O P Q R S T U V X W Y Z) do (
    takeown /f %%d:\ /A
    icacls %%d:\ /grant "Console Logon:(OI)(CI)M" /T
    icacls %%d:\ /grant:r "System":F
    icacls %%d:\ /grant:r "Administrators":F
    icacls %%d:\ /remove "Everyone"
    icacls %%d:\ /remove "Authenticated Users"
    icacls %%d:\ /remove "Users"
    icacls %%d:\ /setowner "NT SERVICE\TrustedInstaller" /t
)

takeown /f "%USERPROFILE%\Desktop" /A
icacls "%USERPROFILE%\Desktop" /setowner "%username%" /t
icacls "%USERPROFILE%\Desktop" /grant "%username%:(OI)(CI)F" /T
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /remove "System"
icacls "%USERPROFILE%\Desktop" /remove "Users"
icacls "%USERPROFILE%\Desktop" /remove "Authenticated Users"
icacls "%USERPROFILE%\Desktop" /remove "Administrators"

takeown /f "%SystemDrive%\Users\Public\Desktop" /A
icacls "%SystemDrive%\Users\Public\Desktop" /setowner "%username%" /t
icacls "%SystemDrive%\Users\Public\Desktop" /grant "%username%:(OI)(CI)F" /T
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Creator Owner"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Batch"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Service"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "INTERACTIVE"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "System"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Users"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Authenticated Users"
icacls "%SystemDrive%\Users\Public\Desktop" /remove "Administrators"
