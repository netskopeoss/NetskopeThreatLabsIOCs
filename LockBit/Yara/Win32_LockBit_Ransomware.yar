rule Win32_LockBit_Ransomware
{
    meta:
        description = "Detects the Lockbit Ransomware"
        author = "Netskope Threat Labs"

    strings:
        $v1_00 = "Service %s stopped"
        $v1_01 = "SOFTWARE\\LockBit"
        $v1_02 = "All your important files are encrypted"
        $v1_03 = "Download Tor browser"

        $v2_lb = "LockBit" wide nocase fullword
        $v2_00 = "Elevation:Administrator" wide nocase
        $v2_01 = "gpupdate" wide nocase
        $v2_02 = "LDAP://" wide nocase
        $v2_03 = "NETLOGON" wide nocase
        $v2_04 = "powershell.exe" wide nocase
        $v2_05 = "Microsoft XPS Document Writer" wide nocase
        $v2_06 = "RESTORE-MY-FILES.TXT" wide nocase
        $v2_07 = "ToxID" wide nocase
        $v2_08 = "mshta.exe" wide nocase

        $svc00 = "sophos"
        $svc01 = "veeam"
        $svc02 = "backup"
        $svc03 = "bedbg"
        $svc04 = "PDVFSService"
        $svc05 = "BackupExecVSSProvider"
        $svc06 = "BackupExecAgentAccelerator"
        $svc07 = "BackupExecAgentBrowser"
        $svc08 = "BackupExecDiveciMediaService"
        $svc09 = "BackupExecJobEngine"
        $svc10 = "BackupExecManagementService"
        $svc11 = "BackupExecRPCService"
        $svc12 = "MVArmor"
        $svc13 = "MVarmor64"
        $svc14 = "VSNAPVSS"
        $svc15 = "VeeamTransportSvc"
        $svc16 = "VeeamDeploymentService"
        $svc17 = "VeeamNFSSvc"
        $svc18 = "AcronisAgent"

        $cmd00 = "/c vssadmin Delete Shadows /All /Quiet"
        $cmd01 = "/c bcdedit /set {default} recoveryenabled No"
        $cmd02 = "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures"
        $cmd03 = "/c wbadmin DELETE SYSTEMSTATEBACKUP"
        $cmd04 = "/c wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest"
        $cmd05 = "/c wmic SHADOWCOPY /nointeractive"
        $cmd06 = "/c wevtutil cl security"
        $cmd07 = "/c wevtutil cl system"
        $cmd08 = "/c wevtutil cl application"

    condition:
        uint16(0) == 0x5a4d
		and (
			(all of ($v1_*) and 5 of ($svc*) and 3 of ($cmd*)) or
			($v2_lb and 4 of ($v2_0*))
		)
}