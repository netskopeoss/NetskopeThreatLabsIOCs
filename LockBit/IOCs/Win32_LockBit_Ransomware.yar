rule Win32_LockBit_Ransomware
{
    meta:
        description = "Detects the Lockbit Ransomware"
        author = "Netskope Research Team"

    strings:
        $str00 = "Service %s stopped"
        $str01 = "SOFTWARE\\LockBit"
        $str02 = "All your important files are encrypted"
        $str03 = "Download Tor browser"

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
        uint16(0) == 0x5a4d and
        all of ($str*) and 10 of ($svc*) and 5 of ($cmd*)
}
