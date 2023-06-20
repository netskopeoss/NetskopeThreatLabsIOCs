rule Win32_Ransomware_KillDisk: wiper
{
	meta:
		description = "Detects HermeticWiper samples"
		author = "Netskope Threat Labs"

	strings:
		$str00 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" wide fullword
		$str01 = "SYSTEM\\CurrentControlSet\\Control\\CrashControl" wide fullword
		$str02 = "SeLoadDriverPrivilege" wide fullword
		$str03 = "ServicesActive" wide fullword
		$str04 = "SeBackupPrivilege" wide fullword
		$str05 = "\\\\.\\EPMNTDRV\\%u" wide fullword
		$str06 = "DRV_X64" wide fullword
		$str07 = "DRV_X86" wide fullword
		$str08 = "DRV_XP_X64" wide fullword
		$str09 = "DRV_XP_X86" wide fullword

	condition:
		uint16(0) == 0x5a4d
		and 6 of ($str*)
}
