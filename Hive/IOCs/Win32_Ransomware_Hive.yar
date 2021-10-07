rule Win32_Ransomware_Hive
{
	meta:
		description = "Detects unpacked 32-bit Hive Ransomware"
		author = "Netskope Threat Labs"

	strings:
		$go = "GO build" nocase
		$str00 = "EncryptFile"
		$str01 = "EncryptFiles"
		$str02 = "EraseKey"
		$str03 = "ExportKey"
		$str04 = "KillProcess"
		$str05 = "Notify"
		$str06 = "PreNotify"
		$str07 = "RemoveItself"
		$str08 = "RemoveShadowCopies"
		$str09 = "ScanFiles"
		$str10 = "StopServices"

	condition:
		uint16(0) == 0x5a4d
		and $go and 8 of ($str*)
}
