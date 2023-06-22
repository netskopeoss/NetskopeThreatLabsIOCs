rule Win32_Khonsari_Ransomware
{
	meta:
		description = "Detects Khonsari Ransomware"
		author = "Netskope Threat Labs"

	strings:
		$ext = ".khonsari" wide nocase
		$str01 = "RSACryptoServiceProvider"
		$str02 = "RSAParameters"
		$str03 = "FromBase64String"
		$str04 = "ToBase64String"
		$str05 = "CryptoStream"
		$str06 = "MemoryStream"
		$str07 = "DownloadString"

	condition:
		uint16(0) == 0x5a4d and
		$ext and 5 of ($str*)
}