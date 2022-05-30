import "pe"


rule Win32_Ransomware_Jasmin
{
    meta:
        description = "Identifies Jasmin (a.k.a. GoodWill) ransomware samples"
        author = "Netskope Threat Labs"
        reference = "cea1cb418a313bdc8e67dbd6b9ea05ad"

	strings:
		$str01 = ".NET Framework"
		$str02 = "AES_Encrypt"
		$str03 = "CheckConnection"
		$str04 = "FileEncryption"
		$str05 = "GeneratePassword"
		$str06 = "GenerateSystemId"
		$str07 = "hostaddr"
		$str08 = "MakeConnection"
		$str09 = "passwordkey"
		$str10 = "RetriveFiles"
		$str11 = "RNGCryptoServiceProvider"
		$str12 = "StartExtraction"
		$str13 = "WriteSystemId"

    condition:
        uint16(0) == 0x5a4d
        and pe.timestamp > 1893499200
        and 8 of ($str*)
}
