rule Win32_BlackSnake_Ransomware
{	
	meta:
		description = "Identifies BlackSnake ransomware"
		author = "Netskope Threat Labs"

	strings:
		$a01 = "AsymmetricKeyExchangeFormatterCONNECTDATA"
		$a02 = "AvailableFreeSpaceAddXmlElement"
		$a03 = "CkfiniteNotSupportedInComparableType"
		$a04 = "driveNotification"
		$a05 = "getidIsTerminating"
		$a06 = "NAMEsetRNG"
		$a07 = "URIFilterTypeNameIgnoreCase"
		$a08 = "WndProc"
		$b01 = "AddClipboardFormatListener"
		$b02 = "Clipboard"
		$b03 = "keyRSA"
		$b04 = "NAMEsetRNG"
		$b05 = "RijndaelManaged"
		$b06 = "RSACryptoServiceProvider"
		$b07 = "set_IV"
		$b09 = "textToEncrypt"

	condition:
		uint16(0) == 0x5a4d
		and 5 of ($a*) and 5 of ($b*)
}