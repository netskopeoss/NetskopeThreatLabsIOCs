rule Win32_Trojan_AgentTesla
{
	meta:
		description = "Identifies AgentTesla samples."
		author = "Netskope Threat Labs"

	strings:
		$bin00 = "#Blob"
		$bin01 = "#GUID"
		$bin02 = "#Strings"

		$str00 = "get_AccountCredential"
		$str01 = "get_accountName"
		$str02 = "get_Address"
		$str03 = "get_AltKeyDown"
		$str04 = "get_Assembly"
		$str05 = "get_Attachments"
		$str06 = "get_Clipboard"
		$str07 = "get_Computer"
		$str08 = "get_ComputerName"
		$str09 = "get_Connected"
		$str10 = "get_ExecutablePath"
		$str11 = "get_Host"
		$str12 = "get_Key"
		$str13 = "get_Keyboard"
		$str14 = "get_ProcessName"
		$str15 = "set_UserAgent"
		$str16 = "set_UserName"
		$str17 = "set_IsBodyHtml"
		$str18 = "set_IV"

	condition:
		uint16(0) == 0x5a4d
		and all of ($bin*) and 10 of ($str*)
}
