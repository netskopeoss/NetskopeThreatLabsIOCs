rule Win32_Trojan_MHTGlitch : backdoor
{
	meta:
		description = "Identifies a backdoor from a malicious campaign identified by Netskope Threat Labs"
		reference = "f35ce827885711a49f7fa0f884cff05460bb3f582810b10beb06ceff57eda547"

	strings:
		$aes_seq = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }

		// Loop sequence, based on 0x10044177
		$asm_00 = { 66 8b ?? 83 c? 02 66 85 ?? 75 ?? 2b ??  }

		$api00 = "EnumProcesses"
		$api01 = "SHGetFolderPathW"
		$api02 = "SHCreateDirectoryExW"
		$api03 = "ObtainUserAgentString"
		$api04 = "GetAdaptersInfo"
		$api05 = "GetUserNameW"
		$api06 = "GetComputerNameExW"

		$str00 = "User:" wide nocase
		$str01 = "Computer:" wide nocase
		$str02 = "<DIR>" wide nocase
		$str03 = "properties.bin" wide nocase
		$str04 = "7zAES"
		$str05 = "LZMA"
		$str06 = "AES256CBC"
		$str07 = "BZip2"

	condition:
		uint16(0) == 0x5a4d
		and $aes_seq
		and #asm_00 > 2
		and all of ($api*)
		and all of ($str*)
}
