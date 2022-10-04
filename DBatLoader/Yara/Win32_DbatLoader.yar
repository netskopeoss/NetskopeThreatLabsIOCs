import "pe"

rule Win32_DBatLoader_Stage01
{
	meta:
		description = "Detects the first stage of DBatLoader samples"
		author = "Netskope Threat Labs"
		reference = "07915b1a44803fc9bd86d2d9ddad19434440b3d73f5c77f3400c84a935dd0255"

	strings:
		$str00 = "SOFTWARE\\Borland\\Delphi\\RTL"

		// 0x46d0ba
		$asm01 = { 93 53 59 87 d3 87 ca 6a ?? 5b 83 f0 ?? 6a ?? 59 6a 00 6a 01 }

		// 0x46cf39
		$asm02 = { 90 90 90 90 90 90 90 8d 04 ?? 8b 44 ?? ?? 8d ?? ?? 8b ?? ?? ?? 89 ?? ?? 6a 04 68 00 10 00 00  }

		// 0x46d0ba
		$asm03 = { 93 53 59 87 d3 87 ca 6a ?? 5b 83 f0 ?? 6a ?? 59 6a ?? 6a ?? 8b 4? ?? 50 ff 5? ??  }

	condition:
		uint16(0) == 0x5a4d
		and $str00 and 2 of ($asm*)
}

rule Win32_DBatLoader_Stage02
{
	meta:
		description = "Detects the second stage of DBatLoader samples"
		author = "Netskope Threat Labs"
		reference = "8f1d0ba030b897786c9ad6b68bb9165e539371648a8a60e2a6f1136647b5104e"

	strings:
		$delphi = "SOFTWARE\\Borland\\Delphi\\RTL"

		$str01 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
		$str02 = "C:\\Users\\Public\\nest"
		$str03 = "C:\\Users\\Public\\KDECO.bat"
		$str04 = "C:\\Users\\Public\\UKO.bat"
		$str05 = "C:\\Users\\Public\\Trast.bat"
		$str06 = "start /min C:\\Users\\Public\\UKO.bat"

	condition:
		uint16(0) == 0x5a4d
		and $delphi
		and 3 of ($str*)
		and pe.number_of_resources > 0
}