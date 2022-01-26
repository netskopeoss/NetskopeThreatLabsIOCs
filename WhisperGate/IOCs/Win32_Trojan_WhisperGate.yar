rule Win32_Trojan_WhisperGate
{
	meta:
		description = "Identifies the fist stage of WhisperGate malware"
		author = "Netskope Threat Labs"

	strings:
		$str00 = "\\\\.\\PhysicalDrive0" wide
		$str01 = "GCC: (GNU)"
		$str02 = "AAAAA"
		$str03 = "Your hard drive has been corrupted"
		$str04 = "In case you want to recover all hard drives"
		$str05 = "You should pay us"
		$str06 = "We will contact you to give further instructions"
		$str07 = "You should pay us"

	condition:
		uint16(0) == 0x5a4d and 5 of ($str*)
}

rule Win32_Network_WhisperGate
{
	meta:
		description = "Identifies the fourth stage of WhisperGate malware"
		author = "Netskope Threat Labs"

	strings:
		// Based on 0x004014E3
		$asm = { e8 ?? ?? ?? ?? 89 c2 b9 00 00 10 00 b0 cc 89 d7  }

		$str01 = "cmd.exe /min /C ping 111.111.111.111 -n 5 -w 10 > Nul & Del /f /q" 
		$str02 = "A:\\Windows" wide
		$str03 = ".HTML" wide
		$str04 = ".XHTML" wide
		$str05 = ".DOCX" wide
		$str06 = ".PPTX" wide
		$str07 = ".ONETOC2" wide
		$str08 = ".JPEG" wide
		$str09 = ".DOTM" wide
		$str10 = ".DOTX" wide
		$str11 = ".XLSM" wide
		$str12 = ".XLSB" wide
		$str13 = ".XLTX" wide
		$str14 = ".XLTM" wide
		$str15 = ".PPTM" wide
		$str16 = ".PPSM" wide
		$str17 = ".PPSX" wide
		$str18 = ".PPAM" wide
		$str19 = ".POTX" wide
		$str20 = ".POTM" wide
		$str21 = ".TIFF" wide

	condition:
		uint16(0) == 0x5a4d and all of them
}
