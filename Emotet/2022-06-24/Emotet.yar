import "pe"


rule Emotet_XLS_File
{
    meta:
        description = "Identifies XLS files possibly used by Emotet"
        author = "Netskope Threat Labs"
        reference = "0ce21d816db32d111c2e6f5d0d54348aa3df9003b548078f70fe141016257112"

	strings:
		$str01 = "Excel 4.0"
		$str02 = "Microsoft Excel"
		$str03 = "ownloadToFil"
		$scd01 = "scd1.ocx"
		$scd02 = "scd2.ocx"
		$scd03 = "scd3.ocx"
		$scd04 = "scd4.ocx"

	condition:
		all of ($str*) and 2 of ($scd*)
}

rule Win64_Trojan_Emotet
{
    meta:
        description = "Identifies 64-bit Emotet samples"
        author = "Netskope Threat Labs"
        reference = "839f19aeafb1c4acd58ef1f755982c01df810e103b468b1a545ebc64964e173e"

    strings:
		// Based on string decryption
        $asm00 = { 8b 0b 4? ff c3 4? 8d 5b 04 33 cd 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4? 8d 40 08 66 41 89 40 fa 0f b6 c1 66 c1 e9 08 66 41 89 40 fc 66 41 89 48 fe 4? 3b d9 72 }

		// Based on C2 address parsing
		$asm01 = { 4? 8d 05 ?? ?? ?? ?? 4? 89 8? ?? ?? ?? ?? 4? 8d 05 ?? ?? ?? ?? 4? 89 8? ?? ?? ?? ?? 4? 8d 05 ?? ?? ?? ?? 4? 89 4? ?? 4? 8d 05 ?? ?? ?? ?? 4? 89 8? ?? ?? ?? ?? 4? 8d 05 ?? ?? ?? ?? 4? 89 8? ?? ?? ?? ?? 4? 8d 05 ?? ?? ?? ?? 4? 89 8? ?? ?? ?? ?? 4? 8d 05 ?? ?? ?? ?? 4? 89 8? ?? ?? ?? ?? 4? 8d 05 }

		// Based on decryption keys
		$asm02 = { 45 33 c9 4? 8b d0 4? 85 c0 74 ?? 4? 8d 4b 48 4? 8b c0 4? 8b d1 4? 2b d3 4? 83 c2 03 4? c1 ea 02 4? 3b d9 4? 0f 47 d1 4? 85 d2 74 ?? 4? 2b d8 }

    condition:
        pe.is_64bit() and all of ($asm*)
}