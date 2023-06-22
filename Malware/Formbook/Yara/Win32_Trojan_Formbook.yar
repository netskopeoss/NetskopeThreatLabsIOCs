import "pe"
import "math"


rule Win32_Trojan_Formbook_01
{
	meta:
		description = "Identifies the first stage of the .NET Formbook loader"
		author = "Netskope Threat Labs"
		sha256 = "388292015e4c2d075b935a8299d99335d957e3ad5134a33f28c4dc7f5e3687c5"

	strings:
		$str00 = "PlaylistPanda"
		$str01 = "CorExeMain"
		$str02 = "VarArgMet"
		$str03 = "System.Net"
		$str04 = "MainForm"
		$str05 = "x121312x121312"
		$str06 = "ZoneIdentityPermissionAttrib"

	condition:
		uint16(0) == 0x5a4d
		and math.entropy(0, filesize) >= 7
		and all of ($str*)
}

rule Win32_Trojan_Formbook_02
{
	meta:
		description = "Identifies the second stage of the .NET Formbook loader"
		author = "Netskope Threat Labs"
		sha256 = "e33254e2ad4d279914a29450f98d1750a9f513fc8ddb853e0dd8346b805faa43"

	strings:
		$str01 = "Microsoft.VisualBasic"
		$str02 = "SpaceChemSolver"
		$str03 = "SortHelper"
		$str04 = "RunCore"
		$str05 = "DemandedResources"
		$str06 = "ConstructionResponse"
		$str07 = "GetBytes"

	condition:
		uint16(0) == 0x5a4d
		and all of ($str*)
}

rule Win32_Trojan_Formbook_03
{
	meta:
		description = "Identifies the third stage of the .NET Formbook loader (a.k.a. CyaX-Sharp)"
		author = "Netskope Threat Labs"
		sha256 = "04e27134490848fda6a4fc5abaa4001d36bc222f0b1098698573c510e3af69c8"
		sha256 = "4322269fa75f84f6d21dd1e334fe01541ae55a6bed21d8ea7ea26b9bd2bff499"

	strings:
		$str01 = "DotNetZipAdditionalPlatforms"

		$p00 = "x5PhlKc5Z75TX8ZAxA.2M4tZ3G4Di2E5P924i"
		$p01 = "4HnSVBQUZwSvdLstPZ.tUdWKyFDwClq26Va54"

		$u00 = "eaIgfPjRhA"
		$u01 = "pepVuxoygA"
		$u02 = "fVkXSK7E.resources"
		$u04 = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTE2Ij8" wide

	condition:
		uint16(0) == 0x5a4d
		and $str01
		and (all of ($p*) or all of ($u*))
}

rule Win32_Trojan_Formbook_04
{
	meta:
		description = "Identifies the Formbook samples"
		author = "Netskope Threat Labs"
		sha256 = "0d1caeae9e59a10b6b52ffb7687966ec6b0c2f0f36b8d76657d51f1aa57cd737"

	strings:
		// Based on 0x409900
		$asm = { 55 8b ec 51 0f 31 33 c9 03 c8 0f 31 2b c1 }

		// Based on 0x4154e0
		$asm01 = { 3c 1d 0f 84 ?? ?? ?? ?? 8d 50 e0 80 fa 03 0f 86 ?? ?? ?? ?? 3c 24 0f 84 ?? ?? ?? ?? 3c 25 74 ?? 8d 48 d8 80 f9 03 0f 86 ?? ?? ?? ?? 3c 2c 74 ?? 3c 2d 0f 84 }

		// call $+5 -> pop eax -> retn
		$asm02 = { E8 00 00 00 00 58 C3 }

	condition:
		uint16(0) == 0x5a4d
		and pe.number_of_sections == 1
		and pe.number_of_imports == 0
		and math.entropy(0, filesize) >= 7
		and all of ($asm*)
}
