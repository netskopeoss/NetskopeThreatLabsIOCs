rule Win32_SquirrelWaffle_DLL
{
	meta:
		description = "Detects unpacked 32-bit SquirrelWaffle"
		author = "Netskope Threat Labs"

	strings:
		$pdb = "C:\\Users\\Administrator\\source\\repos\\Dll1\\Release\\Dll1.pdb"

		$str00 = "start /i /min /b start /i /min /b start /i /min /b"
		$str01 = "Dll1.dll" fullword
		$str02 = "ldr" fullword

		$asm_dec =  { 8a 04 ?? 32 04 ?? 8d 4? ?? 0f b6 c0 50 6a ?? e8 ?? ?? ?? ??  }

	condition:
		uint16(0) == 0x5a4d
		and ($pdb or all of ($str*) or $asm_dec)
}