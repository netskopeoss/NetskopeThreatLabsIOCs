import "pe"
import "math"

rule Win32_BlackMatter_Ransomware
{
    meta:
        description = "Detects the BlackMatter Ransomware"
        author = "Netskope Threat Labs"

    strings:
        $asm00 = { b8 ?? ?? ?? ?? 35 ?? ?? ?? ?? 50 e8 ?? ?? ?? ??  }
        $asm01 = { 64 a1 30 00 00 00 8b 40 0c 8d 48 0c 89 4d f0 8b 48 0c 8b 59 18 8b 43 3c 03 c3 8b 50 78 }
        $asm02 = { b9 ?? ?? ?? ?? 81 30 ?? ?? ?? ?? 83 c0 04 49 75 ??  }

    condition:
        uint16(0) == 0x5a4d
        and pe.number_of_imports < 4
        and math.entropy(pe.sections[pe.section_index(".rsrc")].raw_data_offset, pe.sections[pe.section_index(".rsrc")].raw_data_size) >= 7
        and 2 of ($asm*)
}