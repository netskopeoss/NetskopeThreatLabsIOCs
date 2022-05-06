import "pe"


rule Emotet_LNK_File
{
    meta:
        description = "Identifies LNK files possibly used by Emotet"
        author = "Netskope Threat Labs"
        reference = "3a8ba63525e63a389284a822463d78836b3aba1ad3ac960e761620a3c31ca040"

    strings:
        $lnk = {4C 00 00 00 01 }
        $str00 = "powershell.exe" nocase
        $str01 = "Out-Null;" wide nocase
        $str02 = "[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String" wide nocase
        $str03 = "powershell -executionpolicy bypass -file" wide nocase

    condition:
        $lnk at 0 and all of ($str*)
}

rule Win64_Trojan_Emotet
{
    meta:
        description = "Identifies 64-bit Emotet samples"
        author = "Netskope Threat Labs"
        reference = "331c8818e5326be8cacf9e655733ce9a71599ee344f186d9f82080f6182b7596"

    strings:
        $asm00 = { 8b ?? 4? ff c? 4? 8d ?? ?? 33 ?? 0f b6 ?? 66 41 89 ?? 0f b7 ?? c1 e? ?? 66 c1 e? ?? 4? 8d ?? ?? 66 41 89 ?? ?? 0f b6 ?? 66 c1 e? ?? 66 41 89 ?? ?? 66 41 89 ?? ?? 4? 3b ?? 72 ??  }
        $asm01 = { 45 33 ?? 4? 8b ?? 4? 85 ?? 74 ?? 8b ?? 45 8b ?? 4? c1 e? ?? 4? 8d ?? ?? 4? 8b ?? 4? 2b ?? 4? 83 c? ?? 4? c1 e? ?? 4? 3b ?? 4? 0f 47 ?? 4? 85 ?? 74 ?? 4? 8b ?? 4? 2b ?? }
        $asm03 = { 0f b7 c1 c1 e9 10 66 c1 e8 08  }

    condition:
        pe.is_64bit()
        and pe.exports("DllRegisterServer")
        and all of ($asm*)
}