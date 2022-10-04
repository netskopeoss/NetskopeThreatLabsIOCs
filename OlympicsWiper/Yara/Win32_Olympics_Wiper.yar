rule Win32_Olympics_Wiper
{
    meta:
        description = "Detects wiper malware found during the Tokyo 2021 Olympics"
        author = "Netskope Threat Labs"

    strings:
        $str01 = "\\\\.\\Global\\ProcmonDebugLogger"
        $str02 = "OllyDbg"
        $str03 = "TIdaWindow"
        $str04 = "WinDbgFrameClass"
        $str05 = "FilemonClass"
        $str06 = "RegmonClass"
        $str07 = "PROCEXPL"
        $str08 = "TCPViewClass"
        $str09 = "SmartSniff"
        $str10 = "Autoruns"
        $str11 = "ProcessHacker"

        $asm_bp_check = { 8? ?? cc }
        $asm_vmware_check =  { b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56  }
        $asm_jmp_check = { 8a 00 3c e9 0f 84 ?? ?? ?? ?? 3c eb 0f 84 ?? ?? ?? ??  }

    condition:
        uint16(0) == 0x5a4d and
        8 of ($str*) and 2 of ($asm*)
}