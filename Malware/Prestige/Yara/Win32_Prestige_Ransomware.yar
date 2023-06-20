rule Win32_Prestige_Ransomware
{
    meta:
        description = "Detects the Prestige Ransomware"
        author = "Netskope Threat Labs"
        reference = "5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57"

    strings:
        $v1_00 = "C:\\Users\\Public\\README" wide
        $v1_01 = "@proton.me" wide nocase
        $v1_02 = "you personal files have been encrypted" wide nocase

        $ext00 = ".backup" wide
        $ext01 = ".bak2" wide
        $ext02 = ".bak3" wide
        $ext03 = ".bkup" wide
        $ext04 = ".bzip" wide
        $ext05 = ".bzip2" wide
        $ext06 = ".db-wal" wide
        $ext07 = ".docm" wide
        $ext08 = ".docx" wide
        $ext09 = ".dotm" wide
        $ext10 = ".dotx" wide
        $ext11 = ".dump" wide
        $ext12 = ".gzip" wide
        $ext13 = ".java" wide
        $ext14 = ".jpeg" wide
        $ext15 = ".json" wide
        $ext16 = ".lzma" wide
        $ext17 = ".mdmr" wide
        $ext18 = ".mpeg" wide
        $ext19 = ".nude" wide
        $ext20 = ".nvram" wide

        $cmd00 = "MSSQLSERVER" wide
        $cmd01 = "wbadmin.exe delete catalog -quiet" wide
        $cmd02 = "vssadmin.exe delete shadows /all /quiet" wide
        $cmd03 = "reg.exe add HKCR\\.enc" wide
        $cmd04 = "reg.exe add HKCR\\enc\\shell\\open\\command" wide

    condition:
        uint16(0) == 0x5a4d
        and all of them
}