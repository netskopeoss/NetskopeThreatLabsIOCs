import "pe"

rule Win32_Trojan_Packed_RedLineStealer
{
    meta:
        description = "Identifies a loader used to deploy RedLine Stealer"
        author = "Netskope Threat Labs"
        reference = "4d77e265722624b5d4d1841d45c7c677"

    strings:
        $str00 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" wide
        $str01 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" wide

        $api01 = "VirtualProtect"
        $api02 = "SendMessageA"
        $api03 = "PostMessageA"

        $asm00 = { 8a 8? ?? ?? ?? ?? 30 04 ?e 46 }
        $asm01 = { 8a 8? ?? ?? ?? ?? 30 04 3e e8 }

    condition:
        uint16(0) == 0x5a4d
        and 1 of ($str*)
        and 2 of ($api*)
        and 1 of ($asm*)
}

rule Win32_Trojan_RedLineStealer
{
    meta:
        description = "Identifies RedLine Stealer samples"
        author = "Netskope Threat Labs"
        reference = "deb95cae4ba26dfba536402318154405"

    strings:
        $str00 = "System.Net.Sockets"
        $str01 = "ListOfPrograms"
        $str02 = "GetDefaultIPv4Address"
        $str03 = "GetWindowsVersion"
        $str04 = "cookies.sqlite" wide
        $str05 = "user.config" wide
        $str06 = "%appdata%\\discord\\Local Storage\\leveldb" wide
        $str07 = "{0}\\FileZilla\\recentservers.xml" wide
        $str08 = "Software\\Valve\\SteamLogin" wide
        $str09 = "NordVpn" wide

    condition:
        uint16(0) == 0x5a4d
        and pe.timestamp > 2210760000
        and all of ($str*)
}
