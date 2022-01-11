rule Win64_Ransomware_NightSky: ransomware
{
    meta:
        description = "Identifies unpacked/dumped Night Sky ransomware samples"
        author = "Netskope Threat Labs"

    strings:
        $str00 = ".nightsky" nocase wide
        $str01 = "NightSkyReadMe.hta" nocase wide
        $str02 = "tset123155465463213" nocase wide
        $str03 = "-----BEGIN RSA PUBLIC KEY-----"
        $str04 = "-----END RSA PUBLIC KEY-----"

    condition:
        uint16(0) == 0x5a4d and 3 of ($str*)
}
