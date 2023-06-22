# MHTGlitch

Malicious campaign identified by Netskope Threat Labs that uses Web Page Archive files (".mht" or ".mhtml") to deliver infected documents, which eventually deploy a backdoor that uses Glitch for C2 communication. [Details](https://www.netskope.com/blog/abusing-microsoft-office-using-malicious-web-archive-files).

### IOCs
* **README.md**: All IOCs from this malicious campaign analyzed by Netskope Threat Labs.

### Yara
* **Win32_Trojan_MHTGlitch.yar**: Yara rule to identify the backdoor that is deployed through the infected Web Archive files.

### Scripts
* **README.md**: How to use the scripts we released
* **deobfuscate_macro_strings.py**: This script decodes strings from malicious VBA code, found in the MHTGlitch campaign.
