# MHTGlitch

Malicious campaign identified by Netskope Threat Labs that uses Web Page Archive files (".mht" or ".mhtml") to deliver infected documents, which eventually deploy a backdoor that uses Glitch for C2 communication.

### IOCs
* **README.md**: All IOCs from this malicious campaign analyzed by Netskope Threat Labs.
* **Win32_Trojan_MHTGlitch.yar**: Yara rule to identify the backdoor that is deployed through the infected Web Archive files.

### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decode the strings from infected documents related to this campaign.

```shell
(venv) pip install -r requirements.txt
(venv) python3 deobfuscate_macro_strings.py --payload /path/to/extracted_macro.vba
```

Since there are not a lot of strings, all of them are printed in the console.
