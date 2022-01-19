# AgentTesla

Malicious campaign identified by Netskope Threat Labs that uses malicious PowerPoint files to deliver multiple malware, such as AgentTesla, hosting most of the payloads in cloud services.

### IOCs
* **README.md**: All IOCs from this malicious campaign analyzed by Netskope Threat Labs.
* **AgentTesla_decrypted_strings.txt**: Strings decrypted from AgentTesla sample analyzed in this campaign.
* **Win32_Loader_ProjFUD.yar**: Yara rule to identify the .NET injector used by AgentTesla.
* **Win32_Trojan_AgentTesla.yar**: Yara rule to identify AgentTesla samples.

