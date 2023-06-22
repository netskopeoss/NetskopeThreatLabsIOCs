# SquirrelWaffle
In September 2021, a new malware family named SquirrelWaffle joined the threat landscape. It spread through infected Microsoft Office documents attached in spam emails. [Details](https://www.netskope.com/blog/squirrelwaffle-new-malware-loader-delivering-cobalt-strike-and-qakbot).

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from SquirrelWaffle samples analyzed by Netskope Threat Labs
* **SquirrelWaffle_decrypted_strings.txt**: Decrypted strings from the file analyzed by Netskope Threat Labs

### Yara
* **Win32_SquirrelWaffle_DLL.yar**: Yara rule to identify unpacked SquirrelWaffle DLLs

### Scripts
* **README.md**: How to use the scripts we released
* **decrypt_config.py**: This script decrypts the configuration from unpacked SquirrelWaffle DLL samples
