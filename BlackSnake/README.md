# BlackSnake
BlackSnake is a RaaS (ransomware-as-a-service) group that first appeared in a hacking forum in August 2022. On February 28, 2023, a new variant of BlackSnake was spotted, notable for having a clipper module that targets cryptocurrency users.

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from the BlackSnake sample analyzed by Netskope Threat Labs

### Yara
* **Win32_BlackSnake_Ransomware.yar**: Yara rule to identify BlackSnake samples

### Scripts
* **README.md**: How to use the scripts we released
* **decode_strings.py**: This script decodes strings from a decompiled BlackSnake ransomware
