# Tokyo Olympics Wiper
A new malware threat emerged just before the 2020 Tokyo Olympics opening ceremony, able to damage an infected system by wiping its files. The malware disguises itself as a PDF document containing information about cyber attacks associated with the Tokyo Olympics. [Details](https://www.netskope.com/blog/netskope-threat-coverage-2020-tokyo-olympics-wiper-malware).

In this repository, you will find:

### IOCs
* **hashes.txt**: sha256 hashes from the  samples analyzed by Netskope Threat Labs
* **decrypted_strings.txt**: Decrypted strings from the sample analyzed in the blog post

### Yara
* **Win32_Olympics_Wiper.yar**: Yara rule to identify unpacked Tokyo Olympics Wiper samples

### Scripts
* **README.md**: How to use the scripts we released
* **decrypt_olympics_wiper_strings.py**: This script decrypts the strings from 2020 Tokyo Olympics Wiper samples
