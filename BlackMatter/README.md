# BlackMatter
In July 2021, a new ransomware named BlackMatter emerged and was being advertised in web forums, where the group was searching for compromised networks from companies with revenues of $100 million or more per year. [Details](https://www.netskope.com/blog/netskope-threat-coverage-blackmatter).

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from the BlackMatter sample analyzed by Netskope Threat Labs

### Yara
* **Win32_BlackMatter_Ransomware.yar**: Yara rule to identify BlackMatter samples

### Scripts
* **README.md**: How to use the scripts we released
* **decrypt_data.py**: This script decrypts strings and the configuration from unpacked BlackMatter ransomware samples
* **generate_hash.py**: This script generates the hashes used by BlackMatter to decode API calls