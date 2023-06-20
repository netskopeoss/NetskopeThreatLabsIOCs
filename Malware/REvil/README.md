# REvil
The REvil ransomware (a.k.a Sodinokibi) is a threat group that operates in the RaaS (Ransomware-as-a-Service) model, where the infrastructure and the malware is supplied to affiliates, who can use the malware to infect target organizations. [Details](https://www.netskope.com/blog/netskope-threat-coverage-revil).

In this repository, you will find:

### IOCs
* **REvil_domains.txt**: domains from the files analyzed in the blog post, from Kaseya's incident.
* **REvil_hashes.txt**: sha256 hashes from the files analyzed in the blog post, from Kaseya's incident.
* **REvil_decrypted_config.json**: Decrypted configuration from the REvil unpacked payload.

### Scripts
* **README.md**: How to use the scripts we released
* **decrypt_REvil_config.py**: This script decrypts the configuration from unpacked REvil samples
