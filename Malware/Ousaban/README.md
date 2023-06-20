# Ousaban
Ousaban (a.k.a. Javali) is a banking malware that emerged between 2017 and 2018, with the primary goal of stealing sensitive data from financial institutions in Brazil. This malware is developed in Delphi and it comes from a stream of LATAM banking trojans sourced from Brazil, sharing similarities with other families like Guildma, Casbaneiro and Grandoreiro. [Details](https://www.netskope.com/blog/ousaban-latam-banking-malware-abusing-cloud-services). 

In this repository, you will find:

### Folders
* **IOCs**: All the IOCs related to the Ousaban campaign analyzed by Netskope.

### Scripts
* **README.md**: How to use the scripts we released
* **decrypt_strings.py**: This script can be used to decrypt strings found in Brazilian-based banking malware (e.g. Ousaban,
Guildma, Grandoreiro, etc)
* **decrypt_payload.py**: This script can be used to decrypt Ousaban malware payloads.
