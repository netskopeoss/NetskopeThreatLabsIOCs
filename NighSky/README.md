# Night Sky
Night Sky is a ransomware family [spotted](https://twitter.com/malwrhunterteam/status/1477381209147723788) in January 1st, 2022.  It appears to work in the RaaS (Ransomware-as-a-Service) model, such as other ransomware groups like REvil, LockBit, and Hive.

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from Night Sky samples analyzed by Netskope Threat Labs
* **Win64_Ransomware_NightSky**: Yara rule to identify unpacked Night Sky ransomware

### Code
* **create_mutex.cpp**: Simple code we created just to test if Night Sky was really skipping the encryption if the Mutex was already created.