# Night Sky
Night Sky is a ransomware family spotted in January 1st, 2022.  It appears to work in the RaaS (Ransomware-as-a-Service) model, such as other ransomware groups like REvil, LockBit, and Hive. [Details](https://www.netskope.com/blog/netskope-threat-coverage-night-sky).

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from Night Sky samples analyzed by Netskope Threat Labs

### Yara
* **Win64_Ransomware_NightSky**: Yara rule to identify unpacked Night Sky ransomware

### Code
* **create_mutex.cpp**: Simple code we created just to test if Night Sky was really skipping the encryption if the Mutex was already created.