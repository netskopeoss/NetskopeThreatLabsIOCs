# DBatLoader and Warzone RAT
This folder contains data about a DBatLoader (a.k.a. ModiLoader) sample that uses Discord to deliver a malware known as Warzone (a.k.a. Ave Maria), a Remote Access Trojan created in 2018. [Details](https://www.netskope.com/blog/dbatloader-abusing-discord-to-deliver-warzone-rat).

In this repository, you will find:

### IOCs
* **README.md**: All the IOCs related to the DBatLoader and Warzone analysis.

### Yara
* **Win32_DbatLoader.yar**: Detects DBatLoader samples analyzed in this campaign
* **Win32_Warzone_RAT.yar**: Detects unpacked Warzone RAT (a.k.a. Ave Maria) samples

### Scripts
* **README.md**: How to use the scripts we released
* **decrypt_warzone_c2.py**: This script decrypts the C2 address from unpacked Warzone RAT samples
