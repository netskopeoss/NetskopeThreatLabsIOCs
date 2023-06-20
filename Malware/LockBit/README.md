# LockBit
LockBit Ransomware (a.k.a. ABCD) is yet another ransomware group operating in the RaaS (Ransomware-as-a-Service) model, following the same architecture as other major threat groups, like REvil. This threat emerged in September 2019 and is still being improved by its creators. 

In June 2021, the LockBit group announced the release of LockBit 2.0, which included a new website hosted on the deep web, as well as a new feature to encrypt Windows domains using group policy. [Details](https://www.netskope.com/blog/netskope-threat-coverage-lockbit).

In Semptember 2022, LockBit 3.0 (a.k.a LockBit Black) ransomware builder was leaked, allowing anyone to generate the necessary files to build LockBit payloads, such as the encryptor and decryptor. [Details](https://www.netskope.com/blog/netskope-threat-coverage-lockbits-ransomware-builder-leaked)

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from the LockBit sample analyzed by Netskope Threat Labs

### Yara
* **Win32_LockBit_Ransomware.yar**: Yara rule to identify LockBit samples
