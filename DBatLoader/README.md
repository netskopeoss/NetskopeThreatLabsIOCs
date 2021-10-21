# DBatLoader and Warzone RAT
This folder contains data about a DBatLoader (a.k.a. ModiLoader) sample that uses Discord to deliver a malware known as Warzone (a.k.a. Ave Maria), a Remote Access Trojan created in 2018. 

In this repository, you will find:

### IOCs
* **README.md**: All the IOCs related to the DBatLoader and Warzone analysis.

### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt and extract the C2 address from Warzone RAT files.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_warzone_c2.py --payload /path/to/unpacked_warzone.exe
```

If the script runs successfully, the C2 address will be displayed in the console.