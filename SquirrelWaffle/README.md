# SquirrelWaffle
In September 2021, a new malware family named SquirrelWaffle joined the threat landscape. It spread through infected Microsoft Office documents attached in spam emails. 

In this repository, you will find:

### IOCs
* **README.md**: All IOCs from SquirrelWaffle samples analyzed by Netskope Threat Labs
* **SquirrelWaffle_decrypted_strings**: Decrypted strings from the file analyzed by Netskope Threat Labs
* **Win32_SquirrelWaffle_DLL.yar**: Yara rule to identify unpacked SquirrelWaffle DLLs

### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt SquirrelWaffle strings from unpacked DLLs.
```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_config.py --payload /path/to/unpacked_squirrelwaffle.dll
```

The decrypted strings will be printed out in the console.
