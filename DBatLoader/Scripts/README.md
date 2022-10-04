### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt and extract the C2 address from Warzone RAT files.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_warzone_c2.py --payload /path/to/unpacked_warzone.exe
```

If the script runs successfully, the C2 address will be displayed in the console.