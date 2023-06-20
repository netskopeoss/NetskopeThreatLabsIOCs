### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt SquirrelWaffle strings from unpacked DLLs.
```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_config.py --payload /path/to/unpacked_squirrelwaffle.dll
```

The decrypted strings will be printed out in the console.
