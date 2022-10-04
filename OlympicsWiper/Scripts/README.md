### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt the Olympics Wiper strings automatically.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_olympics_wiper_strings.py --payload /path/to/unpacked_olympics_wiper.exe
```

Since there are not a lot of strings, all of them are printed in the console.