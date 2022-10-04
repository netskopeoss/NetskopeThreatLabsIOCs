### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt and extract the configuration from a REvil unpacked sample.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_REvil_config.py --payload /path/to/unpacked_revil.exe
```

The decrypted configuration will be saved in the same path as the payload, as "decrypted.json"
