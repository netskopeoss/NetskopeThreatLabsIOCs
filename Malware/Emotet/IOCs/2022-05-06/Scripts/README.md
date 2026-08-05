### Scripts

Netskope Threat Labs is releasing these small tools to help anyone that needs to extract information from Emotet samples.

Make sure to install the requirements before the usage:

```shell
(venv) pip install -r requirements.txt
```

**1. decrypt_payload.py**

This tool can be used to decrypt 64-bit Emotet samples from similar files found in a campaign [analyzed by Netskope](https://netskope.com/blog/emotet-campaign-using-lnk-files).  Make sure to extract the encrypted Emotet from the loader/packer before running the script.

```shell
(venv) python3 decrypt_payload.py --payload /path/to/encrypted_resource.bin --key "decryption_key" --out /path/to/emotet.bin
```

If the script runs successfully, Emotet will be saved in the path specified in the "out" parameter.

**2. decrypt_c2.py**

This tool can be used to extract and decrypt C2 addressed from Emotet 64-bit samples.

```shell
(venv) python3 decrypt_c2.py --payload /path/to/emotet.bin
```

If the script runs successfully, the C2 addresses will be displayed in the console.