# Tokyo Olympics Wiper
A new malware threat emerged just before the 2020 Tokyo Olympics opening ceremony, able to damage an infected system by wiping its files. The malware disguises itself as a PDF document containing information about cyber attacks associated with the Tokyo Olympics.

In this repository, you will find:

### IOCs
* **hashes.txt**: sha256 hashes from the  samples analyzed by Netskope Threat Labs
* **decrypted_strings.txt**: Decrypted strings from the sample analyzed in the blog post
* **Win32_Olympics_Wiper.yar**: Yara rule to identify unpacked Tokyo Olympics Wiper samples

### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt the Olympics Wiper strings automatically.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_olympics_wiper_strings.py --payload /path/to/unpacked_olympics_wiper.exe
```

Since there are not a lot of strings, all of them are printed in the console.