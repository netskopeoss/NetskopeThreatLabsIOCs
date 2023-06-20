### Script

Netskope Threat Labs is releasing two scripts. The first one is to help anyone that needs to decrypt the configuration or strings from BlackMatter.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_data.py --payload /tmp/blackmatter.exe

[+] Decrypted strings:

%.8x%.8x%.8x%.8x%
...
sLanguage

[+] Decoded values from decrypted config:
sql
...
dbeng50

###########

[+] ===== Decrypted strings saved at: /tmp/decrypted_strings.txt
[+] ===== Decrypted configuration saved at: /tmp/decrypted_config.bin
[+] ===== Decoded strings saved at: /tmp/decoded_strings.txt

########### Goodbye

```

The second script is to generate the hash value used by BlackMatter to load APIs dynamically, so that the call can be located within the code.

```shell
(venv) python3 generate_hash.py --str kernel32.HeapCreate 

[+] DLL: kernel32.dll
[+] API: HeapCreate

[+] DLL hash: 0xb1fc7f66
[+] DLL + API hash: 0x260b0745
[+] Encoded hash (using 0x22065fed as key): 0x40d58a8

```
