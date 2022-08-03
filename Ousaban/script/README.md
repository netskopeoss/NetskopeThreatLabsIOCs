### Scripts

Netskope Threat Labs is releasing these small tools to help anyone that needs help with Ousaban analysis.

**1. decrypt_payload.py**

This script can be used to decrypt Ousaban malware payloads.

```shell
(venv) python3 decrypt_payload.py --key /path/to/key.bin --payload /path/to/payload 

[+] Decrypted payload saved at: /path/to/payload_decrypted.bin
```

**2. decrypt_strings.py**

This script can be used to decrypt strings found in Brazilian-based banking malware (e.g. Ousaban,
Guildma, Grandoreiro, etc)

You can decrypt a single string:

```shell
(venv) python3 decrypt_strings.py --key BAUdGYGlgX3wUY4XrGGt9z6CrGnnlmpgCaEIjtVSM2U7lYOwieLiZxs8v5df4YMnVY273VQ5jA4wdJvTR0P5r3y28crWsXscOWSW6IPkjwCg7WWUH1mCyA3Dhh8A --string D354F436FD2A1322EB3DF950CA658ACA62

[+] Decrypting D354F436FD2A1322EB3DF950CA658ACA62

Banco <REDACTED>
```

Or multiple strings, saved in a file and separated by new line ("\n")

```shell
(venv) python3 decrypt_strings.py --key BAUdGYGlgX3wUY4XrGGt9z6CrGnnlmpgCaEIjtVSM2U7lYOwieLiZxs8v5df4YMnVY273VQ5jA4wdJvTR0P5r3y28crWsXscOWSW6IPkjwCg7WWUH1mCyA3Dhh8A --strings '/path/to/encrypted_strings.txt'

[+] Decrypted strings saved at: /path/to/encrypted_strings.txt_decrypted.json
```

You can also add "--print" to show the decrypted strings in the console.

```shell
(venv) python3 decrypt_strings.py --key BAUdGYGlgX3wUY4XrGGt9z6CrGnnlmpgCaEIjtVSM2U7lYOwieLiZxs8v5df4YMnVY273VQ5jA4wdJvTR0P5r3y28crWsXscOWSW6IPkjwCg7WWUH1mCyA3Dhh8A --strings '/path/to/encrypted_strings.txt'

[+] Decrypted strings saved at: /path/to/encrypted_strings.txt_decrypted.json

[+] Decrypted strings:

DwmEnableComposition
Avast Secure Browser
mozilla firefox
...
```
