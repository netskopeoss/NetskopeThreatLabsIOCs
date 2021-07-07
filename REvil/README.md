# REvil
The REvil ransomware (a.k.a Sodinokibi) is a threat group that operates in the RaaS (Ransomware-as-a-Service) model, where the infrastructure and the malware is supplied to affiliates, who can use the malware to infect target organizations. For more details, please visit https://www.netskope.com/blog/netskope-threat-coverage-revil

In this repository, you will find:

### IOCs
* **REvil_domains.txt**: domains from the files analyzed in the blog post, from Kaseya's incident.
* **REvil_hashes.txt**: sha256 hashes from the files analyzed in the blog post, from Kaseya's incident.
* **REvil_decrypted_config.json**: Decrypted configuration from the REvil unpacked payload.

### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decrypt and extract the configuration from a REvil unpacked sample.

```shell
(venv) pip install -r requirements.txt
(venv) python3 decrypt_REvil_config.py --payload /path/to/unpacked_revil.exe
```

The decrypted configuration will be saved in the same path as the payload, as "decrypted.json"
