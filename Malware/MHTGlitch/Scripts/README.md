### Script

This is a small tool Netskope Threat Labs is releasing to help anyone that needs to decode the strings from infected documents related to this campaign.

```shell
(venv) pip install -r requirements.txt
(venv) python3 deobfuscate_macro_strings.py --payload /path/to/extracted_macro.vba
```

Since there are not a lot of strings, all of them are printed in the console.
