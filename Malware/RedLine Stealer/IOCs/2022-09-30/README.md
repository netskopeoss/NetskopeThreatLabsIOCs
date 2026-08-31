# IOCs

## Phishing Email

* **Phishing Email (MD5)**
```text
7eb91c6035299451956f5eda1ce49eaa
```

* **PDF Attachment (MD5)**
```text
0e8fb9118a3395ef87638bf36cc03e5a
```

## RedLine Stealer

These are the IOCs of the latest version of the PDF file, as we [mentioned](https://www.netskope.com/blog/redline-stealer-campaign-abusing-discord-via-pdf-links) in our blog post.

* **Downloaded Files (MD5)**
```text
ca144f86e4751e766bd216b72fc9cfb8
2f1588f52e75574ccdced95969b8f275
```

* **Payload URL**
```text
hxxps://cdn.discordapp[.]com/attachments/993279568368644219/1021169437837111346/InvoicePO45928.zip
```

* **C2 Server Address**
```text
103.190.107[.]205:13122
```

* **RedLine Stealer ID**
```text
17.9
```

## NjRAT and PureCrypter

As we [described](https://www.netskope.com/blog/redline-stealer-campaign-abusing-discord-via-pdf-links) in our blog post, we found other URLs in the same PDF file by analyzing the update history, which were delivering other malware.

* **Files Downloaded From Discord (MD5)**
```text
d6097ab6eb34dbf2debb38ccf19df63d
85b2df737e7cde9e55ec7b6bbd07d65a
8cc1f5a49e9c7fd3f851c21cfa5cc546
ade7b1a0adba4f383b749263b08d3c70
35952733edc5bb08d28c4a72adba2da3
```

* **Payload URLs**
```text
hxxps://cdn.discordapp[.]com/attachments/941432753252073502/942138983331291277/Invoice_NO355449609.rar
hxxps://cdn.discordapp[.]com/attachments/941432753252073502/944021090173354014/Encrypted.hta
hxxps://cdn.discordapp[.]com/attachments/941432753252073502/944021536925425674/Encrypted.rar
hxxps://cdn.discordapp[.]com/attachments/941432753252073502/942138289824100383/Server.exe
hxxps://cdn.discordapp[.]com/attachments/941432753252073502/943655796527472670/system.exe
```

* **C2 Server IPs**
```text
91.193.75[.]133:2222
95.214.24[.]140:1111
136.144.41[.]243:1111
```

* **C2 Server Domain**
```text
elektraal.duckdns[.]org
```