# IOCs

* **MD5**
```text
8119c78b7cfb7d9ce37286ec9fc263e2
```

* **SHA256**
```text
5fc44c7342b84f50f24758e39c8848b2f0991e8817ef5465844f5f2ff6085a57
```

* **RSA Key**
```text
-----BEGIN PUBLIC KEY-----'
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4mpkHWE1p0nefE0PL/Qk
gT7bjLTeJ9bpH6v41L1YGI688cwfEnjmIaDa0zwvHfbT8dn4o+Wh2iSpUZk0BYIi
Lw6u5+9nSd2UzD4sB+MY9dv6oVTHInxqp4VNLHR2nMjgIS4rFHYzNJ7Tsj/j3YJZ
dVPuPVCqbpZg5boXoSFbgLNIn6Mnr+vKc5tGh+pkGty0otyFd/ghM0b/xitowcvx
eqZezPO0YXmkjjeTi0jFa7E9IIP3Z/DMOR9r/oJR0NyEIs9HNKdFGTAjJKDAKWxu
1nEPXiZoPPHgS7fxqg40+ciCjj2i7eUwqVkop5PvwjqtqQ0TkIt8EqjvkmDtMrp8
ZQIDAQAB
-----END PUBLIC KEY-----
```

* **Targeted Extensions**
```text
.1cd, .7z, .abk, .accdb, .accdc, .accde, .accdr, .alz, .apk, .apng, .arc, .asd, .asf, .asm, .asx, .avhd, .avi, .avif, .bac, .backup, .bak, .bak2, .bak3, .bh, .bkp, .bkup, .bkz, .bmp, .btr, .bz, .bz2, .bzip, .bzip2, .c, .cab, .cer, .cf, .cfu, .cpp, .crt, .css, .db, .db-wal, .db3, .dbf, .der, .dmg, .dmp, .doc, .docm, .docx, .dot, .dotm, .dotx, .dpx, .dsk, .dt, .dump, .dz, .ecf, .edb, .epf, .exb, .ged, .gif, .gpg, .gzi, .gzip, .hdd, .img, .iso, .jar, .java, .jpeg, .jpg, .js, .json, .kdb, .key, .lz, .lz4, .lzh, .lzma, .mdmr, .mkv, .mov, .mp3, .mp4, .mpeg, .myd, .nude, .nvram, .oab, .odf, .ods, .old, .ott, .ovf, .p12, .pac, .pdf, .pem, .pfl, .pfx, .php, .pkg, .png, .pot, .potm, .potx, .pps, .ppsm, .ppsx, .ppt, .pptm, .pptx, .prf, .pvm, .py, .qcow, .qcow2, .r0, .rar, .raw, .rz, .s7z, .sdb, .sdc, .sdd, .sdf, .sfx, .skey, .sldm, .sldx, .sql, .sqlite, .svd, .svg, .tar, .taz, .tbz, .tbz2, .tg, .tib, .tiff, .trn, .txt, .txz, .tz, .vb, .vbox, .vbox-old, .vbox-prev, .vdi, .vdx, .vhd, .vhdx, .vmc, .vmdk, .vmem, .vmsd, .vmsn, .vmss, .vmx, .vmxf, .vsd, .vsdx, .vss, .vst, .vsx, .vtx, .wav, .wbk, .webp, .wmdb, .wmv, .xar, .xlm, .xls, .xlsb, .xlsm, .xlsx, .xlt, .xltm, .xltx, .xlw, .xz, .z, .zbf, .zip, .zipx, .zl, .zpi, .zz
```

* **Commands**

```text
C:\Windows\System32\reg.exe add HKCR\.enc /ve /t REG_SZ /d enc /f
C:\Windows\System32\reg.exe add HKCR\enc\shell\open\command /ve /t REG_SZ /d \"C:\Windows\Notepad.exe C:\Users\Public\README\" /f
C:\Windows\System32\net.exe stop MSSQLSERVER
C:\Windows\System32\wbadmin.exe delete catalog -quiet
C:\Windows\System32\vssadmin.exe delete shadows /all /quiet
```
